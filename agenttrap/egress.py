"""Per-run network monitor: a private network whose only neighbour is a logging sinkhole.

The sandbox joins this network and uses the sinkhole as its DNS server, so every name resolves to
the sinkhole and every connection ends there. There is no route out, nothing is forwarded, and
HTTPS is read by a mitmproxy container whose certificate the sandbox (and only the sandbox)
trusts; if a program ignores the proxy settings and connects directly, only the host name of its
TLS handshake is visible. The proxy answers every request itself and never contacts the real server.
"""

from __future__ import annotations

import base64
import contextlib
import json
import queue
import threading
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlparse

from agenttrap.detector import Flag, Request, unpacked_text
from agenttrap.llm import STATE_DIR
from agenttrap.sandbox import IMAGE, Network, _docker

SINKHOLE = Path(__file__).with_name("sinkhole.py")
MITM_ADDON = Path(__file__).with_name("mitm_addon.py")
MITM_IMAGE = "mitmproxy/mitmproxy:11"
PROXY_PORT = 8080
LOCAL_NAMES = "localhost,127.0.0.1,::1"
CA_DIR = STATE_DIR / "mitm-ca"
CA_CERT = CA_DIR / "mitmproxy-ca-cert.pem"  # public part: the only file the sandbox receives


_CA_LOCK = threading.Lock()


def ensure_ca() -> None:
    """Create the interception CA once. Its private key stays in .agenttrap/ and is mounted only
    into the proxy container, never into a sandbox. Do not install this CA on your own machine.

    A scan starts several runs at once; on the very first scan they would all create the CA at the
    same time and read each other's half-written files, so only one of them makes it."""
    with _CA_LOCK:
        if not CA_CERT.exists():
            _create_ca()


def _create_ca() -> None:
    CA_DIR.mkdir(parents=True, exist_ok=True)
    made = _docker(
        "run", "--rm", "--entrypoint", "python", "-v", f"{CA_DIR}:/ca", MITM_IMAGE, "-c",
        "from mitmproxy.certs import CertStore; CertStore.from_store('/ca', 'mitmproxy', 2048)",
        timeout=300,
    )  # fmt: skip
    if made.exit_code != 0 or not CA_CERT.exists():
        raise RuntimeError(f"could not create the interception CA:\n{made.stderr[-1000:]}")


@dataclass(frozen=True)
class Observed:
    """Everything the sandbox tried to do on the network."""

    requests: tuple[Request, ...]  # plain-HTTP requests, in full
    hosts: tuple[str, ...]  # every host contacted, by DNS lookup, TLS name or Host header


class Mark(NamedTuple):
    """How many log lines each container had written at some moment."""

    sink: int
    proxy: int


START = Mark(0, 0)


class Egress:
    """Use as a context manager; the network and sinkhole are always removed."""

    def __init__(self, served: Mapping[str, str] | None = None) -> None:
        run_id = uuid.uuid4().hex[:12]
        self.network = f"agenttrap-net-{run_id}"
        self.name = f"agenttrap-sink-{run_id}"
        self.proxy_name = f"agenttrap-proxy-{run_id}"
        self.served = dict(served or {})
        self.ip = ""
        self.proxy_ip = ""

    def net(self) -> Network:
        """The network settings a Sandbox needs to be watched by this Egress."""
        proxy = f"http://{self.proxy_ip}:{PROXY_PORT}"
        bundle = "/etc/ssl/certs/ca-certificates.crt"
        env = {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy}
        env |= {k: bundle for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS")}
        # A program talking to a server on the same machine is not leaving the machine.
        env |= {"NO_PROXY": LOCAL_NAMES, "no_proxy": LOCAL_NAMES}
        return Network(self.network, dns=self.ip, env=env, ca_cert=CA_CERT)

    def __enter__(self) -> Egress:
        ensure_ca()
        _docker("network", "create", "--internal", self.network)
        try:
            started = _docker(
                "run", "-d", "--name", self.name, "--network", self.network,
                "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
                "--security-opt", "no-new-privileges", "--memory", "128m", "--pids-limit", "128",
                "-e", f"SINKHOLE_SERVED={json.dumps(self.served)}",
                "-v", f"{SINKHOLE}:/sinkhole.py:ro",
                IMAGE, "sh", "-c", "SINKHOLE_IP=$(hostname -i) exec python /sinkhole.py",
            )  # fmt: skip
            if started.exit_code != 0:
                raise RuntimeError(f"could not start sinkhole: {started.stderr}")
            fmt = f'{{{{(index .NetworkSettings.Networks "{self.network}").IPAddress}}}}'
            self.ip = _docker("inspect", "-f", fmt, self.name).stdout.strip()
            self._start_proxy(fmt)
        except BaseException:
            self.__exit__()
            raise
        return self

    def _start_proxy(self, ip_format: str) -> None:
        started = _docker(
            "run", "-d", "--name", self.proxy_name, "--network", self.network,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "512m", "--pids-limit", "128",
            "-e", f"SINKHOLE_SERVED={json.dumps(self.served)}",
            "-v", f"{MITM_ADDON}:/addon.py:ro", "-v", f"{CA_DIR}:/ca:ro",
            "--entrypoint", "mitmdump", MITM_IMAGE,
            "--set", "confdir=/ca", "--set", "connection_strategy=lazy",  # never dial upstream
            "-s", "/addon.py", "--listen-port", str(PROXY_PORT),
        )  # fmt: skip
        if started.exit_code != 0:
            raise RuntimeError(f"could not start the proxy: {started.stderr}")
        self.proxy_ip = _docker("inspect", "-f", ip_format, self.proxy_name).stdout.strip()
        for _ in range(50):  # wait until it accepts connections
            logs = _docker("logs", self.proxy_name)
            if '"ready"' in logs.stdout + logs.stderr:
                return
            time.sleep(0.2)
        raise RuntimeError("the proxy did not start listening")

    def __exit__(self, *exc: object) -> None:
        _docker("rm", "-f", self.name)
        _docker("rm", "-f", self.proxy_name)
        _docker("network", "rm", self.network)

    def mark(self) -> Mark:
        """Where the logs end now, so a later `observed(since=mark)` shows only what came after."""
        return Mark(*(len(self._log(container)) for container in (self.name, self.proxy_name)))

    def observed(self, since: Mark = START) -> Observed:
        """What the sandbox did on the network, optionally only after `since`. Offsets are kept
        per container because the two logs grow independently."""
        sink = self._log(self.name)[since.sink :]
        proxy = self._log(self.proxy_name)[since.proxy :]
        return parse_events(sink + proxy)

    @staticmethod
    def _log(container: str) -> list[str]:
        """The container's events. Both the sinkhole and the proxy addon print them to stdout;
        stderr is left out because it grows on its own (warnings) and would shift the offsets."""
        return _docker("logs", container).stdout.splitlines()


class EgressPool:
    """A few Egress instances shared by many short detonations, so each one pays for its sinkhole
    and proxy once instead of every time. Use as a context manager; every one made is removed.

    An Egress is lent to one detonation at a time and made lazily, so a search that never runs in
    parallel starts only one. Callers read their own traffic with `mark()` / `observed(since=)`.
    """

    def __init__(self, served: Mapping[str, str] | None, size: int) -> None:
        self.served = served
        self.size = size
        self._made = 0
        self._lock = threading.Lock()
        self._idle: queue.Queue[Egress] = queue.Queue()
        self._stack = ExitStack()

    def __enter__(self) -> EgressPool:
        return self

    def __exit__(self, *exc: object) -> None:
        self._stack.close()

    @contextmanager
    def lend(self) -> Iterator[Egress]:
        egress = self._take()
        try:
            yield egress
        finally:
            self._idle.put(egress)

    def _take(self) -> Egress:
        try:
            return self._idle.get_nowait()
        except queue.Empty:
            pass
        with self._lock:
            make = self._made < self.size
            self._made += make
        if not make:
            return self._idle.get()
        try:
            return self._stack.enter_context(Egress(self.served))
        except BaseException:
            with self._lock:
                self._made -= 1  # let another caller try rather than wait for one that never comes
            raise


def _body(event: dict) -> str:
    """The request body as text, plus whatever is readable inside it once unpacked, when the
    proxy passed on a compressed or binary body."""
    body = event.get("body") or ""
    packed = event.get("body_b64")
    if packed:
        with contextlib.suppress(ValueError, TypeError):  # a broken field is just not unpacked
            body += "\n" + unpacked_text(base64.b64decode(packed))
    return body


def parse_events(lines: list[str]) -> Observed:
    requests: list[Request] = []
    hosts: dict[str, None] = {}  # ordered, de-duplicated
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        match event.get("kind"):
            case "dns":
                hosts[event["name"]] = None
            case "tls" if event.get("sni"):
                hosts[event["sni"]] = None
            case "http":
                host = event.get("host", "")
                hosts[host.split(":")[0]] = None
                requests.append(
                    Request(
                        method=event.get("method", ""),
                        url=f"{event.get('scheme', 'http')}://{host}{event.get('path', '')}",
                        headers=event.get("headers", {}),
                        body=_body(event),
                    )
                )
    hosts.pop("", None)
    return Observed(tuple(requests), tuple(hosts))


def unexpected_hosts(observed: Observed, allowed: set[str] = frozenset()) -> list[str]:
    """Hosts the sandbox contacted that are not on the allow-list."""
    return [
        host
        for host in observed.hosts
        if host not in allowed and urlparse(f"//{host}").hostname not in allowed
    ]


def contact_flags(observed: Observed, allowed: set[str] = frozenset()) -> list[Flag]:
    """Soft flags for every host contacted that isn't expected. A repo may have a good reason."""
    return [
        Flag("contacted-host", f"sandbox contacted {host}", hard=False)
        for host in unexpected_hosts(observed, allowed)
    ]
