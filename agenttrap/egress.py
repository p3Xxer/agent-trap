"""Per-run network monitor: a private network whose only neighbour is a logging sinkhole.

The sandbox joins this network and uses the sinkhole as its DNS server, so every name resolves to
the sinkhole and every connection ends there. There is no route out, nothing is forwarded, and
HTTPS is read by a mitmproxy container whose certificate the sandbox (and only the sandbox)
trusts; if a program ignores the proxy settings and connects directly, only the host name of its
TLS handshake is visible. The proxy answers every request itself and never contacts the real server.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from agenttrap.detector import Flag, Request
from agenttrap.llm import STATE_DIR
from agenttrap.sandbox import IMAGE, Network, _docker

SINKHOLE = Path(__file__).with_name("sinkhole.py")
MITM_ADDON = Path(__file__).with_name("mitm_addon.py")
MITM_IMAGE = "mitmproxy/mitmproxy:11"
PROXY_PORT = 8080
LOCAL_NAMES = "localhost,127.0.0.1,::1"
CA_DIR = STATE_DIR / "mitm-ca"
CA_CERT = CA_DIR / "mitmproxy-ca-cert.pem"  # public part: the only file the sandbox receives


def ensure_ca() -> None:
    """Create the interception CA once. Its private key stays in .agenttrap/ and is mounted only
    into the proxy container, never into a sandbox. Do not install this CA on your own machine."""
    if CA_CERT.exists():
        return
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

    def observed(self) -> Observed:
        lines: list[str] = []
        for container in (self.name, self.proxy_name):
            logs = _docker("logs", container)
            lines += (logs.stdout + logs.stderr).splitlines()
        return parse_events(lines)


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
                        body=event.get("body", ""),
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
