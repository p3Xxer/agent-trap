"""Per-run network monitor: a private network whose only neighbour is a logging sinkhole.

The sandbox joins this network and uses the sinkhole as its DNS server, so every name resolves to
the sinkhole and every connection ends there. There is no route out, nothing is forwarded, and
HTTPS is not decrypted: for TLS only the host name is visible, for plain HTTP the whole request.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from agenttrap.detector import Flag, Request
from agenttrap.sandbox import IMAGE, _docker

SINKHOLE = Path(__file__).with_name("sinkhole.py")


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
        self.served = dict(served or {})
        self.ip = ""

    def __enter__(self) -> Egress:
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
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        _docker("rm", "-f", self.name)
        _docker("network", "rm", self.network)

    def observed(self) -> Observed:
        logs = _docker("logs", self.name)
        return parse_events((logs.stdout + logs.stderr).splitlines())


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
                        url=f"http://{host}{event.get('path', '')}",
                        headers=event.get("headers", {}),
                        body=event.get("body", ""),
                    )
                )
    hosts.pop("", None)
    return Observed(tuple(requests), tuple(hosts))


def contact_flags(observed: Observed, allowed: set[str] = frozenset()) -> list[Flag]:
    """Soft flags for every host contacted that isn't expected. A repo may have a good reason."""
    return [
        Flag("contacted-host", f"sandbox contacted {host}", hard=False)
        for host in observed.hosts
        if host not in allowed and urlparse(f"//{host}").hostname not in allowed
    ]
