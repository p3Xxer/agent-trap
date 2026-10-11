"""A throwaway Docker container for one detonation run.

The container sits on an internal Docker network with no route to the internet, runs with all
capabilities dropped and resource limits, and is always destroyed afterwards. The target repo is
copied in at /work and the canaries are planted in /root.
"""

from __future__ import annotations

import io
import shlex
import subprocess
import tarfile
import tempfile
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from agenttrap.canary import Canaries, write_home

IMAGE = "agenttrap-sandbox:0.2"
NETWORK = "agenttrap-internal"
DOCKERFILE = Path(__file__).with_name("sandbox.Dockerfile")
WORKDIR = "/work"


@dataclass(frozen=True)
class Network:
    """How a sandbox is attached to the network. The default is the shared, DNS-less network."""

    name: str = NETWORK
    dns: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)  # e.g. proxy settings
    ca_cert: Path | None = None  # public certificate the sandbox should trust


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


def _docker(*args: str, input: str | None = None, timeout: float = 120) -> CommandResult:
    p = subprocess.run(
        ["docker", *args], input=input, capture_output=True, text=True, timeout=timeout
    )
    return CommandResult(p.returncode, p.stdout, p.stderr)


def _as_root(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    return info


def ensure_ready() -> None:
    """Build the image and create the isolated network if they don't exist yet."""
    if _docker("image", "inspect", IMAGE).exit_code != 0:
        built = _docker(
            "build", "-t", IMAGE, "-f", str(DOCKERFILE), str(DOCKERFILE.parent), timeout=900
        )
        if built.exit_code != 0:
            raise RuntimeError(f"docker build failed:\n{built.stderr[-2000:]}")
    if _docker("network", "inspect", NETWORK).exit_code != 0:
        _docker("network", "create", "--internal", NETWORK)


class Sandbox:
    """Use as a context manager so the container is always removed."""

    def __init__(self, repo: Path, canaries: Canaries, net: Network | None = None) -> None:
        """`net`: a monitored per-run network (see egress.py); the default has no DNS at all."""
        self.repo = repo
        self.canaries = canaries
        self.net = net or Network()
        self.name = f"agenttrap-{uuid.uuid4().hex[:12]}"

    def __enter__(self) -> Sandbox:
        variables = {**self.canaries.env, **self.net.env}
        env = [arg for k, v in variables.items() for arg in ("-e", f"{k}={v}")]
        dns = ["--dns", self.net.dns] if self.net.dns else []
        started = _docker(
            "run", "-d", "--name", self.name, "--network", self.net.name, *dns,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "1g", "--cpus", "1", "--pids-limit", "256",
            *env, IMAGE, "sleep", "infinity",
        )  # fmt: skip
        if started.exit_code != 0:
            raise RuntimeError(f"could not start sandbox: {started.stderr}")
        try:
            self._copy_repo()
            with tempfile.TemporaryDirectory() as home:
                write_home(self.canaries, Path(home))
                _docker("cp", f"{home}/.", f"{self.name}:/root")
            if self.net.ca_cert:
                self._trust(self.net.ca_cert)
        except BaseException:
            self.__exit__()
            raise
        return self

    def _copy_repo(self) -> None:
        """Copy the repo in, owned by root. The container has no right to touch files owned by
        anyone else, so a folder the project ships (an `egg-info`, say) that kept its owner from
        the host would make the build fail with "Cannot update time stamp"."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            archive.add(self.repo, arcname=".", filter=_as_root)
        copied = subprocess.run(
            ["docker", "cp", "-", f"{self.name}:{WORKDIR}"],
            input=buffer.getvalue(), capture_output=True, timeout=300,
        )  # fmt: skip
        if copied.returncode != 0:
            raise RuntimeError(f"could not copy the repo in: {copied.stderr.decode()[-500:]}")

    def _trust(self, cert: Path) -> None:
        """Add a public certificate to the sandbox's trust store."""
        target = "/usr/local/share/ca-certificates/agenttrap-ca.crt"
        _docker("cp", str(cert), f"{self.name}:{target}")
        updated = _docker("exec", self.name, "update-ca-certificates")
        if updated.exit_code != 0:
            raise RuntimeError(f"could not trust the interception certificate: {updated.stderr}")

    def __exit__(self, *exc: object) -> None:
        _docker("rm", "-f", self.name)

    def run(self, command: str, timeout: int = 60) -> CommandResult:
        """Run a shell command in /work. The time limit is enforced inside the container."""
        wrapped = f"timeout -s KILL {timeout} sh -c {shlex.quote(command)}"
        return _docker("exec", "-w", WORKDIR, self.name, "sh", "-c", wrapped, timeout=timeout + 15)

    def read(self, path: str) -> CommandResult:
        return _docker("exec", "-w", WORKDIR, self.name, "cat", "--", path)

    def write(self, path: str, text: str) -> CommandResult:
        script = 'mkdir -p "$(dirname -- "$1")" && cat > "$1"'
        return _docker("exec", "-i", "-w", WORKDIR, self.name, "sh", "-c", script, "_", path,
                       input=text)  # fmt: skip
