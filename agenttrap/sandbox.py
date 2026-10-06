"""A throwaway Docker container for one detonation run.

The container sits on an internal Docker network with no route to the internet, runs with all
capabilities dropped and resource limits, and is always destroyed afterwards. The target repo is
copied in at /work and the canaries are planted in /root.
"""

from __future__ import annotations

import shlex
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from agenttrap.canary import Canaries, write_home

IMAGE = "agenttrap-sandbox:0.1"
NETWORK = "agenttrap-internal"
DOCKERFILE = Path(__file__).with_name("sandbox.Dockerfile")
WORKDIR = "/work"


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

    def __init__(self, repo: Path, canaries: Canaries) -> None:
        self.repo = repo
        self.canaries = canaries
        self.name = f"agenttrap-{uuid.uuid4().hex[:12]}"

    def __enter__(self) -> Sandbox:
        env = [arg for k, v in self.canaries.env.items() for arg in ("-e", f"{k}={v}")]
        started = _docker(
            "run", "-d", "--name", self.name, "--network", NETWORK,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "1g", "--cpus", "1", "--pids-limit", "256",
            *env, IMAGE, "sleep", "infinity",
        )  # fmt: skip
        if started.exit_code != 0:
            raise RuntimeError(f"could not start sandbox: {started.stderr}")
        try:
            _docker("cp", f"{self.repo}/.", f"{self.name}:{WORKDIR}")
            with tempfile.TemporaryDirectory() as home:
                write_home(self.canaries, Path(home))
                _docker("cp", f"{home}/.", f"{self.name}:/root")
        except BaseException:
            self.__exit__()
            raise
        return self

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
