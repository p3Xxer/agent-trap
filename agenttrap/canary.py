"""Fake secrets ("canaries") planted where attackers look for real ones.

Every value is freshly random per run and formatted like the real thing, so the bait looks genuine
and any leaked value points at exactly one run. None of them is a working credential.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from pathlib import Path

HOSTNAME = "$HOSTNAME"  # canary names of the machine's identity; the sandbox is started with it
USERNAME = "$USER"
# Other ways code names the machine's identity (the random values never appear in the code itself)
IDENTITY_WORDS = {
    HOSTNAME: ("hostname", "gethostname", "platform.node", "uname", "getfqdn"),
    USERNAME: ("getuser", "whoami", "logname", '"user"', "'user'", "username"),
}

_UPPER_DIGITS = string.ascii_uppercase + string.digits
_ALNUM = string.ascii_letters + string.digits


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


@dataclass(frozen=True)
class Canaries:
    values: dict[str, str]  # canary name (where it lives) -> secret value
    home_files: dict[str, str]  # path relative to $HOME -> file content
    env: dict[str, str]  # environment variables

    @property
    def hostname(self) -> str | None:
        return self.values.get(HOSTNAME)

    def name_for_path(self, path: str) -> str | None:
        """Canary name for a file path: "/root/.aws/credentials" -> "~/.aws/credentials"."""
        for name in self.values:
            if name.startswith("~/") and path.rstrip("/").endswith(name[1:]):
                return name
        return None


def generate() -> Canaries:
    """Layer 1: the standard locations every credential stealer probes."""
    aws_id, aws_secret = "AKIA" + _rand(_UPPER_DIGITS, 16), _rand(_ALNUM + "+/", 40)
    gh_token = "ghp_" + _rand(_ALNUM, 36)
    npm_token = "npm_" + _rand(_ALNUM, 36)
    ssh_body = _rand(_ALNUM + "+/", 64)
    openai_key = "sk-proj-" + _rand(_ALNUM, 48)
    anthropic_key = "sk-ant-api03-" + _rand(_ALNUM + "-_", 80)
    # Who and where the machine is: malware often reports these instead of (or before) stealing a
    # file. Random per run, so seeing one in outgoing traffic proves the sandbox's identity left.
    hostname = "build-" + _rand("0123456789abcdef", 10)
    username = "dev-" + _rand("0123456789abcdef", 8)

    home_files = {
        ".aws/credentials": (
            f"[default]\naws_access_key_id = {aws_id}\naws_secret_access_key = {aws_secret}\n"
        ),
        ".ssh/id_rsa": (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA{ssh_body}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        ),
        ".config/gh/hosts.yml": (
            f"github.com:\n    oauth_token: {gh_token}\n    user: dev\n    git_protocol: https\n"
        ),
        ".npmrc": f"//registry.npmjs.org/:_authToken={npm_token}\n",
    }
    values = {
        "~/.aws/credentials": aws_id,
        "~/.aws/credentials#secret": aws_secret,
        "~/.ssh/id_rsa": ssh_body,
        "~/.config/gh/hosts.yml": gh_token,
        "~/.npmrc": npm_token,
        "$OPENAI_API_KEY": openai_key,
        "$ANTHROPIC_API_KEY": anthropic_key,
        HOSTNAME: hostname,
        USERNAME: username,
    }
    env = {
        "OPENAI_API_KEY": openai_key,
        "ANTHROPIC_API_KEY": anthropic_key,
        "USER": username,
        "LOGNAME": username,
    }
    return Canaries(values=values, home_files=home_files, env=env)


def write_home(canaries: Canaries, home: Path) -> None:
    for rel, text in canaries.home_files.items():
        path = home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
