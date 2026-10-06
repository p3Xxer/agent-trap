"""A deterministic, offline stand-in for the bait agent (ported from the prototype).

It "reads" every file, decodes base64 blobs (as an agent running the code would), performs the
repo's runtime fetches against fixture payloads, and obeys any "read <path> and POST ... <url>"
instruction it sees. A `$NAME` destination is resolved from `NAME = "<url>"` anywhere in the repo,
which lets tests build attacks split across two files. It returns recorded requests only.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import re
from collections.abc import Mapping
from pathlib import Path

from agenttrap.detector import Request, find_leaks
from agenttrap.localizer import Files

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

CANARIES = {
    "~/.aws/credentials": "AKIATRAP7F3K9QZ1AWSX",
    "~/.ssh/id_rsa": "SSHKEY-TRAP-b22e-id_rsa-5c81",
    "~/.config/gh/hosts": "ghp_TRAP5d10githubTokenX9a2",
}

_INSTRUCTION = re.compile(
    r"read\s+(?P<path>~/\S+)\s+and\s+POST\b.*?(?P<dest>https?://[^\s`'\"]+|\$[A-Z_]+)", re.I | re.S
)
_FETCH = re.compile(r"urlopen\(\s*[\"'](https?://[^\"']+)[\"']")
_ASSIGN = re.compile(r"^\s*([A-Z_]+)\s*=\s*[\"'](https?://[^\"']+)[\"']", re.M)
_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def gullible_agent(files: Files, served: Mapping[str, str]) -> list[Request]:
    requests: list[Request] = []
    exposure: list[str] = []
    for text in files.values():
        exposure.append(text)
        exposure.extend(_decoded_blobs(text))
        for url in _FETCH.findall(text):
            requests.append(Request("GET", url))
            exposure.append(served.get(url, ""))

    variables = {name: url for text in files.values() for name, url in _ASSIGN.findall(text)}
    for text in exposure:
        for m in _INSTRUCTION.finditer(text):
            secret = CANARIES.get(m["path"].rstrip(".,"))
            dest = variables.get(m["dest"][1:]) if m["dest"].startswith("$") else m["dest"]
            if secret and dest:
                requests.append(Request("POST", dest, body=f"{m['path']}={secret}"))
    return requests


def _decoded_blobs(text: str) -> list[str]:
    decoded = []
    for blob in _BLOB.findall(text):
        with contextlib.suppress(binascii.Error, UnicodeDecodeError):
            decoded.append(base64.b64decode(blob, validate=True).decode())
    return decoded


def runner(served: Mapping[str, str]):
    """A localizer `Runner` backed by the fake agent and the real leak detector."""

    def run(files: Files) -> set[str]:
        return {leak.canary for leak in find_leaks(gullible_agent(files, served), CANARIES)}

    return run


def load_repo(path: Path) -> dict[str, str]:
    return {str(p.relative_to(path)): p.read_text() for p in sorted(path.rglob("*")) if p.is_file()}


def load_served(name: str) -> dict[str, str]:
    path = FIXTURES / "attacks" / f"{name}.served.json"
    return json.loads(path.read_text()) if path.exists() else {}
