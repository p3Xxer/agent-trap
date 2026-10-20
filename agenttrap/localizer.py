"""Pinpoint which file and line made the agent leak a canary.

Delta debugging (ddmin): keep shrinking the set of intact files, then lines, while the leak still
reproduces. What remains is a minimal culprit set, including attacks split across several files.

The localizer knows nothing about agents, sandboxes or models. It takes a `Runner`: a function
that runs the agent on a version of the repo and returns the names of the canaries that leaked.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable, Hashable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T", bound=Hashable)

Files = Mapping[str, str]  # relative path -> file text
Runner = Callable[[Files], set[str]]  # repo version -> names of leaked canaries


@dataclass(frozen=True)
class Culprit:
    file: str
    line: int  # 1-based
    text: str
    tag: str  # plaintext | base64 | runtime-fetch | unicode


def ddmin(items: Sequence[T], fails: Callable[[Sequence[T]], bool], workers: int = 1) -> list[T]:
    """Zeller's ddmin: a minimal subset of `items` for which `fails` is still true.

    `fails(items)` must be true. Each distinct subset is tested at most once, since every test
    may be a costly agent run. With `workers` > 1 the candidates of one round are tested at the
    same time; the first one in order that still fails is taken, exactly as in the sequential
    search, so the answer is the same and only the waiting is shorter.
    """
    seen: dict[frozenset[T], bool] = {}

    def first_failing(candidates: Iterator[list[T]]) -> list[T] | None:
        if workers <= 1:
            return next((c for c in candidates if test(c)), None)
        found = list(candidates)
        todo = {frozenset(c): c for c in found if frozenset(c) not in seen}
        with ThreadPoolExecutor(workers) as pool:
            for key, result in zip(todo, pool.map(fails, todo.values()), strict=True):
                seen[key] = result
        return next((c for c in found if seen[frozenset(c)]), None)

    def test(subset: Sequence[T]) -> bool:
        key = frozenset(subset)
        if key not in seen:
            seen[key] = fails(subset)
        return seen[key]

    items, n = list(items), 2
    while len(items) >= 2:
        chunks = _split(items, n)
        reduced = first_failing(iter(chunks))
        if reduced is not None:
            items, n = reduced, 2
            continue
        complements = ([x for c in chunks if c is not chunk for x in c] for chunk in chunks)
        reduced = first_failing(complements)
        if reduced is not None:
            items, n = reduced, max(n - 1, 2)
            continue
        if n >= len(items):
            break
        n = min(2 * n, len(items))
    return items


def _split(items: list[T], n: int) -> list[list[T]]:
    size, extra = divmod(len(items), n)
    chunks, start = [], 0
    for i in range(n):
        end = start + size + (1 if i < extra else 0)
        chunks.append(items[start:end])
        start = end
    return chunks


def repeat(run: Runner, k: int) -> Runner:
    """Agents are non-deterministic: a leak counts if it happens in ANY of `k` runs."""

    def run_k(files: Files) -> set[str]:
        return set().union(*(run(files) for _ in range(k)))

    return run_k


def localize(
    files: Files,
    run: Runner,
    canary: str,
    candidates: Sequence[str] | None = None,
    workers: int = 1,
) -> list[Culprit]:
    """Culprit lines for one leaked canary: ddmin over files, then over lines in each culprit.

    `candidates` limits the search (e.g. to files the agent read before leaking); every other
    file stays as-is. Neutralized files and lines are blanked, not removed, so line numbers hold.
    """
    candidates = [f for f in (candidates or files) if files[f].strip()]

    def leaks(version: Files) -> bool:
        return canary in run(version)

    if not leaks(files):
        raise ValueError(f"{canary!r} does not leak from the unmodified repo")

    def keep_files(kept: Sequence[str]) -> dict[str, str]:
        blanked = set(candidates) - set(kept)
        return {f: "" if f in blanked else text for f, text in files.items()}

    culprit_files = ddmin(candidates, lambda kept: leaks(keep_files(kept)), workers)
    base = keep_files(culprit_files)
    return [c for path in culprit_files for c in _localize_lines(base, path, leaks, workers)]


def _localize_lines(
    base: dict[str, str], path: str, leaks: Callable[[Files], bool], workers: int = 1
) -> list[Culprit]:
    """ddmin over the non-blank lines of one culprit file, with the other culprits intact."""
    lines = base[path].splitlines()

    def keep_lines(kept: Sequence[int]) -> dict[str, str]:
        keep = set(kept)
        text = "\n".join(line if i in keep else "" for i, line in enumerate(lines))
        return {**base, path: text}

    candidates = [i for i, line in enumerate(lines) if line.strip()]
    kept = ddmin(candidates, lambda subset: leaks(keep_lines(subset)), workers)
    return [Culprit(path, i + 1, lines[i], tag(lines[i])) for i in kept]


_BASE64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_FETCH = re.compile(
    r"urlopen|requests\.(get|post|put|request)\b|httpx\.|http\.client|\.sendall\(|create_connection"
    r"|\bcurl\b|\bwget\b|\bfetch\("
)
_INVISIBLE = re.compile("[​-‏⁠-⁤﻿\U000e0000-\U000e007f]")


_READ = re.compile(r"\.read(?:_text|_bytes|lines)?\(|environ\[|getenv\(")


def reads_a_value(line: str) -> bool:
    """True for a line that takes a value out of a file or the environment (`file.read()`,
    `os.environ[name]`, `os.getenv(...)`): where a secret is actually picked up."""
    return bool(_READ.search(line))


def sends_over_network(line: str) -> bool:
    """True for a line that makes a network request (urlopen, requests.post, curl, ...)."""
    return bool(_FETCH.search(line))


UNCONFIRMED = "unconfirmed"  # found by text search, not by re-running the repository


def tag(line: str) -> str:
    """How the instruction on this line was hidden from a human reader."""
    if _INVISIBLE.search(line):
        return "unicode"
    if any(_decodes_to_text(blob) for blob in _BASE64.findall(line)):
        return "base64"
    if _FETCH.search(line):
        return "runtime-fetch"
    return "plaintext"


def _decodes_to_text(blob: str) -> bool:
    try:
        return base64.b64decode(blob, validate=True).decode().isprintable()
    except (binascii.Error, UnicodeDecodeError):
        return False
