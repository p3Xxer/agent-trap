"""Make a copy of a scanned repo with the culprit lines removed, so it can be scanned again.

The localizer names lines such as `def f():`, `try:` or `except:` that only make sense together.
Blanking just those lines would leave an indented orphan and a syntax error, and a repo that no
longer runs would look "safe". So in Python files each culprit line is mapped to the innermost
statement that contains it, and whole statements are removed. A removed statement becomes `pass`
and the lines after it become blank, so line numbers do not move and blocks stay valid. Other
file types have exactly the culprit lines blanked.

The copy is for inspection. Removing code can change behavior; a person should review it.
"""

from __future__ import annotations

import ast
import shutil
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from agenttrap.localizer import Culprit

PLACEHOLDER = "pass  # removed by agenttrap"


@dataclass(frozen=True)
class Removal:
    file: str
    first_line: int
    last_line: int

    def __str__(self) -> str:
        span = str(self.first_line) if self.first_line == self.last_line else (
            f"{self.first_line}-{self.last_line}"
        )  # fmt: skip
        return f"{self.file}:{span}"


@dataclass(frozen=True)
class Cleaned:
    files: dict[str, str]  # every file that was given, with culprit code removed
    removed: tuple[Removal, ...]
    warnings: tuple[str, ...] = ()


def clean(files: Mapping[str, str], culprits: Iterable[Culprit]) -> Cleaned:
    lines_by_file: dict[str, set[int]] = defaultdict(set)
    for culprit in culprits:
        lines_by_file[culprit.file].add(culprit.line)

    out, removed, warnings = dict(files), [], []
    for name, lines in sorted(lines_by_file.items()):
        source = files[name]
        statements = _statement_spans(source, lines) if name.endswith(".py") else None
        spans = statements if statements is not None else [(n, n, False) for n in sorted(lines)]
        out[name] = _remove(source, spans)
        removed += [Removal(name, first, last) for first, last, _ in spans]
        if statements is not None and not _parses(out[name]):
            warnings.append(f"{name}: the cleaned file is not valid Python; check it by hand")
    return Cleaned(out, tuple(removed), tuple(warnings))


def _statement_spans(source: str, lines: set[int]) -> list[tuple[int, int, bool]] | None:
    """(first, last, is_statement) spans to remove, or None when the file does not parse.

    Each line maps to the innermost statement containing it (the outer one on a tie, so a
    one-line `if x: f()` is removed whole). Spans nested inside another chosen span are dropped.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    statements = [(_span(node), node) for node in ast.walk(tree) if isinstance(node, ast.stmt)]
    chosen: set[tuple[int, int, bool]] = set()
    for line in lines:
        inside = [(span, node) for span, node in statements if span[0] <= line <= span[1]]
        if inside:
            span = min(inside, key=lambda item: item[0][1] - item[0][0])[0]
            chosen.add((*span, True))
        else:  # a comment or blank line between statements
            chosen.add((line, line, False))
    kept: list[tuple[int, int, bool]] = []
    for first, last, is_statement in sorted(chosen, key=lambda s: (s[0], -s[1])):
        if not kept or first > kept[-1][1]:
            kept.append((first, last, is_statement))
    return kept


def _span(node: ast.stmt) -> tuple[int, int]:
    decorators = [d.lineno for d in getattr(node, "decorator_list", [])]
    return min([node.lineno, *decorators]), node.end_lineno or node.lineno


def _remove(source: str, spans: list[tuple[int, int, bool]]) -> str:
    lines = source.split("\n")
    for first, last, is_statement in spans:
        indent = lines[first - 1][: len(lines[first - 1]) - len(lines[first - 1].lstrip())]
        for n in range(first, last + 1):
            lines[n - 1] = ""
        if is_statement:
            lines[first - 1] = indent + PLACEHOLDER
    return "\n".join(lines)


def _parses(source: str) -> bool:
    try:
        ast.parse(source)
    except SyntaxError:
        return False
    return True


def write_copy(repo: Path, out_dir: Path, changed: Mapping[str, str]) -> None:
    """Copy the whole repo (binary files included, `.git` excluded) and overwrite changed files.

    `out_dir` must not exist or must be empty, so nothing is ever overwritten by accident.
    """
    if out_dir.exists() and any(out_dir.iterdir()):
        raise FileExistsError(f"{out_dir} already exists and is not empty")
    shutil.copytree(  # symlinks stay links; copying what they point at could pull in host files
        repo, out_dir, symlinks=True, ignore=shutil.ignore_patterns(".git"), dirs_exist_ok=True
    )
    for name, text in changed.items():
        (out_dir / name).write_text(text)
