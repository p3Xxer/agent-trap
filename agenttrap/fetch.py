"""Turn text pasted into a web page into a safe, size-limited local copy of a public GitHub repo.

The checks run cheapest first, so a bad request is refused before anything is downloaded:

1. the text must be a plain https://github.com/<owner>/<repo> address (no network);
2. GitHub's API says whether the repo exists, is public and how big it is (one small request);
3. a shallow clone with a time limit, no submodules, no password prompts and no symlinks;
4. the working tree is measured (bytes and files) and `.git` is removed.

Every failure is a `FetchError` whose message is written for the person at the page.
Nothing from the repo is executed here: a clone does not run repository hooks, and git LFS
downloads are switched off.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from agenttrap.net import TLS

MAX_REPO_KB = 50_000  # 50 MB, as reported by GitHub before we download anything
MAX_TREE_BYTES = 50_000_000
MAX_FILES = 3_000
CLONE_TIMEOUT = 120
API_TIMEOUT = 15

_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
_REPO = re.compile(r"[A-Za-z0-9._-]{1,100}")
_PATH = re.compile(r"/([^/]+)/([^/]+?)(?:\.git)?(?:/tree/[^/]+)?/?")


class FetchError(Exception):
    """A problem the user can understand and fix. `str(error)` is shown on the page."""


@dataclass(frozen=True)
class RepoRef:
    owner: str
    repo: str

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}.git"

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass(frozen=True)
class RepoInfo:
    size_kb: int
    private: bool


# ---- 1. the text of the URL ------------------------------------------


def parse_github_url(text: str) -> RepoRef:
    """`https://github.com/owner/repo` (also without the scheme, with `.git`, or a `/tree/<branch>`
    page, which is read as the repo itself). Anything else is refused."""
    text = text.strip() if isinstance(text, str) else ""
    hint = "Paste the address of a public GitHub repository, like https://github.com/owner/repo"
    if not text:
        raise FetchError(hint)
    if re.search(r"\s", text) or len(text) > 300:
        raise FetchError(f"That does not look like a single URL. {hint}")

    candidate = re.sub(r"^https?://", "", text, flags=re.I)
    host, slash, path = candidate.partition("/")
    if host.lower() not in ("github.com", "www.github.com"):
        raise FetchError(f"Only github.com repositories can be scanned. {hint}")
    if "?" in path or "#" in path:
        raise FetchError(f"Remove everything after the repository name. {hint}")
    match = _PATH.fullmatch(slash + path)
    if not match:
        raise FetchError(f"That is not the main page of a repository. {hint}")

    owner, repo = match.groups()
    if not _OWNER.fullmatch(owner) or not _REPO.fullmatch(repo) or repo in (".", ".."):
        raise FetchError(f"That is not a valid GitHub owner or repository name. {hint}")
    return RepoRef(owner, repo)


# ---- 2. GitHub's API ------------------------------------------

Api = Callable[[str], tuple[int, dict]]  # URL -> (HTTP status, JSON object); status 0 = no answer


def github_api(url: str) -> tuple[int, dict]:
    request = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "agenttrap"}
    )
    try:
        with urllib.request.urlopen(request, timeout=API_TIMEOUT, context=TLS) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read()
    except OSError:
        return 0, {}
    try:
        data = json.loads(body)
    except ValueError:
        return status, {}
    return status, data if isinstance(data, dict) else {}


def repo_info(ref: RepoRef, api: Api = github_api, max_kb: int = MAX_REPO_KB) -> RepoInfo:
    status, data = api(f"https://api.github.com/repos/{ref.owner}/{ref.repo}")
    if status == 0:
        raise FetchError("Could not reach GitHub. Check your internet connection and try again.")
    if status == 404:
        raise FetchError(f"{ref.slug} was not found. It may be private or misspelled.")
    if status in (403, 429):
        raise FetchError(
            "GitHub is limiting requests from this network. Try again in a few minutes."
        )
    if status != 200 or "size" not in data:
        raise FetchError(f"GitHub could not describe {ref.slug} (status {status}).")
    info = RepoInfo(size_kb=int(data["size"]), private=bool(data.get("private")))
    if info.private:
        raise FetchError(f"{ref.slug} is private. Only public repositories can be scanned.")
    if info.size_kb == 0:
        raise FetchError(f"{ref.slug} is empty: there is nothing to scan.")
    if info.size_kb > max_kb:
        raise FetchError(
            f"{ref.slug} is {info.size_kb / 1000:.0f} MB; the limit is {max_kb / 1000:.0f} MB."
        )
    return info


# ---- 3. the clone ------------------------------------------


def clone(
    url: str, dest: Path, *, timeout: float = CLONE_TIMEOUT, allow_local: bool = False
) -> None:
    """A shallow, single-branch clone with a hard time limit.

    `allow_local` lets tests clone from a path on disk; it is never set for pasted URLs.
    """
    command = [
        "git",
        "-c", "core.symlinks=false",  # a symlink to /etc/passwd becomes a plain text file
        "-c", "core.hooksPath=/dev/null",
        "-c", f"protocol.file.allow={'always' if allow_local else 'never'}",
        "clone", "--depth", "1", "--single-branch", "--no-tags", "--quiet", "--", url, str(dest),
    ]  # fmt: skip
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    process = subprocess.Popen(  # noqa: S603 - fixed argument list, no shell
        command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        start_new_session=True,
    )  # fmt: skip
    try:
        _, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)  # git and its helper processes
        process.communicate()
        raise FetchError(
            f"Downloading took longer than {timeout:.0f} seconds, so it was stopped."
        ) from None
    if process.returncode != 0:
        lowered = stderr.lower()
        if "not found" in lowered or "could not read username" in lowered or "denied" in lowered:
            raise FetchError("The repository was not found or is not public.")
        raise FetchError("The repository could not be downloaded.")


# ---- 4. what we got ------------------------------------------


def measure_and_strip(
    tree: Path, max_bytes: int = MAX_TREE_BYTES, max_files: int = MAX_FILES
) -> None:
    """Remove `.git`, then refuse a tree with too many bytes or files. Symlinks are not followed."""
    shutil.rmtree(tree / ".git", ignore_errors=True)
    total = count = 0
    for root, _dirs, files in os.walk(tree, followlinks=False):
        for name in files:
            count += 1
            total += (Path(root) / name).lstat().st_size
            if count > max_files:
                raise FetchError(
                    f"The repository has more than {max_files:,} files; too many to scan."
                )
            if total > max_bytes:
                raise FetchError(
                    f"The repository holds more than {max_bytes // 1_000_000} MB of files."
                )
    if count == 0:
        raise FetchError("The repository has no files to scan.")


def fetch_repo(
    text: str,
    parent: Path,
    *,
    api: Api = github_api,
    do_clone: Callable[[str, Path], None] = clone,
    max_files: int = MAX_FILES,
    max_bytes: int = MAX_TREE_BYTES,
) -> tuple[RepoRef, Path]:
    """Validate `text`, check the repo with GitHub, clone it into `parent` and measure it.

    On any failure nothing is left behind in `parent`.
    """
    ref = parse_github_url(text)
    repo_info(ref, api)
    dest = parent / f"{ref.owner}__{ref.repo}"
    try:
        do_clone(ref.clone_url, dest)
        measure_and_strip(dest, max_bytes, max_files)
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return ref, dest
