import os
import subprocess
import time
from pathlib import Path

import pytest

from agenttrap.fetch import (
    FetchError,
    RepoRef,
    clone,
    fetch_repo,
    measure_and_strip,
    parse_github_url,
    repo_info,
)

# ---- 1. the text of the URL ------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "https://github.com/octocat/Hello-World",
        "https://github.com/octocat/Hello-World/",
        "https://github.com/octocat/Hello-World.git",
        "http://github.com/octocat/Hello-World",
        "github.com/octocat/Hello-World",
        "https://www.github.com/octocat/Hello-World",
        "HTTPS://GitHub.com/octocat/Hello-World",
        "  https://github.com/octocat/Hello-World\n",
        "https://github.com/octocat/Hello-World/tree/main",
    ],
)
def test_accepts_the_main_page_of_a_repository(text):
    assert parse_github_url(text) == RepoRef("octocat", "Hello-World")


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        None,
        "hello",
        "https://gitlab.com/octocat/Hello-World",
        "https://github.com.evil.com/octocat/Hello-World",
        "https://evil.com/github.com/octocat/Hello-World",
        "https://user@github.com/octocat/Hello-World",
        "https://github.com:8443/octocat/Hello-World",
        "https://127.0.0.1/octocat/Hello-World",
        "git@github.com:octocat/Hello-World.git",
        "ssh://git@github.com/octocat/Hello-World",
        "file:///etc/passwd",
        "https://github.com",
        "https://github.com/octocat",
        "https://github.com/octocat/Hello-World/issues",
        "https://github.com/octocat/Hello-World/pull/1",
        "https://github.com/octocat/Hello-World?tab=readme",
        "https://github.com/octocat/Hello-World#readme",
        "https://github.com/octocat/Hello World",
        "https://github.com/octocat/Hello-World https://github.com/a/b",
        "https://github.com/octo_cat/Hello-World",
        "https://github.com/-/Hello-World",
        "https://github.com/octocat/..",
        "https://github.com/" + "a" * 40 + "/repo",
        "https://github.com/octocat/" + "r" * 101,
        "https://github.com/octocat/repo$(whoami)",
        "https://github.com/octocat/repo;rm",
        "https://github.com/" + "a" * 400,
    ],
)
def test_refuses_everything_else_with_a_message(text):
    with pytest.raises(FetchError) as error:
        parse_github_url(text)
    assert str(error.value)  # always something a person can read


def test_the_clone_url_is_rebuilt_never_copied_from_the_input():
    ref = parse_github_url("HTTP://www.GitHub.com/octocat/Hello-World.git/")
    assert ref.clone_url == "https://github.com/octocat/Hello-World.git"
    assert ref.slug == "octocat/Hello-World"


# ---- 2. GitHub's API ------------------------------------------

REF = RepoRef("octocat", "Hello-World")


def api_returning(status, data=None):
    calls = []

    def api(url):
        calls.append(url)
        return status, data or {}

    api.calls = calls
    return api


def test_a_public_repo_within_the_limit_is_accepted():
    api = api_returning(200, {"size": 1234, "private": False})
    assert repo_info(REF, api).size_kb == 1234
    assert api.calls == ["https://api.github.com/repos/octocat/Hello-World"]


@pytest.mark.parametrize(
    ("status", "data", "words"),
    [
        (404, {}, "not found"),
        (403, {}, "limiting"),
        (429, {}, "limiting"),
        (0, {}, "Could not reach GitHub"),
        (500, {}, "could not describe"),
        (200, {"message": "odd"}, "could not describe"),
        (200, {"size": 5, "private": True}, "private"),
        (200, {"size": 0, "private": False}, "empty"),
        (200, {"size": 180_000, "private": False}, "180 MB"),
    ],
)
def test_every_bad_answer_becomes_a_clear_message(status, data, words):
    with pytest.raises(FetchError, match=words):
        repo_info(REF, api_returning(status, data))


def test_the_size_limit_is_a_parameter():
    api = api_returning(200, {"size": 2000, "private": False})
    with pytest.raises(FetchError, match="limit is 1 MB"):
        repo_info(REF, api, max_kb=1000)


# ---- 3. the clone, with real git against local repositories ----------------


def git(*args, cwd):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def source(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    git("init", "-q", "-b", "main", cwd=repo)
    (repo / "README.md").write_text("# hello\n")
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("print('hi')\n")
    os.symlink("/etc/passwd", repo / "link")
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "first", cwd=repo)
    return repo


def test_clone_copies_the_files_and_turns_symlinks_into_plain_text(source, tmp_path):
    dest = tmp_path / "copy"
    clone(f"file://{source}", dest, allow_local=True)
    assert (dest / "src" / "app.py").read_text() == "print('hi')\n"
    link = dest / "link"
    assert not link.is_symlink()
    assert link.read_text() == "/etc/passwd"  # the target path as text, not the host's file


def test_local_paths_are_refused_unless_a_test_allows_them(source, tmp_path):
    with pytest.raises(FetchError):
        clone(f"file://{source}", tmp_path / "copy")
    assert not (tmp_path / "copy" / "README.md").exists()


def test_a_missing_repository_is_a_clear_error(tmp_path):
    with pytest.raises(FetchError, match="could not be downloaded"):
        clone(f"file://{tmp_path}/nothing-here", tmp_path / "copy", allow_local=True)


def test_a_clone_that_hangs_is_killed_at_the_time_limit(tmp_path, monkeypatch):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "git").write_text("#!/bin/sh\nsleep 60\n")
    (fake_bin / "git").chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")

    started = time.time()
    with pytest.raises(FetchError, match="longer than 1 seconds"):
        clone("https://github.com/o/r.git", tmp_path / "copy", timeout=1)
    assert time.time() - started < 15


# ---- 4. measuring what we got ------------------------------------------


def make_tree(root: Path, files: dict[str, bytes]) -> Path:
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def test_git_metadata_is_removed(tmp_path):
    make_tree(tmp_path, {"a.py": b"x", ".git/HEAD": b"ref"})
    measure_and_strip(tmp_path)
    assert not (tmp_path / ".git").exists()
    assert (tmp_path / "a.py").exists()


def test_too_many_files_is_refused(tmp_path):
    make_tree(tmp_path, {f"f{i}.txt": b"x" for i in range(6)})
    with pytest.raises(FetchError, match="more than 5 files"):
        measure_and_strip(tmp_path, max_files=5)


def test_too_many_bytes_is_refused(tmp_path):
    make_tree(tmp_path, {"big.bin": b"x" * 3_000_000})
    with pytest.raises(FetchError, match="more than 2 MB"):
        measure_and_strip(tmp_path, max_bytes=2_000_000)


def test_a_tree_with_no_files_is_refused(tmp_path):
    (tmp_path / ".git").mkdir()
    with pytest.raises(FetchError, match="no files"):
        measure_and_strip(tmp_path)


def test_symlinks_are_not_followed_when_measuring(tmp_path):
    big = tmp_path / "outside"
    big.write_bytes(b"x" * 3_000_000)
    tree = tmp_path / "tree"
    tree.mkdir()
    os.symlink(big, tree / "link")
    (tree / "a.txt").write_text("x")
    measure_and_strip(tree, max_bytes=1_000_000)  # the link itself is tiny


# ---- all four steps together ------------------------------


def fake_clone(files):
    def do_clone(url, dest):
        assert url == "https://github.com/octocat/Hello-World.git"
        make_tree(dest, files)

    return do_clone


def test_fetch_repo_returns_the_reference_and_the_local_copy(tmp_path):
    api = api_returning(200, {"size": 10, "private": False})
    ref, dest = fetch_repo(
        "github.com/octocat/Hello-World", tmp_path, api=api, do_clone=fake_clone({"a.py": b"x"})
    )
    assert ref == REF
    assert (dest / "a.py").exists()
    assert dest.parent == tmp_path


def test_a_bad_url_never_reaches_the_network(tmp_path):
    api = api_returning(200, {"size": 10})
    with pytest.raises(FetchError):
        fetch_repo("https://evil.com/a/b", tmp_path, api=api, do_clone=fake_clone({}))
    assert api.calls == []


def test_a_too_big_repo_is_refused_before_cloning(tmp_path):
    def must_not_clone(url, dest):
        raise AssertionError("cloned a repo that is over the limit")

    api = api_returning(200, {"size": 999_999, "private": False})
    with pytest.raises(FetchError, match="MB"):
        fetch_repo("github.com/octocat/Hello-World", tmp_path, api=api, do_clone=must_not_clone)


def test_a_failed_clone_leaves_nothing_behind(tmp_path):
    def broken(url, dest):
        dest.mkdir()
        (dest / "half.txt").write_text("partial")
        raise FetchError("The repository could not be downloaded.")

    api = api_returning(200, {"size": 10, "private": False})
    with pytest.raises(FetchError):
        fetch_repo("github.com/octocat/Hello-World", tmp_path, api=api, do_clone=broken)
    assert list(tmp_path.iterdir()) == []


def test_a_clone_that_turns_out_too_big_is_removed(tmp_path):
    api = api_returning(200, {"size": 10, "private": False})
    files = {f"f{i}.txt": b"x" for i in range(5)}
    with pytest.raises(FetchError, match="too many"):
        fetch_repo(
            "github.com/octocat/Hello-World",
            tmp_path,
            api=api,
            do_clone=fake_clone(files),
            max_files=2,
        )
    assert list(tmp_path.iterdir()) == []
