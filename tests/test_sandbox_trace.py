"""The hook that notes which repo files Python ran, run for real in a subprocess."""

import os
import subprocess
import sys
from pathlib import Path

from agenttrap import sandbox

HOOK_DIR = Path(sandbox.__file__).with_name("sandbox_trace")


def run_traced(root: Path, log: Path, code: str, *args: str) -> subprocess.CompletedProcess:
    """Run `python -c code` from `root`, which stands in for /work."""
    env = {
        **os.environ,
        "PYTHONPATH": str(HOOK_DIR),
        "AGENTTRAP_TRACE_ROOT": str(root),
        "AGENTTRAP_TRACE_LOG": str(log),
    }
    return subprocess.run(
        [sys.executable, "-c", code, *args], cwd=root, env=env, capture_output=True, text=True
    )


def logged(log: Path) -> set[str]:
    return set(log.read_text().split("\n")) - {""} if log.exists() else set()


def test_only_files_under_the_root_are_logged_and_as_relative_paths(tmp_path):
    root = tmp_path / "work"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("from pkg import helper\n")
    (root / "pkg" / "helper.py").write_text("VALUE = 1\n")
    (root / "unused.py").write_text("VALUE = 2\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "elsewhere.py").write_text("VALUE = 3\n")
    log = tmp_path / "loaded.txt"
    done = run_traced(
        root, log, f"import sys; sys.path[:0] = ['.', {str(outside)!r}]; import pkg, elsewhere"
    )
    assert done.returncode == 0, done.stderr
    assert logged(log) == {"pkg/__init__.py", "pkg/helper.py"}  # not unused.py, not elsewhere.py
    assert all(not line.startswith("/") for line in log.read_text().split())


def test_code_run_from_a_script_or_executed_from_source_is_logged_in_child_processes(tmp_path):
    root = tmp_path / "work"
    root.mkdir()
    (root / "setup.py").write_text("print('building')\n")
    (root / "hooked.py").write_text("")
    log = tmp_path / "loaded.txt"
    child = (
        "import subprocess, sys;"
        "subprocess.run([sys.executable, 'setup.py']);"  # a script run as the main program
        f"exec(compile(open('hooked.py').read(), {str(root / 'hooked.py')!r}, 'exec'))"
    )
    done = run_traced(root, log, child)
    assert done.returncode == 0, done.stderr
    assert logged(log) == {"setup.py", "hooked.py"}


def test_a_log_that_cannot_be_written_does_not_break_the_program(tmp_path):
    root = tmp_path / "work"
    root.mkdir()
    (root / "mod.py").write_text("VALUE = 1\n")
    done = run_traced(
        root,
        tmp_path / "no-such-folder" / "loaded.txt",
        "import sys; sys.path[:0] = ['.']; import mod; print('ok')",
    )
    assert (done.returncode, done.stdout.strip(), done.stderr) == (0, "ok", "")
