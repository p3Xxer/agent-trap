"""The repo is copied into the sandbox owned by root, whoever owned it on the host."""

import tarfile

from agenttrap.sandbox import _as_root


def test_files_are_given_to_root_whatever_their_owner_was():
    info = tarfile.TarInfo("src/x.egg-info")
    info.uid, info.gid, info.uname, info.gname = 501, 20, "dev", "staff"
    changed = _as_root(info)
    assert (changed.uid, changed.gid, changed.uname, changed.gname) == (0, 0, "root", "root")


def _rewheel(folder):
    import subprocess
    import sys

    from agenttrap.scan import REWHEEL

    return subprocess.run(
        [sys.executable, "-c", REWHEEL], cwd=folder, capture_output=True, text=True, check=True
    ).stdout.strip()


def test_an_unpacked_wheel_is_packed_back_into_an_installable_wheel(tmp_path, monkeypatch):
    import zipfile

    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / "__init__.py").write_text("x = 1\n")
    (tmp_path / "demo-1.0.dist-info").mkdir()
    (tmp_path / "demo-1.0.dist-info" / "METADATA").write_text("Name: demo\nVersion: 1.0\n")
    (tmp_path / "demo-1.0.dist-info" / "RECORD").write_text("stale,sha256=x,1\n")
    (tmp_path / "demo.pth").write_text("import demo\n")
    path = _rewheel(tmp_path)
    assert path == "/tmp/demo-1.0-py3-none-any.whl"
    with zipfile.ZipFile(path) as wheel:
        names = set(wheel.namelist())
        record = wheel.read("demo-1.0.dist-info/RECORD").decode()
    assert {"demo/__init__.py", "demo.pth", "demo-1.0.dist-info/METADATA"} <= names
    assert "stale" not in record and "demo.pth,," in record


def test_a_source_project_is_never_repacked(tmp_path):
    (tmp_path / "setup.py").write_text("")
    (tmp_path / "x-1.0.dist-info").mkdir()
    assert _rewheel(tmp_path) == ""
