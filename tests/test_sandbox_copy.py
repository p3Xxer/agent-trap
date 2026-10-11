"""The repo is copied into the sandbox owned by root, whoever owned it on the host."""

import tarfile

from agenttrap.sandbox import _as_root


def test_files_are_given_to_root_whatever_their_owner_was():
    info = tarfile.TarInfo("src/x.egg-info")
    info.uid, info.gid, info.uname, info.gname = 501, 20, "dev", "staff"
    changed = _as_root(info)
    assert (changed.uid, changed.gid, changed.uname, changed.gname) == (0, 0, "root", "root")
