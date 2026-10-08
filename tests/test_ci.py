from agenttrap.ci import (
    annotation_lines,
    commands_disabled,
    emit_github,
    running_in_github,
    summary_markdown,
)
from agenttrap.findings import Finding, Location, findings
from tests.scan_results import injection, intel_for, leaking_result, safe_result

LEAK = "agent-trap/secret-leak"


def test_a_leak_gives_one_error_annotation_per_key_line():
    lines = annotation_lines(findings(leaking_result()))
    errors = [line for line in lines if line.startswith("::error ")]
    assert len(errors) == 2
    assert errors[0].startswith("::error file=setup.py,line=10,title=Agent Trap%3A Secret leaves")
    assert errors[1].startswith("::error file=setup.py,line=11,")
    assert "::notice title=" in lines[-1]  # the unexpected host has no line


def test_warnings_and_notes_use_their_own_commands():
    result = leaking_result(injections=[injection("README.md:11")])
    commands = {line.split(" ", 1)[0] for line in annotation_lines(findings(result))}
    assert commands == {"::error", "::warning", "::notice"}


def test_a_finding_without_a_line_still_produces_an_annotation_without_a_file():
    [line] = annotation_lines([Finding(LEAK, "no line known")])
    assert line == "::error title=Agent Trap%3A Secret leaves the sandbox::no line known"


def test_newlines_in_untrusted_text_cannot_start_a_second_command():
    evil = "boom\n::error file=/etc/passwd,line=1::fake\r\n::set-output name=x::y"
    lines = annotation_lines([Finding(LEAK, evil, (Location("a.py", 1, evil),))])
    assert len(lines) == 1
    assert "\n" not in lines[0] and "\r" not in lines[0]
    # the command and its properties are ours; the attacker's text is only message data
    assert lines[0].startswith("::error file=a.py,line=1,title=Agent Trap%3A Secret leaves")
    assert "boom%0A::error" in lines[0] and "%0D%0A::set-output" in lines[0]


def test_percent_signs_are_escaped_so_encoded_newlines_cannot_be_forged():
    [line] = annotation_lines([Finding(LEAK, "100%0A::error::x")])
    assert "100%250A" in line and "%0A" not in line.replace("%250A", "")


def test_file_names_with_commas_and_colons_cannot_add_properties():
    [line] = annotation_lines([Finding(LEAK, "m", (Location("a,line=99:b.py", 3),))])
    assert line.startswith("::error file=a%2Cline=99%3Ab.py,line=3,title=")


def test_a_very_long_message_is_cut():
    [line] = annotation_lines([Finding(LEAK, "x" * 5000)])
    assert len(line) < 800


# ---- the run summary ------------------------------


def test_summary_has_the_verdict_and_a_table_of_findings():
    result = leaking_result(intel=intel_for())
    text = summary_markdown(result, findings(result))
    assert text.startswith("## Agent Trap: HIJACKED")
    assert "| Finding | Where | Details |" in text
    assert "`setup.py:10`, `setup.py:11`" in text


def test_a_safe_summary_has_no_table():
    text = summary_markdown(safe_result(), [])
    assert "## Agent Trap: SAFE" in text and "| Finding" not in text


def test_untrusted_text_cannot_break_the_summary_table():
    evil = Finding(LEAK, "a | b\n| injected | row |\n`code`", (Location("x|y.py", 1),))
    text = summary_markdown(leaking_result(), [evil])
    rows = [line for line in text.splitlines() if line.startswith("| Secret leaves")]
    assert len(rows) == 1  # the injected newline did not create another row
    assert "a \\| b" in rows[0] and "x\\|y.py" in rows[0]


# ---- emitting ------------------------------


def test_emit_prints_annotations_and_appends_the_summary(tmp_path, monkeypatch, capsys):
    summary = tmp_path / "summary.md"
    summary.write_text("earlier step\n")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    result = leaking_result()
    emit_github(result, findings(result))
    assert capsys.readouterr().out.startswith("::error file=setup.py,line=10")
    assert summary.read_text().startswith("earlier step\n## Agent Trap: HIJACKED")


def test_emit_works_without_a_summary_file(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    result = leaking_result()
    emit_github(result, findings(result))
    assert "::error" in capsys.readouterr().out


def test_commands_are_disabled_between_two_matching_markers(capsys):
    with commands_disabled():
        print("::error::from the report")
    first, middle, last = capsys.readouterr().out.splitlines()
    token = first.removeprefix("::stop-commands::")
    assert len(token) == 32 and middle == "::error::from the report"
    assert last == f"::{token}::"


def test_each_block_uses_a_fresh_token(capsys):
    for _ in range(2):
        with commands_disabled():
            pass
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] != lines[2]


def test_the_resume_marker_is_printed_even_if_the_block_fails(capsys):
    try:
        with commands_disabled():
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert len(capsys.readouterr().out.splitlines()) == 2


def test_running_in_github_reads_the_environment(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert running_in_github()
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    assert not running_in_github()
    monkeypatch.delenv("GITHUB_ACTIONS")
    assert not running_in_github()
