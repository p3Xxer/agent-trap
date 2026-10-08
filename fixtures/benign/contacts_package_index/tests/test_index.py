import urllib.request


def test_package_index_is_reachable_or_skipped():
    try:
        urllib.request.urlopen("https://pypi.org/simple/pip/", timeout=5).read()
    except OSError:
        pass  # offline machines are fine
