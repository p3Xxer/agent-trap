"""Host lookups, with the network replaced by a fake that answers from a dict."""

import io
import json
from datetime import date

from rich.console import Console

from agenttrap.egress import Observed, unexpected_hosts
from agenttrap.intel import (
    MAX_HOSTS,
    HostIntel,
    PackageIntel,
    Report,
    clean,
    domain_candidates,
    lookup,
    lookup_package,
    package_identity,
    rdap_registered,
    search_package_reports,
    search_reports,
)
from agenttrap.reporter import render_intel, render_package

TODAY = date(2026, 10, 7)


class FakeWeb:
    """Answers RDAP by domain name and Tavily by a fixed result list; records every request."""

    def __init__(self, rdap=None, results=None):
        self.rdap = rdap or {}
        self.results = results
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        if "tavily" in request.full_url:
            return None if self.results is None else {"results": self.results}
        name = request.full_url.rsplit("/", 1)[1]
        if name in self.rdap:
            return {
                "ldhName": name,
                "events": [{"eventAction": "registration", "eventDate": self.rdap[name]}],
            }
        return None


def hit(title, content, url="https://blog.example.net/post"):
    return {"title": title, "content": content, "url": url}


# ---- RDAP ------------------------------


def test_candidates_try_the_longer_name_first():
    assert domain_candidates("setup-check.io") == ["setup-check.io"]
    assert domain_candidates("cdn.evil.com") == ["cdn.evil.com", "evil.com"]
    assert domain_candidates("a.b.evil.co.uk") == ["evil.co.uk", "co.uk"]


def test_registration_date_and_age():
    web = FakeWeb(rdap={"evil.com": "2026-09-26T10:00:00Z"})
    [intel] = lookup(["evil.com"], key=None, fetch=web, today=TODAY).values()
    assert intel.registered == date(2026, 9, 26)
    assert intel.age_days == 11
    assert intel.is_recent


def test_falls_back_to_the_parent_domain():
    web = FakeWeb(rdap={"evil.com": "2015-01-01T00:00:00Z"})
    assert rdap_registered("cdn.evil.com", web) == date(2015, 1, 1)


def test_answer_about_a_different_name_is_ignored():
    def parent_answer(request):  # a registry that answers with the parent's record
        return {
            "ldhName": "com",
            "events": [{"eventAction": "registration", "eventDate": "1985-01-01"}],
        }

    assert rdap_registered("evil.com", parent_answer) is None


def test_old_domain_is_not_recent():
    web = FakeWeb(rdap={"old.org": "2001-05-05T00:00:00Z"})
    assert not lookup(["old.org"], key=None, fetch=web, today=TODAY)["old.org"].is_recent


# ---- Tavily ------------------------------


def test_only_pages_that_mention_the_host_and_are_not_its_own_site_count():
    web = FakeWeb(
        results=[
            hit("Campaign analysis", "The domain evil.com serves a malware payload."),
            hit("Cooking pasta", "A recipe with no relevant text."),
            hit("evil.com", "Welcome to evil.com", url="https://evil.com/home"),
            hit("Report", "see cdn.evil.com", url="https://cdn.evil.com/x"),
        ]
    )
    reports = search_reports("evil.com", "k", web)
    assert [r.title for r in reports] == ["Campaign analysis"]


def test_a_page_that_merely_contains_the_name_is_not_a_report():
    far = "evil.com is mentioned here. " + "filler text. " * 30 + "Unrelated: phishing tips."
    web = FakeWeb(results=[hit("Popular sites", far), hit("List", "Top sites: evil.com, a.org")])
    assert search_reports("evil.com", "k", web) == ()


def test_search_sends_only_the_host_and_the_key_only_in_the_header():
    web = FakeWeb(results=[])
    search_reports("evil.com", "tvly-secret", web)
    [request] = web.requests
    body = json.loads(request.data)
    assert set(body) == {"query", "max_results"}
    assert "evil.com" in body["query"]
    assert request.get_header("Authorization") == "Bearer tvly-secret"
    assert "tvly-secret" not in request.full_url + request.data.decode()


def test_nothing_found_differs_from_search_unavailable():
    found_nothing = lookup(["evil.com"], key="k", fetch=FakeWeb(results=[]), today=TODAY)
    failed = lookup(["evil.com"], key="k", fetch=FakeWeb(results=None), today=TODAY)
    assert found_nothing["evil.com"].reports == ()
    assert failed["evil.com"].reports is None


def test_without_a_key_rdap_still_runs_and_search_does_not():
    web = FakeWeb(rdap={"evil.com": "2020-01-01T00:00:00Z"})
    [intel] = lookup(["evil.com"], key=None, fetch=web, today=TODAY).values()
    assert intel.reports is None
    assert intel.registered == date(2020, 1, 1)
    assert not any("tavily" in r.full_url for r in web.requests)


def test_web_text_is_cleaned_and_shortened():
    assert clean("a\x1b[31m  b\n\n c\x00", 50) == "a [31m b c"
    assert clean("x" * 300, 20) == "x" * 19 + "…"


# ---- which hosts ------------------------------


def test_ip_addresses_and_dotless_names_are_skipped_and_the_list_is_capped():
    web = FakeWeb()
    hosts = ["1.2.3.4", "localhost", "[::1]", *[f"h{i}.example.com" for i in range(10)]]
    result = lookup(hosts, key=None, fetch=web, today=TODAY)
    assert list(result) == [f"h{i}.example.com" for i in range(MAX_HOSTS)]


def test_internal_looking_names_are_never_looked_up():
    web = FakeWeb()
    hosts = ["db.corp", "printer.local", "api.internal", "nas.home", "evil.com"]
    assert list(lookup(hosts, key="k", fetch=web, today=TODAY)) == ["evil.com"]
    assert not any("corp" in r.full_url or "local" in r.full_url for r in web.requests)


def test_unexpected_hosts_respects_the_allow_list():
    observed = Observed((), ("pypi.org", "evil.com", "files.pythonhosted.org"))
    assert unexpected_hosts(observed, {"pypi.org", "files.pythonhosted.org"}) == ["evil.com"]


# ---- the report ------------------------------


def render(intel):
    out = io.StringIO()
    render_intel(intel, Console(file=out, width=100, force_terminal=False))
    return out.getvalue()


def test_report_shows_age_reports_and_unknowns():
    text = render(
        {
            "evil.com": HostIntel(
                "evil.com",
                date(2026, 9, 26),
                11,
                (Report("Campaign", "https://blog.example.net/p", "uses evil.com"),),
            ),
            "quiet.io": HostIntel("quiet.io", None, None, ()),
            "blind.io": HostIntel("blind.io", None, None, None),
        }
    )
    assert "2026-09-26 (11 days ago)  (recent)" in text
    assert "1 page(s) mention it" in text
    assert "web reports: none found" in text
    assert "unknown (search did not run)" in text


def test_text_from_the_web_cannot_break_or_restyle_the_report():
    nasty = Report("[/] [bold red]x[/", "https://a.test/[/]", "[link=http://evil]click[/link]")
    text = render({"evil.com": HostIntel("evil.com", None, None, (nasty,))})
    assert "[bold red]x[/" in text
    assert "[link=http://evil]click[/link]" in text


def test_a_page_about_attackers_misusing_a_host_counts_as_a_report():
    from agenttrap.intel import _reports_host

    text = "this blog explores the potential misuse of webhook.site by attackers to collect data"
    assert _reports_host(text, "webhook.site")
    assert not _reports_host("webhook.site lets you inspect http requests", "webhook.site")


def test_reserved_names_that_cannot_exist_are_never_looked_up():
    from agenttrap.intel import _is_domain

    for host in ("setup-check.test", "collector.agenttrap.invalid", "x.example", "a.localhost"):
        assert not _is_domain(host)
    assert _is_domain("setup-check.io")


# ---- has this package version already been reported? ------------------------------------------


def write(folder, name, text):
    (folder / name).write_text(text)
    return folder


def test_package_identity_from_each_kind_of_file(tmp_path):
    a, b, c, d = (tmp_path / x for x in "abcd")
    for x in (a, b, c, d):
        x.mkdir()
    write(a, "PKG-INFO", "Metadata-Version: 2.1\nName: litellm\nVersion: 1.107.0\n\nName: body\n")
    write(b, "pyproject.toml", '[project]\nname = "fast-invoice"\nversion = "0.3.1"\n')
    write(c, "setup.cfg", "[metadata]\nname = tiketoken\nversion = 99.7\n")
    write(d, "setup.py", "setup(name='s3transfer_sl', version='0.12.5')")
    assert package_identity(a) == ("litellm", "1.107.0")
    assert package_identity(b) == ("fast-invoice", "0.3.1")
    assert package_identity(c) == ("tiketoken", "99.7")
    assert package_identity(d) == ("s3transfer_sl", "0.12.5")


def test_no_version_or_an_odd_name_means_no_search(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\nname = "x"\ndynamic = ["version"]\n')
    assert package_identity(tmp_path) is None
    write(tmp_path, "PKG-INFO", "Name: bad name; rm -rf\nVersion: 1.0\n")
    assert package_identity(tmp_path) is None


def test_a_private_project_name_is_never_sent_out(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\nname = "secret-internal-tool"\nversion = "1.0"\n')
    web = FakeWeb(results=[])
    assert lookup_package(tmp_path, key="k", public=False, fetch=web) is None
    assert web.requests == []
    assert lookup_package(tmp_path, key="k", public=True, fetch=web).name == "secret-internal-tool"


def test_a_published_package_is_searched_and_sends_only_its_name_and_version(tmp_path):
    write(tmp_path, "PKG-INFO", "Name: litellm\nVersion: 1.107.0\n")
    web = FakeWeb(results=[])
    info = lookup_package(tmp_path, key="tvly-secret", public=False, fetch=web)
    assert info == PackageIntel("litellm", "1.107.0", ())
    [request] = web.requests
    body = json.loads(request.data)
    assert set(body) == {"query", "max_results"}
    assert '"litellm" "1.107.0"' in body["query"]
    assert "tvly-secret" not in request.full_url + request.data.decode()


def test_without_a_key_nothing_is_searched(tmp_path):
    write(tmp_path, "PKG-INFO", "Name: litellm\nVersion: 1.107.0\n")
    web = FakeWeb(results=[])
    assert lookup_package(tmp_path, key=None, public=True, fetch=web) is None
    assert web.requests == []


def test_a_report_must_name_this_version_near_a_malware_word():
    results = [
        hit("LiteLLM 1.107.0 compromised on PyPI", "The release steals cloud and AI keys."),
        hit("Typosquats", "A malicious typosquat of litellm was found."),  # no version
        hit("Release notes", "litellm 1.107.0 adds a new router."),  # no malware word
        hit("Other version", "litellm 1.107.01 is malicious."),  # a different version
    ]
    found = search_package_reports("litellm", "1.107.0", "k", FakeWeb(results=results))
    assert [r.title for r in found] == ["LiteLLM 1.107.0 compromised on PyPI"]


def test_name_separators_count_as_the_same_and_search_failure_is_unknown():
    results = [hit("Report", "The package s3transfer-sl 0.12.5 is malicious.")]
    assert search_package_reports("s3transfer_sl", "0.12.5", "k", FakeWeb(results=results))
    assert search_package_reports("x", "1.0", "k", FakeWeb(results=None)) is None


def test_package_reports_are_shown_as_escaped_text():
    out = io.StringIO()
    info = PackageIntel("litellm", "1.107.0", (Report("[bold]x[/]", "https://a.net/p", "steals"),))
    render_package(info, Console(file=out, width=200, color_system=None))
    text = out.getvalue()
    assert "Has litellm 1.107.0 already been reported?" in text
    assert "[bold]x[/]" in text


def test_the_scan_page_is_told_what_the_package_search_found():
    from agenttrap.pipeline import _package_message

    report = Report("t", "https://a.net/p", "s")
    assert "no public reports of x 1.0" in _package_message(PackageIntel("x", "1.0", ()))
    assert "1 public page(s)" in _package_message(PackageIntel("x", "1.0", (report,)))
    assert "could not search" in _package_message(PackageIntel("x", "1.0", None))


def test_an_unpacked_wheel_is_a_published_package_and_names_itself(tmp_path):
    (tmp_path / "elementary_data-0.23.3.dist-info").mkdir()
    (tmp_path / "elementary_data-0.23.3.dist-info" / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: elementary-data\nVersion: 0.23.3\n"
    )
    assert package_identity(tmp_path) == ("elementary-data", "0.23.3")
    web = FakeWeb(results=[])
    info = lookup_package(tmp_path, key="k", public=False, fetch=web)
    assert info == PackageIntel("elementary-data", "0.23.3", ())
