"""Host lookups, with the network replaced by a fake that answers from a dict."""

import io
import json
from datetime import date

from rich.console import Console

from agenttrap.egress import Observed, unexpected_hosts
from agenttrap.intel import (
    MAX_HOSTS,
    HostIntel,
    Report,
    clean,
    domain_candidates,
    lookup,
    rdap_registered,
    search_reports,
)
from agenttrap.reporter import render_intel

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
