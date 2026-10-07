"""Who is behind a host the scan flagged? Two public lookups, run on the host machine.

* RDAP (free, no key) says when the domain was registered.
* Tavily web search says whether anyone publicly reports the domain as malicious.

Only the host name is ever sent out, and never one that looks private: nothing from the repo, the
run or the canaries. Everything that comes back is untrusted text from the internet. It is cleaned
and shortened here, shown to the human as data, and never given to a model. A lookup that fails
reports "unknown", which is different from "searched and found nothing".
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import ssl
import urllib.request
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import date, datetime
from urllib.parse import urlparse

import certifi
from dotenv import load_dotenv

load_dotenv()

SEARCH_URL = "https://api.tavily.com/search"
RDAP_URL = "https://rdap.org/domain/{}"
TIMEOUT = 10
MAX_HOSTS = 5
MAX_REPORTS = 3
SNIPPET_CHARS = 200
RECENT_DAYS = 90
NEAR_CHARS = 150  # a malware word must be this close to the host name to count as a report

_BAD_WORDS = re.compile(
    r"\b(malware|malicious|phishing|scam|botnet|ransomware|trojan|spyware|stealer|c2|exfiltrat\w*)\b"
)

# python.org builds of Python on macOS ship without root certificates, so use certifi's bundle.
_TLS = ssl.create_default_context(cafile=certifi.where())

# Names that only exist inside a private network. They are never sent to a public service.
PRIVATE_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home", ".localdomain", ".intranet")

Fetch = Callable[[urllib.request.Request], dict | None]  # JSON object, or None on any failure


@dataclass(frozen=True)
class Report:
    title: str
    url: str
    snippet: str


@dataclass(frozen=True)
class HostIntel:
    host: str
    registered: date | None  # None: unknown (no RDAP data for this domain)
    age_days: int | None
    reports: tuple[Report, ...] | None  # None: the search could not run; (): nothing found

    @property
    def is_recent(self) -> bool:
        return self.age_days is not None and self.age_days < RECENT_DAYS


def api_key() -> str | None:
    return os.environ.get("TAVILY_API_KEY") or None


def http_json(request: urllib.request.Request, timeout: float = TIMEOUT) -> dict | None:
    """Perform a request and parse a JSON object. Any network or parse failure gives None."""
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_TLS) as response:
            data = json.load(response)
    except (OSError, ValueError):  # URLError, HTTPError and timeouts are OSError
        return None
    return data if isinstance(data, dict) else None


def lookup(
    hosts: Iterable[str],
    *,
    key: str | None,
    fetch: Fetch = http_json,
    today: date | None = None,
) -> dict[str, HostIntel]:
    """Look up each host (IP addresses and dotless names are skipped; at most MAX_HOSTS)."""
    today = today or date.today()
    wanted = [h for h in dict.fromkeys(h.lower().rstrip(".") for h in hosts) if _is_domain(h)]
    wanted = wanted[:MAX_HOSTS]
    with ThreadPoolExecutor(max(1, len(wanted))) as pool:
        found = pool.map(lambda host: _lookup_one(host, key, fetch, today), wanted)
        return {intel.host: intel for intel in found}


def _lookup_one(host: str, key: str | None, fetch: Fetch, today: date) -> HostIntel:
    registered = rdap_registered(host, fetch)
    age = (today - registered).days if registered else None
    reports = search_reports(host, key, fetch) if key else None
    return HostIntel(host, registered, age, reports)


def _is_domain(host: str) -> bool:
    if "." not in host or host.endswith(PRIVATE_SUFFIXES):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


# ---- RDAP: when was the domain registered? ------------------------------------------------------


def domain_candidates(host: str) -> list[str]:
    """Names to try at the registry: without a public-suffix list we guess the registered domain
    is the last 3 or the last 2 labels, longest first (so example.co.uk is tried before co.uk).
    Known limit: for a host under a two-part suffix whose own record is missing, the fallback can
    land on the suffix itself (co.uk) and report its age instead of the domain's."""
    labels = host.split(".")
    return [".".join(labels[-n:]) for n in (3, 2) if len(labels) >= n]


def rdap_registered(host: str, fetch: Fetch) -> date | None:
    for name in domain_candidates(host):
        request = urllib.request.Request(
            RDAP_URL.format(name),
            headers={"Accept": "application/rdap+json", "User-Agent": "agenttrap"},
        )
        data = fetch(request)
        # The answer must be about the name we asked for, not a registry or a parent domain.
        if data and str(data.get("ldhName", "")).lower() == name:
            return _registration_date(data)
    return None


def _registration_date(data: dict) -> date | None:
    for event in data.get("events", []):
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            try:
                return datetime.fromisoformat(str(event["eventDate"]).replace("Z", "+00:00")).date()
            except (KeyError, ValueError):
                return None
    return None


# ---- Tavily: does the public web report this host? ----------------------------------------------


def search_reports(host: str, key: str, fetch: Fetch) -> tuple[Report, ...] | None:
    request = urllib.request.Request(
        SEARCH_URL,
        data=json.dumps(
            {"query": f'"{host}" malware OR phishing OR scam OR malicious', "max_results": 8}
        ).encode(),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "agenttrap",
        },
    )
    data = fetch(request)
    if data is None or not isinstance(data.get("results"), list):
        return None
    reports = []
    for item in data["results"]:
        if not isinstance(item, dict):
            continue
        title, url, content = (str(item.get(k) or "") for k in ("title", "url", "content"))
        if _reports_host(f"{title}. {content}".lower(), host) and not _is_own_site(url, host):
            reports.append(Report(clean(title, 100), url[:300], clean(content, SNIPPET_CHARS)))
    return tuple(reports[:MAX_REPORTS])


def _reports_host(text: str, host: str) -> bool:
    """True when the host name appears close to a malware or phishing word. A page that merely
    contains the name (a list of popular sites, a blog post that links to it) is not a report."""
    for match in re.finditer(re.escape(host), text):
        window = text[max(0, match.start() - NEAR_CHARS) : match.end() + NEAR_CHARS]
        if _BAD_WORDS.search(window):
            return True
    return False


def _is_own_site(url: str, host: str) -> bool:
    """A page on the host itself is the host describing itself, not a report about it."""
    site = urlparse(url).hostname or ""
    return site == host or site.endswith(f".{host}")


def clean(text: str, limit: int) -> str:
    """Collapse whitespace, drop control characters and shorten text that came from the web."""
    text = re.sub(r"\s+", " ", re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", " ", text)).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"
