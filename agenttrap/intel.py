"""Who is behind a host the scan flagged, and has this package already been reported? Public
lookups, run on the host machine.

* RDAP (free, no key) says when the domain was registered.
* Tavily web search says whether anyone publicly reports the domain as malicious.
* Tavily web search says whether anyone publicly reports this package version as malicious or
  compromised. Only for a published package (an unpacked sdist, which has PKG-INFO) or a
  repository downloaded from a public link, so a private project's name is never sent out.

Only the host name, or the package's name and version, is ever sent out, and never a host that
looks private: nothing else from the repo, the run or the canaries. Everything that comes back is
untrusted text from the internet. It is cleaned and shortened here, shown to the human as data,
and never given to a model. A lookup that fails reports "unknown", which is different from
"searched and found nothing".
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import tomllib
import urllib.request
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from configparser import ConfigParser
from configparser import Error as ConfigError
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

from agenttrap.net import TLS

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
    r"\b(malware|malicious|phishing|scam|botnet|ransomware|trojan|spyware|stealer|c2|exfiltrat\w*"
    r"|misus\w*|abus\w*|attackers?)\b"
)

# Names that only exist inside a private network, or are reserved and can never exist on the
# internet (RFC 2606, 6761). They are never sent to a public service.
PRIVATE_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home", ".localdomain", ".intranet",
                    ".test", ".invalid", ".example", ".localhost")  # fmt: skip

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


@dataclass(frozen=True)
class PackageIntel:
    name: str
    version: str
    reports: tuple[Report, ...] | None  # None: the search could not run; (): nothing found


def api_key() -> str | None:
    return os.environ.get("TAVILY_API_KEY") or None


def http_json(request: urllib.request.Request, timeout: float = TIMEOUT) -> dict | None:
    """Perform a request and parse a JSON object. Any network or parse failure gives None."""
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=TLS) as response:
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


def _tavily_request(query: str, key: str) -> urllib.request.Request:
    return urllib.request.Request(
        SEARCH_URL,
        data=json.dumps({"query": query, "max_results": 8}).encode(),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "agenttrap",
        },
    )


def search_reports(host: str, key: str, fetch: Fetch) -> tuple[Report, ...] | None:
    query = f'"{host}" malware OR phishing OR scam OR malicious'
    data = fetch(_tavily_request(query, key))
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


# ---- Tavily: has this package version already been reported? -----------------------------------

_PACKAGE_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+!_-]{0,39}")
_PACKAGE_BAD_WORDS = re.compile(
    r"\b(malware|malicious|compromised?|backdoor\w*|trojan\w*|stealer|steals?|exfiltrat\w*"
    r"|supply[- ]chain attack)\b"
)
VERSION_GAP = 40  # the version must follow the package name within this many characters


def lookup_package(
    repo: Path, *, key: str | None, public: bool, fetch: Fetch = http_json
) -> PackageIntel | None:
    """Search the web for reports of this exact package version. None when there is no key, no
    name and version to search for, or the name may be private (not a published package, and not
    downloaded from a public link)."""
    if not key or not (public or _published(repo)):
        return None
    identity = package_identity(repo)
    if identity is None:
        return None
    name, version = identity
    return PackageIntel(name, version, search_package_reports(name, version, key, fetch))


def _published(repo: Path) -> bool:
    """An sdist (PKG-INFO) or an unpacked wheel (a *.dist-info folder) came from a package
    index, so its name is already public."""
    return (repo / "PKG-INFO").is_file() or any(repo.glob("*.dist-info/METADATA"))


def package_identity(repo: Path) -> tuple[str, str] | None:
    """The package's name and version, from the first file that states both: PKG-INFO (in every
    sdist), pyproject.toml, setup.cfg, then plain literals in setup.py. Nothing is run."""
    for read in (_from_pkg_info, _from_wheel, _from_pyproject, _from_setup_cfg, _from_setup_py):
        try:
            found = read(repo)
        except (OSError, UnicodeDecodeError, ValueError, ConfigError, AttributeError):
            found = None
        if found and _PACKAGE_NAME.fullmatch(found[0]) and _VERSION.fullmatch(found[1]):
            return found
    return None


def _from_pkg_info(repo: Path, path: str = "PKG-INFO") -> tuple[str, str] | None:
    fields = {}
    for line in (repo / path).read_text(errors="replace").splitlines():
        if not line.strip():
            break  # the headers end at the first blank line
        key, _, value = line.partition(":")
        fields.setdefault(key.strip().lower(), value.strip())
    return (fields["name"], fields["version"]) if "name" in fields and "version" in fields else None


def _from_wheel(repo: Path) -> tuple[str, str] | None:
    """An unpacked wheel states its name and version in *.dist-info/METADATA, in the same
    format as PKG-INFO."""
    found = sorted(repo.glob("*.dist-info/METADATA"))
    return _from_pkg_info(repo, str(found[0].relative_to(repo))) if found else None


def _from_pyproject(repo: Path) -> tuple[str, str] | None:
    project = tomllib.loads((repo / "pyproject.toml").read_text()).get("project", {})
    name, version = project.get("name"), project.get("version")
    return (name, version) if isinstance(name, str) and isinstance(version, str) else None


def _from_setup_cfg(repo: Path) -> tuple[str, str] | None:
    config = ConfigParser(interpolation=None)
    config.read_string((repo / "setup.cfg").read_text())
    name = config.get("metadata", "name", fallback=None)
    version = config.get("metadata", "version", fallback=None)
    return (name.strip(), version.strip()) if name and version else None


def _from_setup_py(repo: Path) -> tuple[str, str] | None:
    text = (repo / "setup.py").read_text(errors="replace")
    name = re.search(r"""\bname\s*=\s*['"]([^'"]+)['"]""", text)
    version = re.search(r"""\bversion\s*=\s*['"]([^'"]+)['"]""", text)
    return (name.group(1), version.group(1)) if name and version else None


def search_package_reports(
    name: str, version: str, key: str, fetch: Fetch
) -> tuple[Report, ...] | None:
    query = f'"{name}" "{version}" malicious OR compromised OR malware OR backdoor'
    data = fetch(_tavily_request(query, key))
    if data is None or not isinstance(data.get("results"), list):
        return None
    reports = []
    for item in data["results"]:
        if not isinstance(item, dict):
            continue
        title, url, content = (str(item.get(k) or "") for k in ("title", "url", "content"))
        if _reports_package(f"{title}. {content}".lower(), name, version):
            reports.append(Report(clean(title, 100), url[:300], clean(content, SNIPPET_CHARS)))
    return tuple(reports[:MAX_REPORTS])


def _reports_package(text: str, name: str, version: str) -> bool:
    """True when the page names this package *and this version* close to a word like malicious
    or compromised. Requiring the version keeps away the many pages about look-alike packages
    ("a malicious typosquat of requests") and about other, unaffected versions."""
    separators = r"[-_.]"  # PyPI treats these as the same in a name
    name_pattern = separators.join(re.escape(part) for part in re.split(separators, name.lower()))
    mention = re.compile(
        rf"(?<![\w.-]){name_pattern}(?![\w-])[^\n]{{0,{VERSION_GAP}}}?"
        rf"(?<![\w.]){re.escape(version.lower())}(?![\w]|\.\w)"
    )
    for match in mention.finditer(text):
        window = text[max(0, match.start() - NEAR_CHARS) : match.end() + NEAR_CHARS]
        if _PACKAGE_BAD_WORDS.search(window):
            return True
    return False
