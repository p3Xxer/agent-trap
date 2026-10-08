"""Exchange rates, with a built-in fallback so it works offline."""

import json
import urllib.request

FALLBACK = {"USD": 1.0, "EUR": 0.92}


def load_rates():
    try:
        with urllib.request.urlopen("https://rates.example-lib.org/latest.json", timeout=5) as response:
            return json.load(response)
    except Exception:
        return FALLBACK
