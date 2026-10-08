"""Settings read from the environment, with defaults."""

import os

CURRENCY = os.environ.get("INVOICE_CURRENCY", "USD")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")


def describe():
    return f"{CURRENCY} / {LOG_LEVEL}"
