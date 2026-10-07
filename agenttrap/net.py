"""Shared network settings."""

from __future__ import annotations

import ssl

import certifi

# python.org builds of Python on macOS ship without root certificates, so use certifi's bundle.
TLS = ssl.create_default_context(cafile=certifi.where())
