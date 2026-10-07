"""Model client (vendored from Spec Clash, logic unchanged). Every call goes to a real model.

Provider is chosen with LLM_PROVIDER (default: nebius). All providers speak the
OpenAI API, so only the address, key and model names differ.

Money safety (paid providers):
  * MAX_USD_PER_CHECK  stops one analysis from spending more than this.
  * TOTAL_BUDGET_USD   lifetime cap, remembered on disk in .agenttrap/spend.json,
                       so restarts don't reset it. Keep it under your credits.
  * Before every call we assume the worst case (the full max_tokens) and refuse
    if that could cross either cap.
  * Identical requests are answered from a disk cache (.agenttrap/cache/), so
    re-checking the same rule with the same roles costs nothing.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:  # load .env when python-dotenv is installed
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

# Cache, spend ledger and interception CA. Defaults to the project folder; set AGENTTRAP_STATE_DIR
# when the package is installed somewhere else (for example on a CI runner).
STATE_DIR = Path(
    os.environ.get("AGENTTRAP_STATE_DIR") or Path(__file__).resolve().parent.parent / ".agenttrap"
)
CACHE_DIR = STATE_DIR / "cache"
# Recorded runs: cache files copied here (and committed) so the demo examples replay a
# real earlier run exactly, even on a fresh server. Read-only.
RECORDED_DIR = STATE_DIR / "recorded"
LEDGER_FILE = STATE_DIR / "spend.json"

PROVIDERS = {
    "nebius": {
        "base_url": "https://api.tokenfactory.nebius.com/v1/",
        "key_env": "NEBIUS_API_KEY",
        "models": {
            "nano": "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B",
            "super": "nvidia/nemotron-3-super-120b-a12b",
            "ultra": "nvidia/Nemotron-3-Ultra-550b-a55b",
        },
        # USD per 1M tokens (input, output). Deliberately on the high side so the
        # brakes trip early rather than late. Check your Token Factory pricing page.
        "prices": {"nano": (0.10, 0.50), "super": (0.40, 1.20), "ultra": (1.50, 6.00)},
    },
    "nvidia": {  # build.nvidia.com free developer key
        "base_url": "https://integrate.api.nvidia.com/v1",
        "key_env": "NVIDIA_API_KEY",
        "models": {
            "nano": "nvidia/nemotron-3-nano-30b-a3b",
            "super": "nvidia/nemotron-3-super-120b-a12b",
            "ultra": "nvidia/nemotron-3-super-120b-a12b",
        },
        "prices": {"nano": (0, 0), "super": (0, 0), "ultra": (0, 0)},
    },
    "ollama": {  # a model running on your own computer
        "base_url": os.environ.get("OLLAMA_URL", "http://localhost:11434/v1"),
        "key_env": None,
        "models": {"nano": "nemotron-3-nano", "super": "nemotron-3-nano", "ultra": "nemotron-3-nano"},
        "prices": {"nano": (0, 0), "super": (0, 0), "ultra": (0, 0)},
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "key_env": "OPENROUTER_API_KEY",
        "models": {
            "nano": "nvidia/nemotron-3-nano-30b-a3b:free",
            "super": "nvidia/nemotron-3-super-120b-a12b:free",
            "ultra": "nvidia/nemotron-3-super-120b-a12b:free",
        },
        "prices": {"nano": (0, 0), "super": (0, 0), "ultra": (0, 0)},
    },
}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


class Settings:
    def __init__(self) -> None:
        self.provider = os.environ.get("LLM_PROVIDER", "nebius").strip().lower()
        if self.provider not in PROVIDERS:
            raise ValueError(f"LLM_PROVIDER must be one of: {', '.join(PROVIDERS)}")
        p = PROVIDERS[self.provider]
        self.base_url = p["base_url"]
        self.key_env = p["key_env"]
        self.models = {s: os.environ.get(f"MODEL_{s.upper()}", m) for s, m in p["models"].items()}
        self.prices = p["prices"]
        self.max_per_check = _env_float("MAX_USD_PER_CHECK", 0.50)
        self.total_budget = _env_float("TOTAL_BUDGET_USD", 20.0)
        self.thinking_off = os.environ.get("THINKING_OFF", "1") == "1"
        self.use_cache = os.environ.get("CACHE", "1") == "1"
        self.json_mode = os.environ.get("JSON_MODE", "1") == "1"
        # A fixed seed per job makes fresh runs far more repeatable on hosts that honour it.
        self.seed = os.environ.get("SEED", "1") == "1"
        self.seed_salt = os.environ.get("SEED_SALT", "")


SETTINGS = Settings()


class BudgetExceeded(RuntimeError):
    pass


class ModelError(RuntimeError):
    pass


def strip_thinking(text: Optional[str]) -> str:
    """Remove <think>...</think> blocks some reasoning models put in the reply."""
    if not text:
        return ""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    text = re.sub(r"^.*?</think>", "", text, flags=re.S)  # opening tag cut off
    return text.strip()


def cost(size: str, tokens_in: int, tokens_out: int) -> float:
    pin, pout = SETTINGS.prices[size]
    return (tokens_in * pin + tokens_out * pout) / 1_000_000


class Ledger:
    """Lifetime spend, shared by all requests and saved to disk."""

    def __init__(self, path: Path = LEDGER_FILE) -> None:
        self.path = path
        self.lock = threading.Lock()
        self.data = {"total_usd": 0.0, "calls": 0, "tokens_in": 0, "tokens_out": 0}
        if path.exists():
            try:
                self.data.update(json.loads(path.read_text()))
            except ValueError:
                pass

    @property
    def total(self) -> float:
        return self.data["total_usd"]

    def add(self, usd: float, tin: int, tout: int) -> None:
        with self.lock:
            self.data["total_usd"] += usd
            self.data["calls"] += 1
            self.data["tokens_in"] += tin
            self.data["tokens_out"] += tout
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=2))


LEDGER = Ledger()

_client = None
_client_lock = threading.Lock()


def _get_client():
    global _client
    with _client_lock:
        if _client is None:
            key = os.environ.get(SETTINGS.key_env) if SETTINGS.key_env else "local"
            if not key:
                raise ModelError(f"{SETTINGS.key_env} is not set. Put it in .env (never in code).")
            from openai import OpenAI

            _client = OpenAI(base_url=SETTINGS.base_url, api_key=key, max_retries=3, timeout=180)
        return _client


@dataclass
class Usage:
    calls: int = 0
    cached: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    by_role: dict = field(default_factory=dict)


def _drop_unsupported(kwargs: dict, err: Exception) -> bool:
    """If the host rejected an optional feature (HTTP 400), switch it off for good."""
    msg = str(err)
    if "400" not in msg:
        return False
    if "seed" in kwargs and "seed" in msg.lower():
        SETTINGS.seed = False
        kwargs.pop("seed")
        return True
    if "response_format" in kwargs and ("response_format" in msg or "json" in msg.lower()):
        SETTINGS.json_mode = False
        kwargs.pop("response_format")
        return True
    if "extra_body" in kwargs:
        SETTINGS.thinking_off = False
        kwargs.pop("extra_body")
        return True
    if "response_format" in kwargs:
        SETTINGS.json_mode = False
        kwargs.pop("response_format")
        return True
    return False


class LLM:
    """One instance per analysis, so per-check spending can be capped."""

    def __init__(self) -> None:
        self.usage = Usage()
        self.lock = threading.Lock()
        self.keys: list[str] = []  # cache keys this analysis used (for recording demo runs)

    def status(self) -> dict:
        return {
            "provider": SETTINGS.provider,
            "models": SETTINGS.models,
            "calls": self.usage.calls,
            "cached": self.usage.cached,
            "tokens_in": self.usage.tokens_in,
            "tokens_out": self.usage.tokens_out,
            "cost_usd": round(self.usage.cost_usd, 5),
            "total_spent_usd": round(LEDGER.total, 5),
            "total_budget_usd": SETTINGS.total_budget,
            "by_role": self.usage.by_role,
        }

    def chat(self, role: str, size: str, messages: list[dict], max_tokens: int = 1500,
             temperature: float = 0.2, json_mode: bool = False) -> str:
        """`role` names the job (e.g. 'parse', 'teammate:qa:2'). It is part of the
        cache key, so three runs of the same teammate stay three separate samples."""
        model = SETTINGS.models[size]
        key = hashlib.sha256(json.dumps(
            [SETTINGS.provider, model, role, messages, max_tokens, temperature, json_mode,
             SETTINGS.seed_salt], sort_keys=True
        ).encode()).hexdigest()
        cache_file = CACHE_DIR / f"{key}.json"
        with self.lock:
            self.keys.append(key)
        if SETTINGS.use_cache:
            for f in (cache_file, RECORDED_DIR / f"{key}.json"):
                if f.exists():
                    with self.lock:
                        self.usage.cached += 1
                    return json.loads(f.read_text())["text"]

        text = self._call(role, size, model, messages, max_tokens, temperature, json_mode)
        if SETTINGS.use_cache:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps({"role": role, "model": model, "text": text}))
        return text

    # ---------- internals ----------
    def _create(self, client, kwargs, model, role):
        for _ in range(3):
            try:
                return client.chat.completions.create(**kwargs)
            except Exception as err:
                if not _drop_unsupported(kwargs, err):
                    raise ModelError(f"{model} call failed ({role}): {err}") from err
        raise ModelError(f"{model} call failed ({role}) after dropping optional features")

    def _check_budget(self, size: str, messages: list[dict], max_tokens: int) -> None:
        est_in = sum(len(m["content"]) for m in messages) // 3 + 50  # ~3 chars per token, generous
        worst = cost(size, est_in, max_tokens)
        if self.usage.cost_usd + worst > SETTINGS.max_per_check:
            raise BudgetExceeded(
                f"This check would pass its ${SETTINGS.max_per_check:.2f} limit "
                f"(MAX_USD_PER_CHECK). Spent so far: ${self.usage.cost_usd:.4f}.")
        if LEDGER.total + worst > SETTINGS.total_budget:
            raise BudgetExceeded(
                f"Total spend would pass ${SETTINGS.total_budget:.2f} (TOTAL_BUDGET_USD). "
                f"Spent so far: ${LEDGER.total:.4f}.")

    def _call(self, role, size, model, messages, max_tokens, temperature, json_mode=False) -> str:
        client = _get_client()
        for attempt in range(2):  # second attempt only if the reply was cut off
            self._check_budget(size, messages, max_tokens)
            kwargs = dict(model=model, messages=messages, max_tokens=max_tokens, temperature=temperature)
            if SETTINGS.thinking_off:
                kwargs["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}
            if json_mode and SETTINGS.json_mode:
                kwargs["response_format"] = {"type": "json_object"}
            if SETTINGS.seed:
                digest = hashlib.sha256(f"{SETTINGS.seed_salt}:{role}".encode()).hexdigest()
                kwargs["seed"] = int(digest[:8], 16)
            started = time.time()
            resp = self._create(client, kwargs, model, role)
            tin = getattr(resp.usage, "prompt_tokens", 0) or 0 if resp.usage else 0
            tout = getattr(resp.usage, "completion_tokens", 0) or 0 if resp.usage else 0
            usd = cost(size, tin, tout)
            LEDGER.add(usd, tin, tout)
            with self.lock:
                u = self.usage
                u.calls += 1
                u.tokens_in += tin
                u.tokens_out += tout
                u.cost_usd += usd
                r = u.by_role.setdefault(role.split(":")[0], {"calls": 0, "cost_usd": 0.0, "seconds": 0.0})
                r["calls"] += 1
                r["cost_usd"] = round(r["cost_usd"] + usd, 6)
                r["seconds"] = round(r["seconds"] + time.time() - started, 2)

            choice = resp.choices[0]
            text = strip_thinking(choice.message.content)
            if text:
                return text
            if choice.finish_reason == "length" and attempt == 0:
                max_tokens *= 2  # the model spent its budget thinking; give it room once
                continue
            raise ModelError(f"{model} returned an empty reply for {role} "
                             f"(finish_reason={choice.finish_reason}).")
        raise ModelError(f"{model} returned an empty reply for {role}.")
