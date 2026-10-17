#!/usr/bin/env python3
"""
exa_search.py -- web search for zaenum, backed by the Exa API.

The passive sources see only names that already exist in Certificate
Transparency or Common Crawl. `--discover` asks Exa a plain-language question
("south african universities", "shops hosted on cloudflare") and gets back the
pages that answer it; zaenum reduces each URL to a zone and enumerates it as
usual.

exa-py is needed only for --discover -- every other flag still runs on the
stdlib. The key is read from EXA_API_KEY, or from the gitignored .env beside
this file when the variable is unset, and is never printed or sent anywhere
except Exa's own API.

  pip install -r requirements.txt
  python3 zaenum.py --discover "south african universities"
"""

from __future__ import annotations

import os
import re

from exa_py import Exa

API_KEY_ENV = "EXA_API_KEY"
DEFAULT_RESULTS = 5
MAX_RESULTS = 100
STATUS_RE = re.compile(r"status code (\d{3})")


class ExaSearchError(RuntimeError):
    """A search that failed, worded so the CLI can show it as-is."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def load_env_file(path: str = None) -> None:
    """Fill EXA_API_KEY from a gitignored .env, without overriding the shell.

    Deliberately tiny: KEY=VALUE lines, # comments, optional quotes. Anything
    already exported stays authoritative.
    """
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.environ.get(API_KEY_ENV, "").strip() or not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.split("#", 1)[0].strip()
                if "=" not in line:
                    continue
                name, value = line.split("=", 1)
                if name.strip() == API_KEY_ENV:
                    os.environ[API_KEY_ENV] = value.strip().strip("'\"")
                    return
    except OSError:
        return


def api_key() -> str:
    load_env_file()
    key = os.environ.get(API_KEY_ENV, "").strip()
    if not key:
        raise ExaSearchError(
            f"{API_KEY_ENV} is not set -- put it in .env (see .env.example) "
            "or export it before running --discover"
        )
    return key


def client() -> Exa:
    """One Exa client, built on the server from the environment."""
    return Exa(api_key())


def describe_failure(status: int) -> str:
    if status == 401:
        return "Exa rejected the API key (401) -- check EXA_API_KEY"
    if status == 402:
        return "Exa credits are exhausted (402) -- top up on dashboard.exa.ai"
    if status == 429:
        return "Exa rate limit hit (429) -- retry in a moment"
    return f"Exa request failed with HTTP {status}"


def search(query: str, num_results: int = DEFAULT_RESULTS) -> list:
    """Run one Exa search; return plain dicts with the fields the CLI shows.

    Raises ExaSearchError for a missing key, an Exa refusal, or no network, so
    the caller can print a real error instead of an empty result list.
    """
    query = (query or "").strip()
    if not query:
        raise ExaSearchError("--discover needs a non-empty query")
    limit = max(1, min(int(num_results or DEFAULT_RESULTS), MAX_RESULTS))
    exa = client()
    try:
        response = exa.search(
            query,
            type="auto",
            num_results=limit,
            contents={"highlights": True},
        )
    except ValueError as exc:
        # exa-py's only documented failure: HTTP >= 400 as a ValueError.
        found = STATUS_RE.search(str(exc))
        status = int(found.group(1)) if found else 0
        raise ExaSearchError(describe_failure(status) if status
                             else f"Exa search failed: {exc}", status) from exc
    except Exception as exc:  # requests' network, DNS and timeout errors
        raise ExaSearchError(
            f"Exa unreachable: {type(exc).__name__}: {exc}") from exc

    results = []
    for item in response.results or []:
        results.append({
            "title": item.title,
            "url": item.url,
            "published_date": item.published_date,
            "author": item.author,
            "highlights": [h for h in (item.highlights or []) if h],
        })
    return results
