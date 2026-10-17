#!/usr/bin/env python3
"""
zaenum.py -- enumerate hostnames for any zone from public passive sources,
and attribute each one to the CDN or edge serving it.

Works for .za second-level domains (co.za, org.za, ...) and for any other
TLD: a zone is just the name you ask about.

Sources (both public, no API key):
  ct  Certificate Transparency via crt.sh          (broad, TLS hosts only)
  cc  Common Crawl URL index                       (paginated, resumable)

Everything is written to disk per zone. Re-running resumes where the last
run stopped instead of re-fetching from the beginning.

Usage
  python3 zaenum.py                                 # interactive console
  python3 zaenum.py --sld all                       # every delegated .za SLD
  python3 zaenum.py --sld co.za --sources ct,cc
  python3 zaenum.py --sld example.com               # any TLD, not just .za
  python3 zaenum.py --sld law.za --cdn              # tag each host's CDN
  python3 zaenum.py --domains-file zones.txt --cdn
  python3 zaenum.py --sld school.za --resolve       # best-effort DNS check
  python3 zaenum.py --discover "south african universities"   # Exa web search

Output (default ./out)
  <zone>.hosts.txt     sorted unique hostnames, one per line
  <zone>.cdn.tsv       host, provider, evidence, IP (only with --cdn)
  all.hosts.txt        aggregate across every zone processed
  summary.json         per-zone counts, CDN tallies and source status
  .state.json          resume cursors -- delete to start over
  .cdn-ranges.json     cached CDN IP ranges (7 day TTL)
  <zone>.resolved.txt  host -> IPv4 pairs, only with --resolve

stdlib only, Python 3.8+, except --discover which needs exa-py
(requirements.txt) and an EXA_API_KEY.
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import sys
import time
import traceback
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

# Delegated .za second-level domains, per ZADNA's NIC.ZA registry listing.
SLD_INFO = {
    "co.za": "unrestricted, general use (largest)",
    "web.za": "unrestricted, general use",
    "org.za": "non-commercial organisations",
    "net.za": "network infrastructure operators",
    "ac.za": "higher education / research (TENET, moderated)",
    "edu.za": "accredited FET colleges (moderated)",
    "gov.za": "government entities (moderated)",
    "school.za": "schools (moderated)",
    "law.za": "attorneys and advocates (moderated)",
    "nom.za": "individuals, personal names (moderated)",
    "mil.za": "Department of Defence (closed)",
    "agric.za": "private delegation (ARC)",
    "nis.za": "private delegation",
    "grondar.za": "private delegation",
    "tm.za": "trademarks (dormant, no new registrations)",
    "ngo.za": "NGOs (dormant, no new registrations)",
    "alt.za": "historical registrants (dormant)",
}

# Two-label public suffixes outside .za, so a result for
# books.example.co.uk becomes example.co.uk rather than co.uk.
EXTRA_SLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "edu.au", "co.nz", "co.ke", "co.zw", "co.bw", "co.mz", "com.br",
    "com.ng", "co.jp", "com.cn",
}

USER_AGENT = "zaenum/1.0 (passive domain enumeration; set a contact before bulk runs)"
HOST_RE = re.compile(r"^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
CT_URL = "https://crt.sh/?q={query}&output=json&exclude=expired"
CC_COLLINFO = "https://index.commoncrawl.org/collinfo.json"
CC_INDEX = "https://index.commoncrawl.org/{cid}-index?url=*.{sld}&output=json"
RETRYABLE = {408, 425, 429, 500, 502, 503, 504}

# Public IP-range feeds, used to attribute a host to a CDN edge by address.
# Azure's list is a large rolling download and is intentionally omitted; header
# fingerprinting still catches Azure Front Door.
CDN_RANGE_SOURCES = {
    "Cloudflare": ("https://www.cloudflare.com/ips-v4", "text"),
    "Fastly": ("https://api.fastly.com/public-ip-list", "json-fastly"),
    "Amazon CloudFront": ("https://ip-ranges.amazonaws.com/ip-ranges.json", "json-aws"),
    "Google": ("https://www.gstatic.com/ipranges/goog.json", "json-google"),
}

# CNAME chains that give the provider away even when IP ranges are stale.
CDN_CNAME_PATTERNS = [
    ("cloudflare.net", "Cloudflare"),
    ("cloudflare.com", "Cloudflare"),
    ("fastly.net", "Fastly"),
    ("fastlylb.net", "Fastly"),
    ("akamaiedge.net", "Akamai"),
    ("edgekey.net", "Akamai"),
    ("akamaitechnologies.com", "Akamai"),
    ("cloudfront.net", "Amazon CloudFront"),
    ("azureedge.net", "Azure Front Door"),
    ("azurefd.net", "Azure Front Door"),
    ("trafficmanager.net", "Azure Traffic Manager"),
    ("edgecastcdn.net", "Edgecast"),
    ("stackpathdns.com", "StackPath"),
    ("netlify.app", "Netlify"),
    ("netlify.com", "Netlify"),
    ("vercel-dns.com", "Vercel"),
    ("vercel.app", "Vercel"),
    ("github.io", "GitHub Pages"),
    ("fly.dev", "Fly.io"),
    ("googlehosted.com", "Google"),
    ("sucuri.net", "Sucuri"),
    ("incapdns.net", "Imperva"),
]

# Response headers that identify an edge, checked in order.
CDN_HEADER_RULES = [
    ("cf-ray", "Cloudflare"),
    ("cf-cache-status", "Cloudflare"),
    ("x-amz-cf-id", "Amazon CloudFront"),
    ("x-amz-cf-pop", "Amazon CloudFront"),
    ("x-fastly-request-id", "Fastly"),
    ("fastly-debug-digest", "Fastly"),
    ("x-served-by", "Fastly"),
    ("x-akamai-transformed", "Akamai"),
    ("akamai-grn", "Akamai"),
    ("x-akamai-request-id", "Akamai"),
    ("x-azure-ref", "Azure Front Door"),
    ("x-msedge-ref", "Azure Front Door"),
    ("x-vercel-id", "Vercel"),
    ("x-vercel-cache", "Vercel"),
    ("x-nf-request-id", "Netlify"),
    # x-github-request-id means GitHub's own front end, not GitHub Pages;
    # the Pages CNAME (github.io) is matched separately below.
    ("x-github-request-id", "GitHub"),
    ("fly-request-id", "Fly.io"),
    ("x-sucuri-id", "Sucuri"),
]

# Fallbacks when only the Server / Via header or a generic CDN header is present.
CDN_SERVER_HINTS = [
    ("cloudflare", "Cloudflare"),
    ("cloudfront", "Amazon CloudFront"),
    ("akamai", "Akamai"),
    ("google frontend", "Google"),
    ("gws", "Google"),
    ("gse", "Google"),
    ("netlify", "Netlify"),
    ("vercel", "Vercel"),
    ("fly.io", "Fly.io"),
    ("sucuri", "Sucuri"),
    ("imperva", "Imperva"),
]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def http_get(url: str, timeout: int = 60, delay: float = 1.0, tries: int = 4):
    """Return (status, body). status is None only when every attempt failed.

    Callers must distinguish a real empty answer (200 with `[]`) from a
    transient failure, so nothing is ever marked complete on an error.
    """
    last = "unknown error"
    for attempt in range(1, tries + 1):
        req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json, */*"})
        wait = None
        try:
            with urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except HTTPError as exc:
            last = f"HTTP {exc.code}"
            if exc.code not in RETRYABLE:
                try:
                    body = exc.read()
                except Exception:
                    body = b""
                return exc.code, body
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            try:
                wait = float(retry_after) if retry_after else None
            except (TypeError, ValueError):
                wait = None
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            last = f"{type(exc).__name__}: {exc}"

        if attempt == tries:
            break
        wait = wait if wait is not None else min(60.0, delay * (2 ** attempt))
        wait *= 0.5 + random.random()
        log(f"  retry {attempt}/{tries - 1} in {wait:.1f}s ({last})")
        time.sleep(wait)

    log(f"  ! giving up after {tries} tries ({last}): {url}")
    return None, b""


def norm_host(raw: str):
    """Normalise one candidate name into a lowercase hostname, or None."""
    if not raw:
        return None
    host = raw.strip().lower().rstrip(".")
    host = host.replace("\x00", "")
    if "@" in host:            # CT sometimes returns rfc822 names
        host = host.split("@", 1)[1]
    while host.startswith("*.") or host.startswith("."):
        host = host[2:] if host.startswith("*.") else host[1:]
    if ":" in host:            # drop :port; bail on raw IPv6
        host = host.split(":", 1)[0]
    if not host or host.replace(".", "").isdigit():
        return None
    return host if HOST_RE.match(host) else None


def belongs(host, zone: str) -> bool:
    """`zone` is whatever was asked for: a .za SLD (co.za) or a plain domain."""
    return host == zone or host.endswith("." + zone)


def parse_names(value: str):
    """crt.sh packs multiple SANs into one string separated by newlines/commas."""
    for part in re.split(r"[\n,]", value or ""):
        host = norm_host(part)
        if host:
            yield host


# --------------------------------------------------------------------------- #
# CDN attribution
# --------------------------------------------------------------------------- #
def _cidr_entry(cidr, provider):
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None
    return (int(net.network_address), int(net.broadcast_address), provider)


def parse_ranges(provider: str, body: bytes, kind: str):
    entries = []
    if kind == "text":
        for token in body.decode("utf-8", "replace").split():
            entry = _cidr_entry(token, provider)
            if entry:
                entries.append(entry)
        return entries

    data = json.loads(body)
    if kind == "json-fastly":
        for cidr in data.get("addresses", []):
            entry = _cidr_entry(cidr, provider)
            if entry:
                entries.append(entry)
    elif kind == "json-aws":
        for prefix in data.get("prefixes", []):
            if prefix.get("service") == "CLOUDFRONT" and prefix.get("ip_prefix"):
                entry = _cidr_entry(prefix["ip_prefix"], provider)
                if entry:
                    entries.append(entry)
    elif kind == "json-google":
        for prefix in data.get("prefixes", []):
            if prefix.get("ipv4Prefix"):
                entry = _cidr_entry(prefix["ipv4Prefix"], provider)
                if entry:
                    entries.append(entry)
    return entries


class CdnRanges:
    """Sorted IPv4 blocks with binary-search lookup."""

    def __init__(self, entries):
        self.entries = sorted(entries)
        self.starts = [entry[0] for entry in self.entries]

    def __len__(self):
        return len(self.entries)

    def lookup(self, ip_int: int):
        index = bisect_right(self.starts, ip_int) - 1
        if index < 0:
            return None
        start, end, provider = self.entries[index]
        return provider if start <= ip_int <= end else None


def load_cdn_ranges(cache_path: str, args, max_age_days: int = 7) -> CdnRanges:
    entries = []
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as handle:
                cached = json.load(handle)
            if time.time() - cached.get("fetched", 0) < max_age_days * 86400:
                entries = [(int(s), int(e), p) for s, e, p in cached.get("entries", [])]
                if entries:
                    log(f"cdn: using cached ranges ({len(entries)} blocks)")
        except (OSError, ValueError, TypeError, KeyError):
            entries = []

    if not entries:
        for provider, (url, kind) in CDN_RANGE_SOURCES.items():
            status, body = http_get(url, timeout=args.timeout, delay=args.delay, tries=2)
            if status != 200 or not body:
                log(f"  cdn ranges: {provider} unavailable, skipping")
                continue
            try:
                found = parse_ranges(provider, body, kind)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                log(f"  cdn ranges: {provider} unparseable ({exc}), skipping")
                continue
            log(f"  cdn ranges: {provider} {len(found)} blocks")
            entries.extend(found)
        if entries:
            try:
                with open(cache_path, "w", encoding="utf-8") as handle:
                    json.dump({"fetched": time.time(),
                               "entries": [[s, e, p] for s, e, p in entries]}, handle)
            except OSError:
                pass

    return CdnRanges(entries)


def provider_from_headers(headers) -> tuple:
    """Pure header fingerprint: (provider or None, evidence)."""
    lowered = {str(k).lower(): str(v) for k, v in dict(headers).items()}

    for header, provider in CDN_HEADER_RULES:
        if header in lowered:
            return provider, f"header:{header}={lowered[header][:48]}"

    server = lowered.get("server", "").lower()
    for hint, provider in CDN_SERVER_HINTS:
        if hint in server:
            return provider, f"server:{server[:48]}"

    via = lowered.get("via", "").lower()
    for hint, provider in CDN_SERVER_HINTS:
        if hint in via:
            return provider, f"via:{via[:48]}"

    return None, ""


def provider_from_cname(chain: str) -> tuple:
    """Pure CNAME fingerprint: (provider or None, evidence)."""
    lowered = (chain or "").lower()
    for pattern, provider in CDN_CNAME_PATTERNS:
        if pattern in lowered:
            return provider, f"cname:{pattern}"
    return None, ""


def probe_headers(host: str, timeout: float = 8.0) -> tuple:
    """One HTTPS request, headers only. TLS verification is off on purpose:
    a misconfigured cert must not hide which edge is serving the host."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(host, timeout=timeout, context=context)
    try:
        conn.request("GET", "/", headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Range": "bytes=0-0",
        })
        response = conn.getresponse()
        headers = response.getheaders()
        response.read(1)
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None, ""
    finally:
        conn.close()
    return provider_from_headers(headers)


def classify_host(host: str, ranges: CdnRanges, timeout: float = 8.0):
    """Return (provider, evidence, ip_list). Ranges beat CNAMEs beat headers."""
    canonical, aliases, ips = "", [], []
    try:
        canonical, aliases, ips = socket.gethostbyname_ex(host)
    except (socket.gaierror, UnicodeError, OSError):
        return "unresolved", "dns:nxdomain", []

    for ip in ips:
        try:
            provider = ranges.lookup(int(ipaddress.ip_address(ip)))
        except ValueError:
            continue
        if provider:
            return provider, f"ip:{ip}", ips

    provider, evidence = provider_from_cname(" ".join([canonical] + list(aliases)))
    if provider:
        return provider, evidence, ips

    provider, evidence = probe_headers(host, timeout)
    if provider:
        return provider, evidence, ips

    return "origin", "no-cdn-signature", ips


def load_cdn_rows(path: str) -> dict:
    rows = {}
    if not os.path.exists(path):
        return rows
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2 and parts[0]:
                    rows[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else "",
                                      parts[3] if len(parts) > 3 else "")
    except OSError:
        return {}
    return rows


def write_cdn_rows(path: str, rows: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# host\tprovider\tevidence\tip\n")
        for host in sorted(rows):
            provider, evidence, ips = rows[host]
            handle.write(f"{host}\t{provider}\t{evidence}\t{ips}\n")


# --------------------------------------------------------------------------- #
# sources
# --------------------------------------------------------------------------- #
def ct_hosts(sld: str, state: dict, args) -> list:
    """Certificate Transparency search for *.<sld> via crt.sh."""
    st = state.setdefault("ct", {}).setdefault(sld, {})
    if st.get("complete"):
        log(f"  ct/{sld}: already complete, skipping")
        return []

    url = args.ct_url.format(query=quote("%." + sld, safe=""))
    log(f"  ct/{sld}: querying certificate transparency")
    status, body = http_get(url, timeout=args.timeout, delay=args.delay, tries=args.retries)
    if status is None:
        log(f"  ct/{sld}: source unreachable, leaving resumable")
        return []
    if status != 200:
        # crt.sh answers 502/404 while under load. Never treat that as "empty".
        log(f"  ct/{sld}: HTTP {status}, leaving resumable")
        return []

    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        log(f"  ct/{sld}: non-JSON response ({len(body)} bytes), not marking complete")
        return []

    if not isinstance(rows, list):
        log(f"  ct/{sld}: unexpected payload shape, not marking complete")
        return []

    found = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for field in ("name_value", "common_name"):
            for host in parse_names(str(row.get(field, ""))):
                if belongs(host, sld):
                    found.add(host)

    st["complete"] = True
    st["certificates"] = len(rows)
    log(f"  ct/{sld}: {len(rows)} certificates -> {len(found)} unique hosts")
    return sorted(found)


def cc_newest_collection(args):
    status, body = http_get(CC_COLLINFO, timeout=args.timeout, delay=args.delay,
                            tries=args.retries)
    if status != 200 or not body:
        return None
    try:
        colls = json.loads(body)
        return colls[0]["id"] if colls else None
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        return None


def cc_page_count(cid: str, sld: str, args):
    """Return (pages, saw_real_answer)."""
    url = CC_INDEX.format(cid=cid, sld=sld) + "&showNumPages=true"
    status, body = http_get(url, timeout=args.timeout, delay=args.delay, tries=args.retries)
    if status != 200:
        return 0, False
    if b"No Captures" in body:
        return 0, True
    try:
        return int(json.loads(body).get("pages", 0)), True
    except (json.JSONDecodeError, ValueError, AttributeError, TypeError):
        return 0, False


def cc_hosts(sld: str, state: dict, args, cid: str) -> list:
    """Paginated Common Crawl index walk; commits the cursor after every page."""
    st = state.setdefault("cc", {}).setdefault(sld, {})

    if st.get("collection") != cid:
        if st:
            log(f"  cc/{sld}: new crawl {cid}, restarting this SLD")
        st.clear()
        st.update({"collection": cid, "next_page": 0})
    if st.get("complete"):
        log(f"  cc/{sld}: already complete, skipping")
        return []

    pages, answered = cc_page_count(cid, sld, args)
    if pages <= 0:
        if answered:
            st["complete"] = True
            log(f"  cc/{sld}: crawl holds no pages for this SLD, marking complete")
        else:
            log(f"  cc/{sld}: index unreachable, leaving resumable")
        return []
    log(f"  cc/{sld}: {pages} index pages in {cid}, resuming at {st['next_page']}")

    found = set()
    while st["next_page"] < pages:
        page = st["next_page"]
        url = CC_INDEX.format(cid=cid, sld=sld) + f"&page={page}"
        status, body = http_get(url, timeout=args.timeout, delay=args.delay,
                                tries=args.retries)
        if status != 200:
            log(f"  cc/{sld}: page {page} failed (HTTP {status}), stopping here to resume later")
            return sorted(found)

        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            raw_url = record.get("url") if isinstance(record, dict) else None
            if not raw_url:
                continue
            host = norm_host(urlsplit(raw_url).hostname or "")
            if host and belongs(host, sld):
                found.add(host)

        st["next_page"] = page + 1
        if st["next_page"] >= pages:
            st["complete"] = True
        log(f"  cc/{sld}: page {page + 1}/{pages}, {len(found)} unique hosts so far")
        if args.delay:
            time.sleep(args.delay)

    return sorted(found)


# --------------------------------------------------------------------------- #
# persistence
# --------------------------------------------------------------------------- #
class Store:
    def __init__(self, outdir: str):
        self.dir = outdir
        os.makedirs(outdir, exist_ok=True)
        self.seen = {}

    def path(self, sld: str, suffix: str = "hosts.txt") -> str:
        return os.path.join(self.dir, f"{sld}.{suffix}")

    def load(self, sld: str) -> int:
        seen = set()
        path = self.path(sld)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    host = line.strip()
                    if host:
                        seen.add(host)
        self.seen[sld] = seen
        return len(seen)

    def add(self, sld: str, hosts) -> int:
        seen = self.seen.setdefault(sld, set())
        fresh, batch = [], set()
        for host in hosts:
            if host in seen or host in batch:
                continue
            batch.add(host)
            fresh.append(host)
        if fresh:
            with open(self.path(sld), "a", encoding="utf-8") as handle:
                for host in fresh:
                    handle.write(host + "\n")
            seen.update(fresh)
        return len(fresh)

    def finalize(self, sld: str) -> int:
        path = self.path(sld)
        seen = self.seen.get(sld, set())
        # Always materialise the file, even when empty, so downstream
        # scripts can rely on the path existing.
        with open(path, "w", encoding="utf-8") as handle:
            for host in sorted(seen):
                handle.write(host + "\n")
        return len(seen)

    def aggregate(self, slds) -> int:
        everything = set()
        for sld in slds:
            everything |= self.seen.get(sld, set())
        path = os.path.join(self.dir, "all.hosts.txt")
        with open(path, "w", encoding="utf-8") as handle:
            for host in sorted(everything):
                handle.write(host + "\n")
        return len(everything)


def load_state(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (json.JSONDecodeError, OSError):
            log("state file unreadable, starting fresh")
    return {}


def save_state(path: str, state: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
    os.replace(tmp, path)


# --------------------------------------------------------------------------- #
# optional DNS resolution
# --------------------------------------------------------------------------- #
def resolve_hosts(hosts, workers: int = 16):
    def one(host):
        try:
            info = socket.getaddrinfo(host, None, socket.AF_INET)
            return host, info[0][4][0] if info else ""
        except (socket.gaierror, UnicodeError, OSError):
            return host, ""

    resolved = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, ip in pool.map(one, hosts):
            if ip:
                resolved[host] = ip
    return resolved


# --------------------------------------------------------------------------- #
# web discovery (Exa)
# --------------------------------------------------------------------------- #
def zone_from_host(host: str):
    """Reduce a page host to the zone worth enumerating.

    news24.com/news/... is a page, not a zone: keep news24.com. Multi-label
    public suffixes are preserved, so www.unisa.ac.za gives unisa.ac.za and
    shop.example.co.uk gives example.co.uk.
    """
    if not host:
        return None
    host = host.lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    labels = host.split(".")
    if not HOST_RE.match(host) or len(labels) < 2:
        return None
    for sld in SLD_INFO:
        depth = sld.count(".") + 1
        if host.endswith("." + sld) and len(labels) > depth:
            return ".".join(labels[-(depth + 1):])
    if len(labels) > 2 and ".".join(labels[-2:]) in EXTRA_SLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def zones_from_results(results) -> list:
    """Zones from Exa result URLs, deduped in result order."""
    zones = []
    for result in results:
        host = (urlsplit(result.get("url") or "").hostname or "")
        zone = zone_from_host(host)
        if zone and zone not in zones:
            zones.append(zone)
    return zones


def slug(query: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", query.lower()).strip("-")[:60] or "query"


def print_results(query: str, results) -> None:
    """Render what Exa returned, source link first."""
    if not results:
        log(f"exa: no results for {query!r}")
        return
    print(f"Exa results for {query!r}:")
    for number, result in enumerate(results, 1):
        print(f"\n{number}. {result.get('title') or '(untitled)'}")
        print(f"   {result.get('url')}")
        meta = " | ".join(str(part) for part in
                          (result.get("published_date"), result.get("author")) if part)
        if meta:
            print(f"   {meta}")
        for highlight in (result.get("highlights") or [])[:2]:
            line = " ".join(highlight.split())
            print(f"   > {line[:300]}")


def discover(query: str, num_results: int, outdir: str) -> list:
    """Search the web with Exa and save the results under `outdir`.

    exa_search is imported here rather than at module level so every other
    flag still runs with the stdlib alone.
    """
    try:
        import exa_search
    except ImportError as exc:
        raise RuntimeError(
            "the Exa search needs exa-py -- run: pip install -r requirements.txt "
            f"({exc})") from exc

    results = exa_search.search(query, num_results)
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"exa-{slug(query)}.json")
    payload = {"query": query,
               "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "results": results}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    log(f"exa: {len(results)} results -> {path}")
    print_results(query, results)
    zones = zones_from_results(results)
    for zone in zones:
        log(f"exa: discovered zone {zone}")
    return zones


# --------------------------------------------------------------------------- #
# interactive menu
# --------------------------------------------------------------------------- #
__version__ = "1.1.0"

# Three-row block wordmark. Each glyph is a fixed width across its three rows,
# so the assembled rows line up without hand-counting characters.
GLYPHS = {
    "Z": ("█▀▀█", " ▄▀ ", "█▄▄█"),
    "A": ("▄▀▀▄", "█▄▄█", "█  █"),
    "E": ("█▀▀▀", "█▀▀ ", "█▄▄▄"),
    "N": ("█  █", "█▄ █", "█ ▀█"),
    "U": ("█  █", "█  █", "█▄▄█"),
    "M": ("█▄ ▄█", "█ ▀ █", "▀   ▀"),
}
WORDMARK = tuple(" ".join(GLYPHS[letter][row] for letter in "ZAENUM")
                 for row in range(3))

# Session defaults for the menu. Every one of these maps onto an existing flag,
# so a menu run and the equivalent command line do exactly the same work.
MENU_DEFAULTS = {"out": "out", "delay": 1.0, "timeout": 90, "retries": 5,
                 "max_hosts": 0, "cdn_workers": 8, "discover_results": 5}

MENU_ITEMS = (
    ("01", "enumerate .za SLD", "crt.sh + common crawl for one SLD"),
    ("02", "enumerate any domain", "same pipeline, any TLD"),
    ("03", "enumerate every .za SLD", "all delegated SLDs, resumable"),
    ("04", "CDN attribution only", "zone apex, no enumeration"),
    ("05", "full sweep", "enumerate then tag each host's edge"),
    ("06", "discover zones", "web search via Exa, needs EXA_API_KEY"),
    ("07", "resolve hostnames", "best-effort IPv4 for saved hosts"),
    ("08", "inspect last run", "counts and CDN tallies from disk"),
    ("09", "settings", "output dir, delay, timeout, workers"),
    ("10", "SLD reference", "delegated .za second-level domains"),
)

SETTING_ITEMS = (
    ("1", "out", "output directory"),
    ("2", "delay", "seconds between requests"),
    ("3", "timeout", "per-request timeout (s)"),
    ("4", "retries", "attempts per request"),
    ("5", "max_hosts", "cap per zone, 0 = none"),
    ("6", "cdn_workers", "concurrent CDN probes"),
    ("7", "discover_results", "Exa results to request"),
)


def supports_color(stream=None) -> bool:
    """Colour only for a real terminal that has not opted out."""
    stream = stream if stream is not None else sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def palette(stream=None) -> dict:
    """ANSI codes, or empty strings when colour is off, so callers stay branch-free."""
    codes = {"reset": "0", "bold": "1", "dim": "2", "green": "38;5;46",
             "dark": "38;5;28", "cyan": "38;5;51", "red": "38;5;203",
             "amber": "38;5;214", "grey": "38;5;244"}
    on = supports_color(stream)
    return {name: (f"\033[{code}m" if on else "") for name, code in codes.items()}


def coerce_setting(key: str, raw: str):
    """Turn one typed menu value into a validated setting, or raise ValueError."""
    if key not in MENU_DEFAULTS:
        raise ValueError(f"unknown setting {key!r}")
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("value cannot be empty")
    if key == "out":
        if raw in {".", ".."}:
            raise ValueError("pick a real directory name")
        return raw
    bounds = {"delay": (0.0, 600.0), "timeout": (1, 3600), "retries": (1, 50),
              "max_hosts": (0, 100_000_000), "cdn_workers": (1, 128),
              "discover_results": (1, 100)}
    low, high = bounds[key]
    try:
        value = float(raw) if key == "delay" else int(raw)
    except ValueError:
        raise ValueError(f"{key} needs a number, got {raw!r}") from None
    if not low <= value <= high:
        raise ValueError(f"{key} must be between {low} and {high}")
    return value


def menu_command(choice, target: str = "", settings=None):
    """Translate a menu selection into the argv main() already understands.

    Returns None for choices the menu handles in-process (inspect, settings,
    reference table, exit) so the caller never shells out to a half-built run.
    """
    cfg = dict(MENU_DEFAULTS)
    if settings:
        cfg.update(settings)
    choice = str(choice).strip()
    if choice in {"0", "8", "9", "10"}:
        return None
    if choice not in {"1", "2", "3", "4", "5", "6", "7"}:
        raise ValueError(f"unknown menu choice {choice!r}")

    base = ["--out", str(cfg["out"]), "--delay", str(cfg["delay"]),
            "--timeout", str(cfg["timeout"]), "--retries", str(cfg["retries"]),
            "--max-hosts", str(cfg["max_hosts"])]
    probes = ["--cdn-workers", str(cfg["cdn_workers"])]

    if choice == "3":
        return ["--sld", "all"] + base
    if choice == "6":
        query = (target or "").strip()
        if not query:
            raise ValueError("discover needs a search phrase")
        return ["--discover", query, "--discover-results",
                str(cfg["discover_results"])] + base

    zone = (target or "").strip().lower().lstrip(".").rstrip(".")
    if not zone:
        raise ValueError(f"option {choice} needs a zone")
    if not HOST_RE.match(zone):
        raise ValueError(f"not a valid zone: {target!r}")
    if choice in {"1", "2"}:
        return ["--sld", zone] + base
    if choice == "4":
        return ["--cdn-only", "--sld", zone] + base + probes
    if choice == "5":
        return ["--sld", zone, "--cdn"] + base + probes
    return ["--sld", zone, "--resolve"] + base


def _width() -> int:
    try:
        return max(56, min(78, os.get_terminal_size().columns - 2))
    except OSError:
        return 70


def print_banner(settings, p):
    width = max(len(line) for line in WORDMARK)
    print()
    print(f"  {p['dark']}┌{'─' * (width + 2)}┐{p['reset']}")
    for line in WORDMARK:
        print(f"  {p['dark']}│{p['reset']} {p['green']}{p['bold']}{line.ljust(width)}{p['reset']} "
              f"{p['dark']}│{p['reset']}")
    print(f"  {p['dark']}└{'─' * (width + 2)}┘{p['reset']}")
    stamp = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
    print(f"  {p['grey']}zone enumeration // edge attribution  v{__version__}{p['reset']}")
    print(f"  {p['grey']}{stamp}   out={settings['out']}   delay={settings['delay']}s"
          f"   timeout={settings['timeout']}s   retries={settings['retries']}{p['reset']}")


def print_menu(p):
    print()
    for key, label, note in MENU_ITEMS:
        print(f"  {p['green']}[{key}]{p['reset']} {p['bold']}{label:<26}{p['reset']}"
              f"{p['grey']}{note}{p['reset']}")
    print(f"  {p['red']}[00]{p['reset']} {p['bold']}{'exit':<26}{p['reset']}"
          f"{p['grey']}leave the console{p['reset']}")


def _ask(p, label: str, default: str = ""):
    """One line of input; returns None on EOF so callers can exit cleanly."""
    hint = f" [{default}]" if default not in ("", None) else ""
    try:
        raw = input(f"\n  {p['cyan']}zaenum ❯{p['reset']} {label}{hint}: ")
    except EOFError:
        return None
    raw = raw.strip()
    return raw or str(default)


def _pause(p):
    try:
        input(f"\n  {p['dark']}enter to return to console{p['reset']} ")
    except EOFError:
        return False
    return True


def _execute(argv, settings, p):
    print(f"\n  {p['dark']}{'-' * _width()}{p['reset']}")
    print(f"  {p['green']}target loadout{p['reset']} {p['grey']}zaenum {shlex_join(argv)}{p['reset']}")
    print(f"  {p['dark']}{'-' * _width()}{p['reset']}\n")
    try:
        code = main(list(argv))
    except KeyboardInterrupt:
        print(f"\n  {p['amber']}interrupted -- progress is saved, rerun to resume{p['reset']}")
        return 130
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception:
        print(f"\n  {p['red']}run failed:{p['reset']}")
        traceback.print_exc()
        return 1
    return code


def shlex_join(argv) -> str:
    """Readable one-line command echo, without importing shlex for one call site."""
    parts = []
    for item in argv:
        parts.append(f'"{item}"' if (not item or " " in item) else str(item))
    return " ".join(parts)


def menu_status(out_dir, p) -> bool:
    path = os.path.join(out_dir, "summary.json")
    if not os.path.exists(path):
        print(f"\n  {p['amber']}no summary.json in {out_dir!r} -- run a sweep first{p['reset']}")
        return False
    try:
        with open(path, "r", encoding="utf-8") as handle:
            summary = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"\n  {p['red']}cannot read {path}: {exc}{p['reset']}")
        return False

    zones = summary.get("slds") or {}
    print(f"\n  {p['bold']}last run{p['reset']} {p['grey']}{summary.get('generated', '?')}"
          f"   aggregate {summary.get('aggregate', 0)} hosts{p['reset']}")
    print(f"  {p['dark']}{'-' * _width()}{p['reset']}")
    print(f"  {'zone':<24}{'hosts':>8}  {'cdn':<28}")
    for zone in sorted(zones):
        info = zones[zone] or {}
        tallies = info.get("cdn") or {}
        top = ", ".join(f"{name} {count}" for name, count
                        in sorted(tallies.items(), key=lambda kv: (-kv[1], kv[0]))[:3])
        print(f"  {zone:<24}{info.get('total', 0):>8}  {top or '-'}")
    if not zones:
        print(f"  {p['grey']}no zones recorded yet{p['reset']}")
    return True


def menu_settings(settings, p) -> None:
    while True:
        print(f"\n  {p['bold']}settings{p['reset']}")
        for key, name, note in SETTING_ITEMS:
            print(f"  {p['green']}[{key}]{p['reset']} {name:<18}{settings[name]:<12}"
                  f"{p['grey']}{note}{p['reset']}")
        choice = _ask(p, "setting to change, 0 to go back", "0")
        if choice is None or choice == "0":
            return
        name = dict((key, name) for key, name, _ in SETTING_ITEMS).get(choice)
        if not name:
            print(f"  {p['red']}no setting {choice!r}{p['reset']}")
            continue
        raw = _ask(p, f"new {name}", str(settings[name]))
        if raw is None:
            return
        try:
            settings[name] = coerce_setting(name, raw)
        except ValueError as exc:
            print(f"  {p['red']}{exc}{p['reset']}")
            continue
        print(f"  {p['green']}{name} = {settings[name]}{p['reset']}")


def menu_table(p) -> None:
    width = max(len(sld) for sld in SLD_INFO)
    print()
    for sld, desc in SLD_INFO.items():
        print(f"  {p['green']}{sld:<{width}}{p['reset']}  {p['grey']}{desc}{p['reset']}")


def run_menu() -> int:
    settings = dict(MENU_DEFAULTS)
    p = palette()
    while True:
        print_banner(settings, p)
        print_menu(p)
        choice = _ask(p, "selection")
        if choice is None:
            print("\n  no interactive input -- run with -h for the flag interface")
            return 0
        choice = choice.lower()
        if not choice:
            continue
        if choice in {"0", "00", "q", "quit", "exit"}:
            print(f"\n  {p['dark']}session closed{p['reset']}\n")
            return 0
        if choice in {"8", "08"}:
            menu_status(settings["out"], p)
            if not _pause(p):
                return 0
            continue
        if choice in {"9", "09"}:
            menu_settings(settings, p)
            continue
        if choice in {"10", "010"}:
            menu_table(p)
            if not _pause(p):
                return 0
            continue

        if choice in {"1", "01"}:
            print(f"\n  {p['grey']}delegated .za SLDs: {', '.join(SLD_INFO)}{p['reset']}")
            target = _ask(p, "SLD", "co.za")
        elif choice in {"2", "02"}:
            target = _ask(p, "domain", "example.com")
        elif choice in {"3", "03"}:
            target = ""
        elif choice in {"4", "04", "5", "05", "7", "07"}:
            target = _ask(p, "zone", "example.com")
        elif choice in {"6", "06"}:
            target = _ask(p, "search phrase", "south african universities")
        else:
            print(f"  {p['red']}no option {choice!r}{p['reset']}")
            continue
        if target is None:
            return 0
        if choice in {"3", "03"}:
            confirm = _ask(p, "all 17 SLDs, this takes a while -- continue? (y/N)", "n")
            if confirm is None:
                return 0
            if confirm.lower() not in {"y", "yes"}:
                continue

        try:
            argv = menu_command(choice, target, settings)
        except ValueError as exc:
            print(f"  {p['red']}{exc}{p['reset']}")
            continue
        if argv is None:
            continue

        code = _execute(argv, settings, p)
        colour = "green" if code == 0 else "red"
        print(f"\n  {p[colour]}exit {code}{p['reset']} {p['grey']}-- artifacts in "
              f"{settings['out']}/{p['reset']}")
        if not _pause(p):
            return 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Enumerate hostnames for any zone (a .za SLD or any domain) from "
                    "public passive sources, and optionally attribute each host to its CDN.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="SLDs: " + ", ".join(SLD_INFO),
    )
    parser.add_argument("--sld", default="co.za",
                        help="a .za SLD or any domain, comma list, or 'all' (default: co.za)")
    parser.add_argument("--domains-file", default="",
                        help="file of zones, one per line (# comments allowed)")
    parser.add_argument("--sources", default="ct,cc",
                        help="comma list of ct,cc (default: ct,cc)")
    parser.add_argument("--out", default="out", help="output directory (default: out)")
    parser.add_argument("--max-hosts", type=int, default=0,
                        help="cap new hostnames kept per SLD (0 = no cap)")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="seconds between requests (default: 1.0)")
    parser.add_argument("--timeout", type=int, default=90, help="per-request timeout")
    parser.add_argument("--retries", type=int, default=5, help="attempts per request (default: 5)")
    parser.add_argument("--ct-url", default=CT_URL,
                        help="override the CT endpoint, keep a {query} placeholder")
    parser.add_argument("--cdn", action="store_true",
                        help="classify each host's CDN/edge by IP range, CNAME and headers")
    parser.add_argument("--cdn-only", action="store_true",
                        help="skip enumeration, just classify the zones themselves")
    parser.add_argument("--cdn-workers", type=int, default=8,
                        help="concurrent CDN probes (default: 8)")
    parser.add_argument("--cdn-timeout", type=float, default=8.0,
                        help="per-probe timeout in seconds (default: 8)")
    parser.add_argument("--resolve", action="store_true",
                        help="best-effort IPv4 lookup for collected hosts")
    parser.add_argument("--discover", default="",
                        help="search the web with Exa for this query, then enumerate "
                             "the zones its results live on (needs EXA_API_KEY)")
    parser.add_argument("--discover-results", type=int, default=5,
                        help="results to ask Exa for with --discover (default: 5)")
    parser.add_argument("--discover-only", action="store_true",
                        help="with --discover, list and save the results without enumerating")
    parser.add_argument("--list-slds", action="store_true", help="print the SLD table")
    parser.add_argument("--menu", action="store_true",
                        help="open the interactive console (the default with no flags)")
    parser.add_argument("--version", action="version", version=f"zaenum {__version__}",
                        help="print the version and exit")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # No flags, or an explicit --menu: the console is the front door. Every
    # action it offers is translated into the same argv a CLI run would use.
    if not argv or argv[0] == "--menu":
        return run_menu()
    args = parse_args(argv)

    if args.list_slds:
        width = max(len(sld) for sld in SLD_INFO)
        for sld, desc in SLD_INFO.items():
            print(f"{sld:<{width}}  {desc}")
        return 0

    # A "zone" is either a .za second-level domain (co.za) or any domain
    # (news24.com). The same fetch/dedupe logic serves both; only CC's
    # whole-SLD wildcard queries time out on the very large SLDs, which is
    # why per-domain zones are supported as well.
    if args.sld.strip().lower() == "all":
        slds = list(SLD_INFO)
    else:
        slds = []
        for token in args.sld.split(","):
            zone = token.strip().lower().lstrip(".").rstrip(".")
            if not zone:
                continue
            if not HOST_RE.match(zone):
                log(f"invalid zone '{zone}'")
                return 2
            if zone not in SLD_INFO and zone.count(".") == 1 and zone.endswith(".za"):
                log(f"note: '{zone}' is not a registered .za SLD, treating it as a plain zone")
            if zone not in slds:
                slds.append(zone)

    if args.domains_file:
        try:
            handle = sys.stdin if args.domains_file == "-" else open(
                args.domains_file, "r", encoding="utf-8")
            try:
                for line in handle:
                    zone = line.split("#", 1)[0].strip().lower().lstrip(".").rstrip(".")
                    if zone and HOST_RE.match(zone) and zone not in slds:
                        slds.append(zone)
            finally:
                if handle is not sys.stdin:
                    handle.close()
        except OSError as exc:
            log(f"cannot read --domains-file: {exc}")
            return 2

    if args.discover:
        try:
            found = discover(args.discover, args.discover_results, args.out)
        except Exception as exc:  # missing key, Exa refusal, no network
            log(f"exa: {exc}")
            return 1
        if not found and not args.discover_only:
            log("exa: no zones found in the results, nothing to enumerate")
            return 0
        for zone in found:
            if zone not in slds:
                slds.append(zone)
        if args.discover_only:
            return 0

    if not slds:
        log("no zones to process")
        return 2

    sources = [s.strip().lower() for s in args.sources.split(",") if s.strip()]
    unknown = set(sources) - {"ct", "cc"}
    if unknown or not sources:
        log(f"bad --sources {args.sources!r} -- use ct,cc")
        return 2

    store = Store(args.out)
    state_path = os.path.join(args.out, ".state.json")
    state = load_state(state_path)

    if args.cdn_only:
        args.cdn = True

    cid = None
    if "cc" in sources and not args.cdn_only:
        cid = cc_newest_collection(args)
        if not cid:
            log("common crawl collection list unavailable, skipping cc source")
            sources = [s for s in sources if s != "cc"]
        else:
            log(f"using common crawl collection {cid}")

    summary = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "common_crawl": cid, "slds": {}}

    for sld in slds:
        existing = store.load(sld)
        log(f"{sld}: {existing} hostnames already saved")

        collected = []
        if not args.cdn_only:
            if "ct" in sources:
                collected.extend(ct_hosts(sld, state, args))
            if "cc" in sources and cid:
                collected.extend(cc_hosts(sld, state, args, cid))

        if args.max_hosts > 0:
            unique = sorted(set(collected))
            collected = unique[:args.max_hosts]

        added = store.add(sld, collected)
        if args.cdn_only and not collected:
            total = len(store.seen.get(sld, set()))
            log(f"{sld}: cdn-only, enumeration skipped")
        else:
            total = store.finalize(sld)
            log(f"{sld}: +{added} new, {total} total -> {store.path(sld)}")
        save_state(state_path, state)
        summary["slds"][sld] = {"new": added, "total": total,
                                "ct": state.get("ct", {}).get(sld, {}),
                                "cc": state.get("cc", {}).get(sld, {})}

    if args.cdn:
        ranges = load_cdn_ranges(os.path.join(args.out, ".cdn-ranges.json"), args)
        if not len(ranges):
            log("cdn: no IP-range feeds reached, relying on CNAME and header signatures only")
        for zone in slds:
            # The zone apex is always classified, so "--cdn-only --sld example.com"
            # answers "what serves this domain?" without enumerating anything.
            hosts = sorted(set(store.seen.get(zone, set())) | {zone})
            path = store.path(zone, "cdn.tsv")
            rows = load_cdn_rows(path)
            todo = [host for host in hosts if host not in rows]
            log(f"cdn/{zone}: {len(hosts)} hosts, {len(rows)} already classified, {len(todo)} to probe")
            if not rows and not len(ranges):
                log(f"cdn/{zone}: no range data, results depend on headers alone")
            if todo:
                with ThreadPoolExecutor(max_workers=max(1, args.cdn_workers)) as pool:
                    results = pool.map(
                        lambda host: classify_host(host, ranges, args.cdn_timeout), todo)
                    for host, result in zip(todo, results):
                        rows[host] = (result[0], result[1], ",".join(result[2]))
                write_cdn_rows(path, rows)
            counts = {}
            for provider, _, _ in rows.values():
                counts[provider] = counts.get(provider, 0) + 1
            summary["slds"].setdefault(zone, {})["cdn"] = dict(sorted(counts.items()))
            top = ", ".join(f"{name} {count}" for name, count
                            in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:4])
            log(f"cdn/{zone}: {top} -> {path}")

    if args.cdn_only:
        summary["aggregate"] = 0
    else:
        aggregate = store.aggregate(slds)
        summary["aggregate"] = aggregate
        log(f"aggregate: {aggregate} hostnames -> {os.path.join(args.out, 'all.hosts.txt')}")

    if args.resolve:
        for sld in slds:
            hosts = sorted(store.seen.get(sld, set()))
            if not hosts:
                continue
            log(f"{sld}: resolving {len(hosts)} hostnames")
            resolved = resolve_hosts(hosts)
            path = store.path(sld, "resolved.txt")
            with open(path, "w", encoding="utf-8") as handle:
                for host in sorted(resolved):
                    handle.write(f"{host} {resolved[host]}\n")
            log(f"{sld}: {len(resolved)}/{len(hosts)} resolved -> {path}")
            summary["slds"][sld]["resolved"] = len(resolved)

    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
