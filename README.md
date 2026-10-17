# zaenum

Enumerates hostnames for **any zone** — a `.za` second-level domain or a plain
domain on any TLD — from public passive sources, and attributes each host to the
CDN or edge that serves it. Resumable: kill it, re-run it, and it continues
rather than starting over.

| Source | What it gives | Weakness |
|---|---|---|
| `ct` — Certificate Transparency via crt.sh | anything serving TLS, including internal-ish names (mail, autodiscover, vpn) | 502s on very large zones; TLS hosts only |
| `cc` — Common Crawl URL index | hostnames seen in crawled URLs, with pagination | index 504s on whole-zone wildcards for big zones |

stdlib only, Python 3.8+ — except `--discover`, which needs `exa-py` from
`requirements.txt` and an Exa API key.

## Usage

```bash
python3 zaenum.py --list-slds                    # the 17 delegated .za SLDs
python3 zaenum.py --sld law.za                   # a .za SLD
python3 zaenum.py --sld example.com              # any other TLD, same code path
python3 zaenum.py --sld all                      # every .za SLD in sequence
python3 zaenum.py --domains-file zones.txt       # many zones, one per line
cat zones.txt | python3 zaenum.py --domains-file - --cdn

# CDN attribution
python3 zaenum.py --sld example.com --cdn-only   # "what serves this domain?"
python3 zaenum.py --sld mweb.co.za --cdn         # enumerate, then tag every host
```

### Web search for zones (Exa)

The two passive sources only see names that already exist. `--discover` asks
[Exa](https://exa.ai) a plain-language question and enumerates the zones the
answers live on:

```bash
pip install -r requirements.txt
export EXA_API_KEY=...                          # or put it in .env
python3 zaenum.py --discover "south african universities"
python3 zaenum.py --discover "shops hosted on cloudflare" --discover-results 10 --cdn
python3 zaenum.py --discover "south african law firms" --discover-only
```

Each result is printed with its title, source link, date/author and a couple of
query-relevant highlights, then saved to `out/exa-<query>.json`. The zone behind
every URL (`www.unisa.ac.za/news` → `unisa.ac.za`) joins the run's zone list, so
`--discover` composes with `--cdn`, `--resolve` and the usual output files.
`--discover-only` stops after printing and saving.

The key is read from `EXA_API_KEY` (or the gitignored `.env` beside the script)
on the machine running the CLI. It is never printed, logged or written to
`out/`, and this is a terminal tool — nothing is sent to a browser. A missing
key, a rejected key (401), exhausted credits (402) and rate limits (429) are
reported as such rather than as an empty result list.

Useful flags: `--delay` (seconds between requests, default 1.0), `--timeout`
(default 90), `--retries` (default 5), `--max-hosts` (cap per zone),
`--cdn-workers` (default 8), `--cdn-timeout` (default 8), `--out` (default `out`).

## Output

```
out/
  <zone>.hosts.txt      sorted unique hostnames, one per line
  <zone>.cdn.tsv        host, provider, evidence, IP   (--cdn)
  <zone>.resolved.txt   host -> IPv4                   (--resolve)
  all.hosts.txt         union across every zone in this run
  summary.json          counts, CDN tallies, per-source state
  .state.json           resume cursors (delete to start over)
  .cdn-ranges.json      cached CDN IP ranges, 7 day TTL
```

Every hostname is normalised (lowercased, `*.` stripped, ports and `rfc822`
addresses removed) and suffix-checked against its zone, so `evilnews24.com`
never lands in a `news24.com` list.

## CDN attribution

Three signals, strongest first:

1. **IP range** — resolves the host and looks the address up in published
   provider blocks: Cloudflare, Fastly, AWS CloudFront, Google. Feeds are
   cached for 7 days in `.cdn-ranges.json`.
2. **CNAME chain** — `gethostbyname_ex` exposes the canonical name, so
   `x.vercel-dns.com`, `d123.cloudfront.net`, `e1.akamaiedge.net` and friends
   identify the edge even when an IP block is stale.
3. **Response headers** — one HTTPS request, headers only: `cf-ray`,
   `x-amz-cf-id`, `x-fastly-request-id`, `x-akamai-*`, `x-azure-ref`,
   `x-vercel-*`, `x-nf-request-id`, `x-github-request-id`, plus `Server` and
   `Via` fallbacks.

`<zone>.cdn.tsv` records which signal produced the answer:

```
freebuff.com   Cloudflare   header:cf-ray=a4bd48a3af63e57a-SJC   216.24.57.1
example.com    Cloudflare   ip:104.20.23.154                    104.20.23.154
mweb.co.za     origin       no-cdn-signature                    102.65.21.239
```

`--cdn-only` classifies the zones themselves without enumerating anything,
which is the fast way to answer "is this domain behind Cloudflare?" for a list.

Two caveats worth knowing:

- **Header beats the range feed for some Cloudflare customers.** Sites on
  Cloudflare for SaaS or certain partner products serve from addresses outside
  the published `ips-v4` list, so `cf-ray` is the only reliable signal for them.
- **TLS verification is deliberately disabled** during header probing. A broken
  certificate would otherwise hide which edge is in front of the host. This is
  a one-request fingerprint, not a security assessment — don't reuse the probe
  as evidence that a site is trustworthy.

Probing sends one HTTP request to every host in the list. Keep `--cdn-workers`
modest (default 8) and only run it against zones you're entitled to look at.

## Arbitrary TLDs

The zone is just a name: `--sld example.com` and `--sld all` take the same code
path. What differs is tractability, not support:

- **Per-zone works everywhere.** `example.com`, `mweb.co.za`, `some.org` — the
  CT and Common Crawl queries are the same shape.
- **Whole-TLD discovery does not exist.** There is no query for "every `.com`
  hostname" — a CT wildcard over a gTLD is unanswerable, which is why the `all`
  shortcut only covers `.za`'s 17 known SLDs (a closed list). For other TLDs you
  supply zones: `--domains-file` or stdin from your own list.

## Resume semantics

State commits after each completed unit — one crt.sh response or one Common
Crawl page — so an interrupted run loses at most a single page. CDN results are
appended to the TSV and re-read on the next run, so classification is also
incremental; a host is never probed twice.

The important distinction the code makes: **a transient error is never recorded
as "done"**. A 502, a 504, a timeout or an HTML maintenance page leaves the zone
resumable. Only a real answer does — a parsed JSON array for `ct` (including
`[]`), or `pages`/`No Captures` for `cc`. If a new Common Crawl collection
appears, that zone restarts, since the old cursor indexes different data.

## Limits worth knowing

- **Big zones are not tractable this way.** `crt.sh` returns 502 for `%.co.za`,
  and the Common Crawl index 504s on `url=*.org.za`. Both stay resumable, so
  nothing is silently lost, but you won't complete `co.za` with these two
  sources alone.
- **Per-domain zones work well** — `--sld somecompany.co.za` succeeds where
  `--sld co.za` fails.
- **For registry-scale coverage**, Rapid7 Open Data's forward-DNS datasets are
  the realistic route: stream a day's gzip and filter. Not implemented here
  because each file is multi-GB.
- **Politeness.** These are public endpoints run by volunteers and academia.
  Keep `--delay` at 1s or above, and put a real contact in `USER_AGENT` before
  any bulk run.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Offline, with a faked transport: host normalisation, CT error-vs-empty
semantics, CC pagination with a mid-walk failure and resume, new-collection
restart, store dedupe across runs, CDN range lookup, and the header/CNAME
fingerprint rules for each provider.
