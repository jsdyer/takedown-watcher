# Takedown Watcher

Tracks DNS, registration and HTTP changes for a configurable watchlist every
six hours. Published at `coolcode.ca/takedown-watcher/`. The supplied watchlist
contains **demonstration controls, not allegations of abuse**. Replace or extend
`watchlist.txt` with targets you actually want to monitor.

## Using the tool

<!-- coolcode:guide -->
Inspect each target's DNS, registration and HTTP evidence and timeline. Ordinary HTTP errors, missing DNS answers, TLS failures and a missing RDAP record do not prove a takedown or identify who acted. Registry hold statuses identify a registrar/registry role but not its reason. “First indicator after report” appears only after an observed live state and a later hold, suspension message or CDN warning; it is an approximate observation interval, not a confirmed response time. Failed DNS checks retain the previous observation and show the error.
<!-- /coolcode:guide -->

**Check a domain now** queries Cloudflare DNS and RDAP in your browser. It does
not fetch the suspect page. The scheduled collector also fetches HTTP evidence,
validates certificates, checks public addresses on each redirect, and never
falls back to insecure TLS. Optional enrichment failure does not erase the
underlying DNS/HTTP observation.

| State | Observable evidence | Attribution |
| --- | --- | --- |
| Live | HTTP response below 400 | Does not establish safe or legitimate content |
| CDN warning | Warning text and Cloudflare response markers | Inferred warning; not confirmed action |
| Suspended | Suspension text in returned content | Could be self-authored; actor unconfirmed |
| HTTP error / Unreachable / TLS error | Response error, failed connection or certificate failure | Unconfirmed |
| No address / NXDOMAIN | Resolver has no address or says name absent | Unconfirmed |
| On hold | RDAP `client hold` / `server hold` | Registrar / registry role; reason unknown |

A missing RDAP record alone does not mean a domain was deleted. Historical
observations were reclassified using these rules without changing their dates.

## Setup

1. **Settings → Secrets and variables → Actions → New repository secret.** All
   three are optional; the collector skips any that are missing.

   | Secret | Used for |
   | --- | --- |
   | `IPINFO_TOKEN` | ASN, network name and country of the site's IP (IPinfo Lite) |
   | `ABUSEIPDB_API_KEY` | Reputation score of the site's IP. The collector only *checks*; it never files reports |
   | `URLSCAN_API_KEY` | Optional scan only when `urlscan_on_change` is explicitly enabled (off by default) |

2. **Settings → Actions → General → Workflow permissions → Read and write.**
   The collector commits `web/data/history.json` and then starts the Pages
   workflow.
3. **Settings → Pages → Source → GitHub Actions.**
4. Run **Actions → Takedown watcher · Collect → Run workflow** once for the first
   capture.

Keyless sources: Cloudflare DNS-over-HTTPS (`cloudflare-dns.com`) and RDAP via
`rdap.org`, which redirects to the registry's server.

## Expand or customize

**Add or remove a domain:** edit `watchlist.txt`. One entry per line:

```
target | reported | note
phish.example | 2026-11-20 | reported to host and registrar, case 12345
https://shop.example.net/checkout | 2026-11-21 |
```

`target` is a bare domain (checked as `https://domain/`) or a full URL.
`reported` (YYYY-MM-DD, UTC) is optional and permits the approximate indicator interval after a prior live observation. There is no
limit on the number of entries. **This repository is public: anything in the
watchlist is visible to everyone.**

A watchlist change needs only a normal commit; the next scheduled run picks it
up. To check immediately, run **Takedown watcher · Collect** from the Actions tab.
When it records a change it commits the history and starts
**Browser tool · Check and publish**, which redeploys the page.

Removing a domain keeps its history. It is marked *removed* and appears when you
tick "Include domains no longer on the watchlist".

**Tune the checks:** `config.json` holds the user agent, HTTP timeout, body size
read, redirect limit, how many changes to keep per target, and whether to submit
urlscan scans on change (`urlscan_on_change`, `urlscan_visibility`). Scans are off
by default. Enabling them submits target URLs to urlscan.io; unlisted results
are not private and may be accessible to urlscan customers. Do not include
credentials, personal data or secret URL tokens in a public watchlist.

**Schedule:** `.github/workflows/collect.yml` runs at minute 23 every six hours
(`23 */6 * * *`). GitHub can delay or skip scheduled runs and disables schedules
in public repositories after 60 days without activity;
`.github/workflows/schedule-guard.yml` re-enables it weekly. Also register
`collect.yml` with the independent Linux scheduler via `workflow_dispatch`, with
a six-hour cadence. `web/data/status.json` exposes `last_success` only when all
watched targets were checked; partial failures cannot make it appear fresh. Re-run
`python3 scripts/add_schedule_guard.py --repository jsdyer/takedown-watcher .github/workflows/collect.yml`
if you rename the collector.

## Development

```sh
node --test tests/*.test.mjs
python3 -m unittest discover -s tests -v
python3 scripts/build.py
python3 -m http.server 8000 --directory dist
```

The collector tests use a fake network and never contact real services. To run
the collector locally against the real services:

```sh
IPINFO_TOKEN=... python3 scripts/collect.py
```

## Files

| Path | Purpose |
| --- | --- |
| `watchlist.txt` | Domains and URLs to watch |
| `config.json` | Collector limits and options |
| `scripts/collect.py` | Scheduled checks; writes `web/data/history.json` |
| `web/data/history.json` | Every recorded state change, published with the page |
| `web/` | Page, styles, DOM code (`app.mjs`) and pure logic (`model.mjs`) |
| `.github/workflows/collect.yml` | Six-hourly collection, commit and publish |
| `.github/workflows/pages.yml` | Test, build and deploy to Pages |
| `.github/workflows/schedule-guard.yml` | Keeps the schedule enabled |
| `tool.json` | Catalogue record for coolcode.ca |

## Collection maintenance

The catalogue, imported README guide, repository audit, sitemap, Cloudflare
visitor registry and Linux refresh watchdog are managed in
[jsdyer/jsdyer.github.io](https://github.com/jsdyer/jsdyer.github.io).
Follow its [tool lifecycle checklist](https://github.com/jsdyer/jsdyer.github.io/blob/main/docs/tool-lifecycle.md)
when changing this tool's identity, source, deployment, inputs or refresh schedule.
The independent scheduler must actually be installed on the Linux server; a
GitHub schedule guard alone cannot guarantee refreshes continue.

Registration boundaries use the vendored ICANN section of the Public Suffix
List (including wildcard and exception rules). Private hosting suffixes are
excluded because RDAP queries the registrable parent, not a service tenant.
To update: `python3 scripts/update_suffixes.py`, run the tests, review and commit
`web/vendor/public-suffixes.json`. See `web/vendor/README.md` for provenance.

Collection saves `web/data/history.json` and `web/data/status.json` together before rebasing and publishing. Collector or collection-workflow changes also trigger a collection run; failed acquisitions retain the previous successful timestamp.
