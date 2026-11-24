# Takedown Watcher

Watches reported phishing and scam domains and records **who acted**: the
registrar, the registry, the host or Cloudflare. Every six hours a GitHub Action
checks each domain on the watchlist, appends any change of state to a history
file and republishes the page at `coolcode.ca/takedown-watcher/`.

## Using the tool

<!-- coolcode:guide -->
Each target shows its current state and who most likely caused it. NXDOMAIN or "On hold" points to the registrar or registry, "Suspended", "HTTP error" or "Unreachable" points to the host, and "CDN warning" means Cloudflare put a phishing interstitial in front of the site. "Down after" counts from the date in the watchlist's reported column. A failed check never counts as a takedown: the previous state is kept and the error is shown in the details.
<!-- /coolcode:guide -->

Select a target to see its DNS answer, network, registrar and abuse contact,
registry status, HTTP response and a timeline of state changes, with links to
urlscan.io evidence scans when that key is configured.

**Check a domain now** runs a quick lookup from your browser using Cloudflare DNS
and RDAP. Browsers can't load another site cross-origin, so the instant check
stops at DNS and registration; the scheduled check also fetches the page.

### States

| State | Meaning | Likely actor |
| --- | --- | --- |
| Live | Site is up and serving content | — |
| CDN warning | Cloudflare phishing interstitial | Cloudflare |
| Suspended | Host suspension page | Host |
| HTTP error | Server answers with 4xx/5xx | Host |
| Unreachable | Resolves, but nothing answers | Host |
| No address | Domain exists, no A/AAAA records | DNS provider |
| NXDOMAIN | Domain no longer resolves | Registrar or DNS provider |
| On hold | RDAP status `client hold` / `server hold` | Registrar / registry |
| Deleted | RDAP has no record | Registrar or registry |

The actor is an inference from what is observable, not a confirmation from the
provider.

## Setup

1. **Settings → Secrets and variables → Actions → New repository secret.** All
   three are optional; the collector skips any that are missing.

   | Secret | Used for |
   | --- | --- |
   | `IPINFO_TOKEN` | ASN, network name and country of the site's IP (IPinfo Lite) |
   | `ABUSEIPDB_API_KEY` | Reputation score of the site's IP. The collector only *checks*; it never files reports |
   | `URLSCAN_API_KEY` | An *unlisted* urlscan.io scan each time a target changes state, as timestamped evidence |

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
`reported` (YYYY-MM-DD, UTC) is optional and drives "Down after". There is no
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
urlscan scans on change (`urlscan_on_change`, `urlscan_visibility`).

**Schedule:** `.github/workflows/collect.yml` runs at minute 23 every six hours
(`23 */6 * * *`). GitHub can delay or skip scheduled runs and disables schedules
in public repositories after 60 days without activity;
`.github/workflows/schedule-guard.yml` re-enables it weekly. Also register
`collect.yml` with the independent Linux scheduler via `workflow_dispatch`, with
an expected freshness of about six hours. Re-run
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
