#!/usr/bin/env python3
"""Check every watchlist target and record state changes in web/data/history.json.

Run by .github/workflows/collect.yml. Uses only Python's standard library.
Optional secrets (read from the environment):
  IPINFO_TOKEN       IPinfo Lite: ASN and country of the site's IP address
  ABUSEIPDB_API_KEY  AbuseIPDB: reputation of the site's IP address (check only)
  URLSCAN_API_KEY    urlscan.io: an evidence scan whenever a target changes state
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import http.client
import socket
from domains import registered_domain
import json
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 1
HOST = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
STATES = {
    "live": "Site is up and serving content",
    "cdn-warning": "Cloudflare is showing a phishing warning in front of the site",
    "suspended": "The response contains a suspension-page marker; operator action is not independently confirmed",
    "http-error": "The server answers, but with an error status",
    "unreachable": "The domain resolves, but nothing answers at that address",
    "no-address": "The domain exists, but has no IP address in DNS",
    "nxdomain": "The domain no longer resolves (NXDOMAIN)",
    "hold": "The registrar or registry put the domain on hold",
    "deleted": "Legacy RDAP-missing classification; not proof of deletion",
    "tls-error": "Certificate validation failed; the page was not fetched insecurely",
}
ACTORS = {state: None for state in STATES}
ACTORS['cdn-warning'] = 'Cloudflare warning (inferred)'
SUSPENSION_MARKERS = (
    "account has been suspended", "this account is suspended", "site has been suspended",
    "website has been suspended", "account suspended", "site suspended",
)
CLOUDFLARE_PHISH_MARKERS = ("suspected phishing", "phishing site")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------- watchlist

def normalize_target(raw: str) -> tuple[str, str]:
    """Return (url, host) for a bare domain or an http(s) URL."""
    raw = raw.strip()
    url = raw if "://" in raw else f"https://{raw}/"
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or parts.username or parts.password:
        raise ValueError("use a domain or an http(s) URL without credentials")
    host = (parts.hostname or "").rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid internationalized domain") from exc
    if not HOST.fullmatch(host):
        raise ValueError(f"not a valid domain name: {host or raw}")
    path = parts.path or "/"
    port = f":{parts.port}" if parts.port else ""
    clean = urllib.parse.urlunsplit((parts.scheme, host + port, path, parts.query, ""))
    return clean, host



def parse_watchlist(text: str) -> list[dict]:
    entries, seen, errors = [], set(), []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = [f.strip() for f in line.split("|")]
        if len(fields) > 3:
            errors.append(f"line {number}: expected at most 3 fields separated by |")
            continue
        fields += [""] * (3 - len(fields))
        raw, reported, note = fields
        try:
            url, host = normalize_target(raw)
        except ValueError as exc:
            errors.append(f"line {number}: {exc}")
            continue
        if reported:
            try:
                if not DATE.fullmatch(reported):
                    raise ValueError
                dt.date.fromisoformat(reported)
            except ValueError:
                errors.append(f"line {number}: reported date must be YYYY-MM-DD")
                continue
        key = raw if "://" in raw else host
        if key in seen:
            errors.append(f"line {number}: {key} is listed twice")
            continue
        seen.add(key)
        if not registered_domain(host):
            errors.append(f"line {number}: enter a registered domain, not a public suffix")
            continue
        entries.append({"target": key, "url": url, "host": host,
                        "domain": registered_domain(host),
                        "reported": reported or None, "note": note[:500] or None})
    if errors:
        raise ValueError("watchlist.txt has problems:\n  " + "\n  ".join(errors))
    return entries


# ---------------------------------------------------------------- network

def checked_url(url, https_only=False):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in (('https',) if https_only else ('http', 'https')) or not parts.hostname or parts.username or parts.password:
        raise ValueError('Only public HTTP(S) URLs without credentials are supported')
    if any(ord(c) < 32 for c in url): raise ValueError('URL contains control characters')
    host = parts.hostname.lower().rstrip('.')
    if host == 'localhost' or host.endswith(('.localhost', '.local', '.internal')):
        raise ValueError('Local targets are not supported')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not address.is_global: raise ValueError('Non-public target address is blocked')
    return parts


def public_addresses(host, port, resolve=socket.getaddrinfo):
    records = resolve(host, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise OSError('Target resolves to a non-public address; request blocked')
    return addresses


class Net:
    """Pin each connection to validated public DNS results; never bypass TLS validation."""
    def __init__(self, user_agent: str, timeout: float, max_body: int):
        self.user_agent, self.timeout, self.max_body = user_agent, timeout, max_body

    def request(self, method, url, headers=None, body=None, verify=True):
        if not verify: raise ValueError('TLS verification cannot be disabled')
        parts = checked_url(url)
        host = parts.hostname.encode('idna').decode('ascii')
        port = parts.port or (443 if parts.scheme == 'https' else 80)
        addresses = public_addresses(host, port)
        connection = http.client.HTTPConnection(host, port, timeout=self.timeout)
        connection.auto_open = 0
        stream = None
        for address in addresses:
            try:
                stream = socket.create_connection((address, port), timeout=self.timeout)
                break
            except OSError:
                if address == addresses[-1]: raise
        try:
            if parts.scheme == 'https':
                stream = ssl.create_default_context().wrap_socket(stream, server_hostname=host)
            connection.sock = stream
            headers = {'User-Agent': self.user_agent, **(headers or {})}
            data = json.dumps(body).encode() if body is not None else None
            if data is not None: headers.setdefault('Content-Type', 'application/json')
            path = urllib.parse.urlunsplit(('', '', parts.path or '/', parts.query, ''))
            connection.request(method, path, body=data, headers=headers)
            with connection.getresponse() as response:
                return response.status, dict(response.getheaders()), response.read(self.max_body)
        finally:
            connection.close()
            stream.close()

    def json(self, url, headers=None, method='GET', body=None):
        status, _, content = self.request(method, url, {'Accept': 'application/json', **(headers or {})}, body)
        try:
            return status, json.loads(content) if content else None
        except ValueError:
            return status, None


def check_dns(net, host: str) -> dict:
    result = {"status": None, "a": [], "aaaa": []}
    for kind, key in (("A", "a"), ("AAAA", "aaaa")):
        query = urllib.parse.urlencode({"name": host, "type": kind})
        status, data = net.json(f"https://cloudflare-dns.com/dns-query?{query}",
                                {"Accept": "application/dns-json"})
        if status != 200 or not isinstance(data, dict) or "Status" not in data:
            raise OSError(f"DNS-over-HTTPS lookup failed (HTTP {status})")
        code = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}.get(data["Status"], f"RCODE{data['Status']}")
        result["status"] = code if result["status"] in (None, "NOERROR") else result["status"]
        wanted = 1 if kind == "A" else 28
        result[key] = sorted({a["data"] for a in data.get("Answer", []) if a.get("type") == wanted})
    if result["status"] not in ("NOERROR", "NXDOMAIN"):
        raise OSError("DNS lookup returned " + result["status"] + "; no takedown inferred")
    return result


def _vcard(entity: dict, field: str):
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) == 2 and isinstance(card[1], list)):
        return None
    for item in card[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            value = item[3]
            return value[0] if isinstance(value, list) else value
    return None


def find_entities(entities, role: str):
    for entity in entities or []:
        if not isinstance(entity, dict):
            continue
        if role in entity.get("roles", []):
            yield entity
        yield from find_entities(entity.get("entities"), role)


def abuse_email(entities):
    for entity in find_entities(entities, "abuse"):
        email = _vcard(entity, "email")
        if email:
            return str(email).removeprefix("mailto:")
    return None


def parse_rdap(data: dict) -> dict:
    registrar = next(find_entities(data.get("entities"), "registrar"), {})
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if isinstance(e, dict)}
    return {
        "found": True,
        "statuses": sorted({str(s).lower() for s in data.get("status", [])}),
        "registrar": _vcard(registrar, "fn") if registrar else None,
        "registrar_abuse": abuse_email(registrar.get("entities")) if registrar else None,
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "nameservers": sorted({str(n.get("ldhName", "")).lower() for n in data.get("nameservers", [])
                               if isinstance(n, dict) and n.get("ldhName")}),
    }


def rdap_lookup(net, domain: str) -> dict:
    """rdap.org answers with a redirect to the registry's RDAP server; follow up to 3 hops."""
    url = f"https://rdap.org/domain/{domain}"
    for _ in range(4):
        checked_url(url, https_only=True)
        status, headers, content = net.request("GET", url, {"Accept": "application/rdap+json, application/json"})
        if status in (301, 302, 303, 307, 308):
            location = {k.lower(): v for k, v in headers.items()}.get("location")
            if not location:
                break
            url = urllib.parse.urljoin(url, location)
            continue
        if status == 404:
            return {"found": False}
        if status != 200:
            raise OSError(f"RDAP lookup failed (HTTP {status})")
        return parse_rdap(json.loads(content))
    raise OSError("RDAP lookup failed (too many redirects)")


def _title(html: str):
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200] if match else None


def check_http(net, url: str, max_redirects: int) -> dict:
    chain, tls_error = [], None
    current = url
    for _ in range(max_redirects + 1):
        try:
            checked_url(current)
            status, headers, content = net.request("GET", current, {"Accept": "text/html,*/*"})
        except (OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLCertVerificationError):
                tls_error = str(getattr(reason, "verify_message", None) or reason)[:200]
            return {"error": f"{type(reason).__name__}: {reason}"[:200], "chain": chain, "tls_error": tls_error}
        lower = {k.lower(): v for k, v in headers.items()}
        chain.append({"url": current, "status": status})
        if status in (301, 302, 303, 307, 308) and lower.get("location"):
            current = urllib.parse.urljoin(current, lower["location"])
            continue
        text = content.decode("utf-8", "replace")
        low = text.lower()
        cloudflare = "cf-ray" in lower or lower.get("server", "").lower() == "cloudflare"
        return {
            "status": status,
            "final_url": current,
            "server": lower.get("server", "")[:100] or None,
            "cloudflare": cloudflare,
            "cloudflare_warning": cloudflare and any(m in low for m in CLOUDFLARE_PHISH_MARKERS),
            "suspended": any(m in low for m in SUSPENSION_MARKERS),
            "title": _title(text),
            "chain": chain,
            "tls_error": tls_error,
        }
    return {"error": "too many redirects", "chain": chain, "tls_error": tls_error}


def check_network(net, ip: str, token: str | None) -> dict:
    result = {"ip": ip}
    if not token:
        return result
    status, data = net.json(f"https://api.ipinfo.io/lite/{ip}", {"Authorization": f"Bearer {token}"})
    if status == 200 and isinstance(data, dict):
        result.update({k: data.get(k) for k in ("asn", "as_name", "as_domain", "country_code")})
    return result


def check_reputation(net, ip: str, key: str | None, max_age: int) -> dict | None:
    if not key:
        return None
    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": max_age})
    status, data = net.json(f"https://api.abuseipdb.com/api/v2/check?{query}", {"Key": key})
    if status != 200 or not isinstance(data, dict) or not isinstance(data.get("data"), dict):
        return None
    d = data["data"]
    return {"score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"),
            "usage": d.get("usageType"), "isp": d.get("isp")}


def submit_scan(net, url: str, key: str | None, visibility: str) -> str | None:
    if not key:
        return None
    status, data = net.json("https://urlscan.io/api/v1/scan/", {"API-Key": key}, "POST",
                            {"url": url, "visibility": visibility})
    if status == 200 and isinstance(data, dict) and str(data.get("result", "")).startswith("https://urlscan.io/"):
        return data["result"]
    return None


# ---------------------------------------------------------------- classify

def classify(dns: dict, rdap: dict | None, http: dict | None) -> tuple[str, str | None]:
    statuses = set((rdap or {}).get("statuses", []))
    if "client hold" in statuses:
        return "hold", "registrar"
    if "server hold" in statuses:
        return "hold", "registry"
    if dns["status"] not in ("NOERROR", "NXDOMAIN"):
        raise ValueError("DNS failure is not a takedown observation")
    if dns["status"] == "NXDOMAIN":
        return "nxdomain", ACTORS["nxdomain"]
    if not dns["a"] and not dns["aaaa"]:
        return "no-address", ACTORS["no-address"]
    if http and http.get("tls_error"):
        return "tls-error", None
    if not http or http.get("error"):
        return "unreachable", ACTORS["unreachable"]
    if http.get("cloudflare_warning"):
        return "cdn-warning", ACTORS["cdn-warning"]
    if http.get("suspended"):
        return "suspended", ACTORS["suspended"]
    if http["status"] >= 400:
        return "http-error", ACTORS["http-error"]
    return "live", None


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def observe(net, entry: dict, config: dict, env: dict) -> dict:
    dns = check_dns(net, entry["host"])
    try:
        rdap = rdap_lookup(net, entry["domain"])
    except (OSError, ValueError) as exc:
        rdap = {"error": str(exc)[:200]}
    rdap_for_state = rdap if "error" not in rdap else None
    http = None
    if dns["status"] != "NXDOMAIN" and (dns["a"] or dns["aaaa"]):
        http = check_http(net, entry["url"], config["max_redirects"])
    state, actor = classify(dns, rdap_for_state, http)
    observation = {"classification_version": 2, "state": state, "actor": actor, "dns": dns, "rdap": rdap, "http": http}
    address = next((ip for ip in dns["a"] + dns["aaaa"] if is_public(ip)), None)
    if address:
        try:
            observation['network'] = check_network(net, address, env.get('IPINFO_TOKEN'))
            reputation = check_reputation(net, address, env.get('ABUSEIPDB_API_KEY'), config['abuseipdb_max_age_days'])
            if reputation: observation['reputation'] = reputation
        except (OSError, ValueError):
            observation['enrichment_error'] = 'Optional network or reputation lookup unavailable'
    return observation


# ---------------------------------------------------------------- history

def empty_history() -> dict:
    return {"schema": SCHEMA, "last_run": None, "targets": {}}


def validate_history(history: dict) -> None:
    if not isinstance(history, dict) or history.get("schema") != SCHEMA or not isinstance(history.get("targets"), dict):
        raise ValueError("history.json has an unexpected shape")
    for key, record in history["targets"].items():
        if not isinstance(record, dict) or record.get("target") != key:
            raise ValueError(f"history entry {key!r} is malformed")
        for change in record.get("changes", []):
            if change.get("state") not in STATES or not isinstance(change.get("at"), str):
                raise ValueError(f"history entry {key!r} has an invalid change")


def apply_observation(record: dict, observation: dict, now: str, limit: int) -> bool:
    """Store the observation; return True when the state changed."""
    record["last_checked"] = now
    record.pop("last_error", None)
    previous = record["changes"][-1] if record["changes"] else None
    changed = previous is None or previous["state"] != observation["state"] or previous.get("actor") != observation["actor"]
    if changed:
        record["changes"].append({"at": now, **observation})
        del record["changes"][:-limit]
    record["current"] = {"at": now, **observation}
    return changed


def run(root: Path, net, env: dict, now: str | None = None) -> dict:
    config = json.loads((root / "config.json").read_text(encoding="utf-8"))
    entries = parse_watchlist((root / config["watchlist"]).read_text(encoding="utf-8"))
    path = root / config["history"]
    history = json.loads(path.read_text(encoding="utf-8")) if path.exists() else empty_history()
    validate_history(history)
    now = now or utc_now()
    watched = {e["target"] for e in entries}
    summary = {"checked": 0, "failed": 0, "changed": []}
    for entry in entries:
        record = history["targets"].setdefault(entry["target"], {
            "target": entry["target"], "first_checked": now, "changes": []})
        record.update(url=entry["url"], reported=entry["reported"], note=entry["note"], watched=True)
        try:
            observation = observe(net, entry, config, env)
        except (OSError, ValueError) as exc:
            # A failed check never counts as a takedown; keep the last good state.
            record["last_error"] = {"at": now, "error": str(exc)[:200]}
            summary["failed"] += 1
            print(f"FAILED  {entry['target']}: {exc}", file=sys.stderr)
            continue
        summary["checked"] += 1
        if apply_observation(record, observation, now, config["max_changes_per_target"]):
            summary["changed"].append(entry["target"])
            if config.get("urlscan_on_change") and observation.get("http") and not observation["http"].get("error"):
                try:
                    scan = submit_scan(net, entry["url"], env.get("URLSCAN_API_KEY"), config["urlscan_visibility"])
                except (OSError, ValueError):
                    scan = None
                if scan:
                    record["changes"][-1]["scan"] = record["current"]["scan"] = scan
        print(f"{observation['state']:<12} {entry['target']}")
    for key, record in history["targets"].items():
        if key not in watched:
            record["watched"] = False  # kept so earlier captures stay readable
    if entries and summary["checked"] == 0:
        raise SystemExit("Every check failed; leaving history.json unchanged.")
    history["last_run"] = now
    history["last_run_summary"] = {"checked": summary["checked"], "failed": summary["failed"], "watched": len(entries)}
    if summary["failed"] == 0: history["last_success"] = now
    validate_history(history)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as handle:
        json.dump(history, handle, indent=1, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
    os.replace(handle.name, path)
    status_path = root / "web/data/status.json"
    status_path.write_text(json.dumps({"last_success": history.get("last_success"),
        "last_attempt": now, **history["last_run_summary"]}, indent=2) + "\n")
    return summary


def main():
    config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
    net = Net(config["user_agent"], config["http_timeout_seconds"], config["max_body_bytes"])
    summary = run(ROOT, net, dict(os.environ))
    print(f"Checked {summary['checked']}, failed {summary['failed']}, changed {len(summary['changed'])}")


if __name__ == "__main__":
    try:
        main()
    except ValueError as exc:
        raise SystemExit(str(exc))
