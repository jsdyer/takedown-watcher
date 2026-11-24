import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import collect  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def doh(status=0, a=(), aaaa=()):
    answers = [{"type": 1, "data": ip} for ip in a] + [{"type": 28, "data": ip} for ip in aaaa]
    return {"Status": status, "Answer": answers}


def rdap(statuses=("active",), registrar="Example Registrar, Inc.", abuse="abuse@registrar.example"):
    return {
        "status": list(statuses),
        "entities": [{"roles": ["registrar"],
                      "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", registrar]]],
                      "entities": [{"roles": ["abuse"],
                                    "vcardArray": ["vcard", [["email", {}, "text", abuse]]]}]}],
        "events": [{"eventAction": "registration", "eventDate": "2026-10-01T00:00:00Z"}],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}],
    }


class FakeNet:
    """Maps (method, url prefix) to (status, headers, body). Records calls."""

    def __init__(self):
        self.routes, self.calls = {}, []

    def add(self, prefix, status=200, body=None, headers=None, method="GET"):
        self.routes[(method, prefix)] = (status, headers or {}, body)

    def request(self, method, url, headers=None, body=None, verify=True):
        self.calls.append((method, url))
        for (m, prefix), (status, response_headers, response) in sorted(self.routes.items(), key=lambda r: -len(r[0][1])):
            if m == method and url.startswith(prefix):
                if isinstance(response, Exception):
                    raise response
                content = response if isinstance(response, bytes) else json.dumps(response).encode() if response is not None else b""
                return status, response_headers, content
        raise OSError(f"no route for {method} {url}")

    def json(self, url, headers=None, method="GET", body=None):
        status, _, content = self.request(method, url, headers, body)
        return status, json.loads(content) if content else None

    def site(self, host, a=("203.0.113.5",), page=b"<title>Tickets</title>ok", status=200, rdap_body=None, headers=None):
        self.add(f"https://cloudflare-dns.com/dns-query?name={host}&type=A", body=doh(0, a))
        self.add(f"https://cloudflare-dns.com/dns-query?name={host}&type=AAAA", body=doh(0))
        self.add(f"https://rdap.org/domain/{collect.registered_domain(host)}", body=rdap_body or rdap())
        self.add(f"https://{host}/", status=status, body=page, headers=headers)


class WatchlistTests(unittest.TestCase):
    def test_parses_domains_urls_dates_and_notes(self):
        entries = collect.parse_watchlist(
            "# comment\n\nExample.com |  | control\nhttps://shop.example.org/login?x=1 | 2026-11-20 | case 7\n")
        self.assertEqual([e["target"] for e in entries], ["example.com", "https://shop.example.org/login?x=1"])
        self.assertEqual(entries[0]["url"], "https://example.com/")
        self.assertEqual(entries[1]["domain"], "example.org")
        self.assertEqual(entries[1]["reported"], "2026-11-20")
        self.assertIsNone(entries[0]["reported"])

    def test_reports_every_bad_line(self):
        with self.assertRaises(ValueError) as caught:
            collect.parse_watchlist("not a domain\nexample.com | 2026-13-01\nexample.com\nexample.com\nftp://x.example\n")
        message = str(caught.exception)
        for line in ("line 1", "line 2", "line 4", "line 5"):
            self.assertIn(line, message)

    def test_accepts_more_entries_than_the_sample(self):
        text = "\n".join(f"site{i}.example | 2026-11-01" for i in range(40))
        self.assertEqual(len(collect.parse_watchlist(text)), 40)

    def test_sample_watchlist_is_valid(self):
        self.assertGreaterEqual(len(collect.parse_watchlist((ROOT / "watchlist.txt").read_text())), 1)

    def test_registered_domain(self):
        self.assertEqual(collect.registered_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(collect.registered_domain("www.example.ca"), "example.ca")


class ClassifyTests(unittest.TestCase):
    def dns(self, status="NOERROR", a=("203.0.113.5",)):
        return {"status": status, "a": list(a), "aaaa": []}

    def test_states_and_actors(self):
        live = {"status": 200}
        cases = [
            (self.dns(), {"found": False}, None, ("deleted", "registrar or registry")),
            (self.dns("NXDOMAIN", ()), {"found": True, "statuses": ["client hold"]}, None, ("hold", "registrar")),
            (self.dns(), {"found": True, "statuses": ["server hold"]}, live, ("hold", "registry")),
            (self.dns("NXDOMAIN", ()), {"found": True, "statuses": ["active"]}, None, ("nxdomain", "registrar or dns provider")),
            (self.dns(a=()), None, None, ("no-address", "dns provider")),
            (self.dns(), None, {"error": "timeout"}, ("unreachable", "host")),
            (self.dns(), None, {"status": 403, "cloudflare_warning": True}, ("cdn-warning", "cloudflare")),
            (self.dns(), None, {"status": 200, "suspended": True}, ("suspended", "host")),
            (self.dns(), None, {"status": 404}, ("http-error", "host")),
            (self.dns(), {"found": True, "statuses": ["active"]}, live, ("live", None)),
        ]
        for dns, rdap_data, http, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(collect.classify(dns, rdap_data, http), expected)


class RunTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        shutil.copyfile(ROOT / "config.json", self.root / "config.json")

    def write_watchlist(self, text):
        (self.root / "watchlist.txt").write_text(text)

    def history(self):
        return json.loads((self.root / "web/data/history.json").read_text())

    def test_records_changes_only_when_state_changes(self):
        self.write_watchlist("phish.example | 2026-11-20 | reported to host\n")
        net = FakeNet()
        net.site("phish.example")
        collect.run(self.root, net, {}, "2026-11-21T00:00:00Z")
        collect.run(self.root, net, {}, "2026-11-21T06:00:00Z")
        net.site("phish.example", page=b"<title>Suspended</title>This account has been suspended", status=200)
        collect.run(self.root, net, {}, "2026-11-21T12:00:00Z")
        record = self.history()["targets"]["phish.example"]
        self.assertEqual([c["state"] for c in record["changes"]], ["live", "suspended"])
        self.assertEqual(record["current"]["actor"], "host")
        self.assertEqual(record["last_checked"], "2026-11-21T12:00:00Z")
        self.assertEqual(record["current"]["rdap"]["registrar_abuse"], "abuse@registrar.example")
        self.assertEqual(record["current"]["rdap"]["nameservers"], ["ns1.example.net"])

    def test_failed_check_keeps_last_good_state(self):
        self.write_watchlist("a.example\nb.example\n")
        net = FakeNet()
        net.site("a.example")
        net.site("b.example")
        collect.run(self.root, net, {}, "2026-11-21T00:00:00Z")
        net.add("https://cloudflare-dns.com/dns-query?name=b.example&type=A", status=503, body={})
        collect.run(self.root, net, {}, "2026-11-21T06:00:00Z")
        record = self.history()["targets"]["b.example"]
        self.assertEqual(record["current"]["state"], "live")
        self.assertEqual(len(record["changes"]), 1)
        self.assertIn("last_error", record)

    def test_all_checks_failing_leaves_history_untouched(self):
        self.write_watchlist("a.example\n")
        net = FakeNet()
        net.site("a.example")
        collect.run(self.root, net, {}, "2026-11-21T00:00:00Z")
        before = (self.root / "web/data/history.json").read_bytes()
        with self.assertRaises(SystemExit):
            collect.run(self.root, FakeNet(), {}, "2026-11-21T06:00:00Z")
        self.assertEqual((self.root / "web/data/history.json").read_bytes(), before)

    def test_removed_targets_are_kept_but_unwatched(self):
        self.write_watchlist("a.example\nb.example\n")
        net = FakeNet()
        net.site("a.example")
        net.site("b.example")
        collect.run(self.root, net, {}, "2026-11-21T00:00:00Z")
        self.write_watchlist("a.example\n")
        collect.run(self.root, net, {}, "2026-11-22T00:00:00Z")
        targets = self.history()["targets"]
        self.assertTrue(targets["a.example"]["watched"])
        self.assertFalse(targets["b.example"]["watched"])

    def test_optional_keys_add_network_reputation_and_scan(self):
        self.write_watchlist("a.example\n")
        net = FakeNet()
        net.site("a.example", headers={"Server": "cloudflare", "CF-RAY": "abc-YVR"})
        net.add("https://api.ipinfo.io/lite/203.0.113.5", body={"asn": "AS13335", "as_name": "Cloudflare, Inc.", "country_code": "US"})
        net.add("https://api.abuseipdb.com/api/v2/check", body={"data": {"abuseConfidenceScore": 12, "totalReports": 3}})
        net.add("https://urlscan.io/api/v1/scan/", method="POST", body={"result": "https://urlscan.io/result/u-1/"})
        # 203.0.113.0/24 is documentation space and not global; use a public address instead.
        net.add("https://cloudflare-dns.com/dns-query?name=a.example&type=A", body=doh(0, ["104.16.1.1"]))
        net.add("https://api.ipinfo.io/lite/104.16.1.1", body={"asn": "AS13335", "as_name": "Cloudflare, Inc.", "country_code": "US"})
        env = {"IPINFO_TOKEN": "t", "ABUSEIPDB_API_KEY": "k", "URLSCAN_API_KEY": "u"}
        collect.run(self.root, net, env, "2026-11-21T00:00:00Z")
        current = self.history()["targets"]["a.example"]["current"]
        self.assertEqual(current["network"]["asn"], "AS13335")
        self.assertEqual(current["reputation"]["score"], 12)
        self.assertEqual(current["scan"], "https://urlscan.io/result/u-1/")
        self.assertTrue(current["http"]["cloudflare"])

    def test_without_keys_no_keyed_services_are_called(self):
        self.write_watchlist("a.example\n")
        net = FakeNet()
        net.site("a.example", a=("104.16.1.1",))
        collect.run(self.root, net, {}, "2026-11-21T00:00:00Z")
        hosts = {url.split("/")[2] for _, url in net.calls}
        self.assertFalse(hosts & {"api.ipinfo.io", "api.abuseipdb.com", "urlscan.io"})

    def test_follows_rdap_and_http_redirects(self):
        self.write_watchlist("a.example\n")
        net = FakeNet()
        net.site("a.example")
        net.add("https://rdap.org/domain/a.example", status=302, headers={"Location": "https://rdap.registry.example/domain/a.example"})
        net.add("https://rdap.registry.example/domain/a.example", body=rdap(["client hold"]))
        collect.run(self.root, net, {}, "2026-11-21T00:00:00Z")
        self.assertEqual(self.history()["targets"]["a.example"]["current"]["state"], "hold")


if __name__ == "__main__":
    unittest.main()
