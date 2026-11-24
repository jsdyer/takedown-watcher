"""Exercise the built page at a project subpath in Chromium, with sample data and mocked lookups."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]

HISTORY = {
    "schema": 1,
    "last_run": "2026-11-23T06:00:00Z",
    "targets": {
        "phish.example": {
            "target": "phish.example", "url": "https://phish.example/", "watched": True,
            "reported": "2026-11-20", "note": "<b>case 7</b>", "first_checked": "2026-11-19T00:00:00Z",
            "last_checked": "2026-11-23T06:00:00Z",
            "changes": [
                {"at": "2026-11-19T00:00:00Z", "state": "live", "actor": None},
                {"at": "2026-11-22T00:00:00Z", "state": "hold", "actor": "registrar",
                 "scan": "https://urlscan.io/result/u-1/"},
            ],
            "current": {"at": "2026-11-23T06:00:00Z", "state": "hold", "actor": "registrar",
                        "dns": {"status": "NXDOMAIN", "a": [], "aaaa": []},
                        "rdap": {"found": True, "statuses": ["client hold"], "registrar": "Reg Inc",
                                 "registrar_abuse": "abuse@reg.example"}},
        },
        "still-up.example": {
            "target": "still-up.example", "url": "https://still-up.example/", "watched": True,
            "reported": None, "note": None, "last_checked": "2026-11-23T06:00:00Z",
            "changes": [{"at": "2026-11-19T00:00:00Z", "state": "live", "actor": None}],
            "current": {"state": "live", "actor": None, "dns": {"status": "NOERROR", "a": ["192.0.2.1"], "aaaa": []}},
        },
        "old.example": {
            "target": "old.example", "watched": False, "changes": [], "current": {}, "last_checked": None,
        },
    },
}


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def fulfil_json(route, body, status=200):
    route.fulfill(status=status, content_type="application/json", body=json.dumps(body),
                  headers={"Access-Control-Allow-Origin": "*"})


def mock_lookups(route):
    url = route.request.url
    if "cloudflare-dns.com" in url:
        fulfil_json(route, {"Status": 0, "Answer": [{"type": 1, "data": "192.0.2.9"}] if "type=A&" in url + "&" else []})
    elif "rdap.org" in url:
        fulfil_json(route, {"status": ["active"], "entities": [{"roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "<img src=x onerror=alert(1)>"]]]}]})
    else:
        route.abort()


def main():
    screenshots = ROOT / "browser-checks"
    screenshots.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        site = Path(temporary) / "takedown-watcher"
        shutil.copytree(ROOT / "dist", site)
        (site / "data/history.json").write_text(json.dumps(HISTORY))
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=temporary))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with sync_playwright() as p:
                executable = os.environ.get("CHROMIUM_EXECUTABLE")
                browser = p.chromium.launch(executable_path=executable) if executable else p.chromium.launch()
                page = browser.new_page(viewport={"width": 1280, "height": 1000})
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.route("https://cloudflare-dns.com/**", mock_lookups)
                page.route("https://rdap.org/**", mock_lookups)
                page.goto(f"http://127.0.0.1:{server.server_port}/takedown-watcher/")
                page.wait_for_selector("#targets tbody tr")
                rows = page.locator("#targets tbody tr")
                assert rows.count() == 2, rows.count()
                assert "still-up.example" in rows.nth(0).inner_text()
                assert "On hold" in rows.nth(1).inner_text() and "2 days" in rows.nth(1).inner_text()
                page.locator("#show-removed").check()
                assert rows.count() == 3
                page.locator("button.link", has_text="phish.example").click()
                details = page.locator("#details").inner_text()
                assert "abuse@reg.example" in details and "<b>case 7</b>" in details
                assert page.locator("#details a[href='https://urlscan.io/result/u-1/']").count() == 1
                page.locator("#check-input").fill("https://Example.COM/login")
                page.locator("#check-form button").click()
                page.wait_for_selector("#check-result:not([hidden])")
                result = page.locator("#check-result").inner_text()
                assert "192.0.2.9" in result and "<img" in result, result
                assert page.locator("img").count() == 0
                page.screenshot(path=str(screenshots / "desktop.png"), full_page=True)
                page.set_viewport_size({"width": 390, "height": 844})
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                page.screenshot(path=str(screenshots / "mobile.png"), full_page=True)
                assert not errors, errors
                browser.close()
            print("Browser checks passed: project subpath, table, details, instant check, safe text and mobile layout")
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
