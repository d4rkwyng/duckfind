"""Integration test: the real service + real headless Chromium against a local
http.server. Needs Playwright's Chromium installed (python -m playwright
install chromium); skipped otherwise. Run on a dev machine or on kamino, not
in duckfind's PHP suite.

The test pages are served from 127.0.0.1, which production refuses, so the
harness calls render_service._enable_test_loopback() -- loopback ONLY;
192.168.x and every other private range stay refused, which is what the
redirect tests rely on.
"""
import asyncio
import http.server
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import render_service  # noqa: E402

pw = pytest.importorskip("playwright.async_api")

SECRET = "test-secret"
HITS = {}

PAGES = {
    "/js.html": (200, "text/html", b"""<!doctype html><html><head><title>JS page</title></head>
<body><div id="app"></div><script>
document.getElementById('app').innerHTML = '<article><h1>Built by script</h1><p>' +
  'This paragraph only exists after JavaScript runs. '.repeat(20) + '</p></article>';
</script></body></html>"""),
    "/assets.html": (200, "text/html", b"""<!doctype html><html><head>
<link rel="stylesheet" href="/style.css">
<style>@font-face { font-family: X; src: url(/font.woff); } body { font-family: X; }</style>
</head><body><p>Text with assets</p><img src="/pixel.png"><video src="/clip.mp4"></video>
<script src="/app.js"></script></body></html>"""),
    "/app.js": (200, "application/javascript", b"document.body.insertAdjacentHTML('beforeend','<p>script ran</p>');"),
    "/style.css": (200, "text/css", b"p{color:red}"),
    "/font.woff": (200, "font/woff", b"wOFF"),
    "/pixel.png": (200, "image/png", b"\x89PNG\r\n\x1a\n"),
    "/clip.mp4": (200, "video/mp4", b"\x00"),
    "/jsredir.html": (200, "text/html", b"""<!doctype html><html><body><p>moving</p>
<script>location.href = 'http://192.168.30.100/';</script></body></html>"""),
    "/xhr-private.html": (200, "text/html", b"""<!doctype html><html><body><p id=r>start</p><script>
fetch('http://192.168.1.1/admin').then(()=>{document.getElementById('r').textContent='LEAKED'})
  .catch(()=>{document.getElementById('r').textContent='fetch blocked'});
</script></body></html>"""),
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        HITS[path] = HITS.get(path, 0) + 1
        if path == "/redir-private":
            self.send_response(302)
            self.send_header("Location", "http://192.168.30.100/")
            self.end_headers()
            return
        if path == "/redir-ok":
            self.send_response(302)
            self.send_header("Location", "/js.html")
            self.end_headers()
            return
        status, ctype, body = PAGES.get(path, (404, "text/plain", b"nope"))
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
async def client(aiohttp_client):
    render_service._enable_test_loopback()
    app = render_service.make_app(SECRET)
    return await aiohttp_client(app)


async def post(client, url, secret=SECRET, ua="chrome"):
    r = await client.post("/render", json={"url": url, "ua": ua}, headers={"X-Relay-Secret": secret})
    return r.status, await r.json()


async def test_js_built_page_is_rendered(client, server):
    st, j = await post(client, server + "/js.html")
    assert st == 200 and j["status"] == "ok"
    assert "Built by script" in j["html"] and "only exists after JavaScript runs" in j["html"]
    assert j["final_url"].endswith("/js.html") and j["truncated"] is False


async def test_assets_blocked_scripts_run(client, server):
    for k in ("/pixel.png", "/font.woff", "/style.css", "/clip.mp4", "/app.js"):
        HITS.pop(k, None)
    st, j = await post(client, server + "/assets.html")
    assert st == 200 and "script ran" in j["html"]
    for k in ("/pixel.png", "/font.woff", "/style.css", "/clip.mp4"):
        assert HITS.get(k, 0) == 0, k + " was fetched"
    assert HITS.get("/app.js", 0) == 1


async def test_redirect_to_private_refused_at_the_hop(client, server):
    st, j = await post(client, server + "/redir-private")
    assert st == 400 and j == {"status": "blocked", "reason": "address"}


async def test_public_redirect_followed(client, server):
    st, j = await post(client, server + "/redir-ok")
    assert st == 200 and "Built by script" in j["html"]


async def test_js_navigation_to_private_refused(client, server):
    st, j = await post(client, server + "/jsredir.html")
    assert st == 400 and j["reason"] == "address"


async def test_subresource_fetch_to_private_refused(client, server):
    st, j = await post(client, server + "/xhr-private.html")
    # the script source contains both strings; check the element's text
    assert st == 200 and '<p id="r">fetch blocked</p>' in j["html"]


@pytest.mark.parametrize("url", ["data:text/html,<h1>hi</h1>", "file:///etc/passwd",
                                 "blob:http://127.0.0.1/abc", "javascript:alert(1)"])
async def test_non_http_navigation_refused(client, url):
    st, j = await post(client, url)
    assert st == 400 and j == {"status": "blocked", "reason": "scheme"}


async def test_private_literal_refused_before_browser(client):
    st, j = await post(client, "http://192.168.30.101/")
    assert st == 400 and j["reason"] == "address"


async def test_bad_secret_and_bad_body(client, server):
    st, j = await post(client, server + "/js.html", secret="wrong")
    assert st == 403
    r = await client.post("/render", data=b"not json", headers={"X-Relay-Secret": SECRET})
    assert r.status == 400
    st, j = await post(client, server + "/js.html", ua="sneaky")
    assert st == 400


async def test_ua_modes(client, server):
    st, j = await post(client, server + "/js.html", ua="honest")
    assert st == 200


async def test_busy_when_one_running_and_one_queued(client, server):
    results = await asyncio.gather(*(post(client, server + "/js.html") for _ in range(4)))
    codes = sorted(s for s, _ in results)
    assert codes.count(200) >= 2 and all(c in (200, 503) for c in codes)
    assert 503 in codes
