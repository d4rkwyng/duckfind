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
import time
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
    "/late-replace.html": (200, "text/html", b"""<!doctype html><html><body><p>first document</p>
<script>window.addEventListener('load', function () { location.replace('/js.html'); });</script>
</body></html>"""),
    "/late-replace-private.html": (200, "text/html", b"""<!doctype html><html><body><p>first</p>
<script>window.addEventListener('load', function () { location.replace('http://192.168.30.100/'); });</script>
</body></html>"""),
    "/cdnprobe.html": (200, "text/html", b"""<!doctype html><html><head>
<link rel="stylesheet" href="/style.css" onload="window.cssok=1" onerror="window.cssok=0">
</head><body><p id=r>probing</p><img id=i src="/pixel.png"><script>
window.addEventListener('load', function () {
  var img = document.getElementById('i');
  document.getElementById('r').textContent =
    (window.cssok === 1 && img.complete && img.naturalWidth > 0) ? 'CDN OK' : 'Static CDN Error';
});
</script></body></html>"""),
    "/iframes.html": (200, "text/html", b"""<!doctype html><html><body><article><h1>Main story</h1>
<p>The main document must render even when its iframes point at refused places.</p></article>
<iframe src="http://0.0.0.0/ad"></iframe><iframe src="http://192.168.30.100/admin"></iframe>
<script src="/slow.js"></script>
</body></html>"""),
    "/slow.js": (200, "application/javascript", b"/* served after a delay: holds DOMContentLoaded until the iframes have navigated */"),
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
        if path == "/slow.js":
            time.sleep(1.0)
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


async def test_navigation_after_load_is_followed_not_a_500(client, server):
    # reddit-shaped: the page replaces itself after load (2026-11-12, kamino).
    st, j = await post(client, server + "/late-replace.html")
    assert st == 200, (st, j)
    assert "Built by script" in j["html"] and j["final_url"].endswith("/js.html")


async def test_navigation_after_load_to_private_is_refused(client, server):
    st, j = await post(client, server + "/late-replace-private.html")
    # either refused as a blocked navigation, or the first DOM if the
    # replace was refused before content() ran -- never the private target, never a 500
    assert st in (200, 400), (st, j)
    if st == 200:
        assert "192.168.30.100" not in j["final_url"]
    else:
        assert j["status"] == "blocked"


class _FakePage:
    def __init__(self, fails):
        self.fails = fails
        self.waits = 0

    async def content(self):
        if self.fails > 0:
            self.fails -= 1
            raise render_service.PWError("Unable to retrieve content because the page is navigating")
        return "<html>stable</html>"

    async def wait_for_load_state(self, state, timeout):
        assert state == "domcontentloaded" and timeout > 0
        self.waits += 1


async def test_page_html_retries_while_navigating():
    import time as _t
    p = _FakePage(fails=2)
    assert await render_service.page_html(p, _t.monotonic(), {}) == "<html>stable</html>"
    assert p.waits == 2


async def test_page_html_gives_up_with_none():
    import time as _t
    p = _FakePage(fails=10)
    assert await render_service.page_html(p, _t.monotonic(), {}) is None
    assert p.waits == render_service.CONTENT_TRIES


async def test_page_html_stops_when_budget_spent():
    import time as _t
    p = _FakePage(fails=1)
    t0 = _t.monotonic() - render_service.NAV_TIMEOUT_S     # budget already used
    assert await render_service.page_html(p, t0, {}) is None
    assert p.waits == 0


async def test_blocked_assets_answered_with_stubs_so_cdn_probes_pass(client, server):
    # wowhead-shaped (2026-11-12): the page swaps itself for an error screen when
    # its stylesheet/image fail. Stubs make them "load" -- and nothing is fetched.
    for k in ("/style.css", "/pixel.png"):
        HITS.pop(k, None)
    st, j = await post(client, server + "/cdnprobe.html")
    assert st == 200, (st, j)
    # the probe's verdict is the text of <p id="r"> (the script source holds both strings)
    import re as _re
    m = _re.search(r'<p id="r">([^<]*)</p>', j["html"])
    assert m and m.group(1) == "CDN OK", m and m.group(1)
    assert HITS.get("/style.css", 0) == 0 and HITS.get("/pixel.png", 0) == 0


def test_stub_table_covers_cdn_types_only():
    assert set(render_service.STUB_RESPONSES) <= render_service.BLOCKED_TYPES
    for t in ("websocket", "eventsource", "ping", "csp_report", "other"):
        assert t not in render_service.STUB_RESPONSES
    assert render_service.STUB_RESPONSES["image"][1].startswith(b"GIF89a")


async def test_refused_iframes_do_not_fail_the_render(client, server):
    # wowhead-shaped (2026-11-12): ad iframes sinkholed to 0.0.0.0 by the DNS
    # filter, or pointing into the LAN, are aborted; the page itself renders.
    st, j = await post(client, server + "/iframes.html")
    assert st == 200, (st, j)
    assert "Main story" in j["html"] and "must render even" in j["html"]


async def test_main_frame_to_sinkholed_host_is_still_refused(client):
    st, j = await post(client, "http://0.0.0.0/")
    assert st == 400 and j["status"] == "blocked"
