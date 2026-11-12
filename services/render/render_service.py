#!/usr/bin/env python3
"""duckfind render service: headless Chromium for the reader's JS fallback.

bespin's read.php asks for this only when a page's own HTML extracts to
(almost) no text. POST /render {"url": ..., "ua": "chrome"|"honest"} with the
relay's shared secret in X-Relay-Secret; the answer is the rendered DOM HTML.
See README.md in this directory for the API, limits and install steps.

Privacy: nothing here logs a URL. Log lines carry only a reason token and a
duration. No browser profile persists: the browser is started with
Playwright's launch() (a fresh temporary profile per browser process, deleted
when it closes -- never launch_persistent_context), TMPDIR points at a private
per-process temp dir, and every render gets a new BrowserContext that is
closed in `finally`, so no cookies, storage or cache carry from one render to
the next.

Address safety, layer 1 of 2: every request the page makes -- the main
document, each redirect hop (Chromium issues each hop as a new routed
request), every subresource -- is checked by ipcheck.check_url() against the
host's resolved addresses before it is allowed. Layer 2 (the guarantee) is the
kernel: nftables on kamino drops this service user's packets to private
ranges.
"""
import asyncio
import hmac
import json
import logging
import os
import shutil
import socket
import sys
import tempfile
import time
from urllib.parse import urljoin

from aiohttp import web
from playwright.async_api import async_playwright, Error as PWError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ipcheck  # noqa: E402

NAV_TIMEOUT_S = 10.0          # goto + settle budget
HARD_TIMEOUT_S = 12.0         # whole render task; past this the browser is restarted
SETTLE_IDLE_S = 2.0           # wait for network idle, at most this, inside the budget
MAX_REQUESTS = 150            # allowed requests per render
MAX_BODY_BYTES = 10 * 1024 * 1024   # summed response bodies (content-length)
MAX_DOM_BYTES = 3 * 1024 * 1024     # rendered HTML returned
RESTART_EVERY = 200           # renders per browser process
MAX_WAITING = 1               # one render running + this many queued, then 503
BLOCKED_TYPES = {"image", "media", "font", "stylesheet", "websocket", "eventsource",
                 "manifest", "other", "texttrack", "ping", "csp_report"}
# Blocked types we answer ourselves with an empty 200 instead of aborting
# (2026-11-12): sites like wowhead probe their CDN and swap the page for a
# "Static CDN Error" screen when stylesheets/images/fonts fail to load. A stub
# keeps them happy, and nothing is fetched upstream either way. Types not
# listed here (websocket, eventsource, ping, csp_report, other) are still
# aborted.
STUB_GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01"
            b"\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
STUB_RESPONSES = {
    "stylesheet": ("text/css", b""),
    "image": ("image/gif", STUB_GIF),
    "font": ("font/woff2", b""),
    "media": ("video/mp4", b""),
    "texttrack": ("text/vtt", b"WEBVTT\n"),
    "manifest": ("application/manifest+json", b"{}"),
}
UA_MODES = ("chrome", "honest")
RENDERER_KEY = web.AppKey("renderer", object)

log = logging.getLogger("duckfind-render")

# Test-only: lets the integration test serve its pages from 127.0.0.1 on a
# random port. Settable only by calling _enable_test_loopback() from the test
# harness -- deliberately NOT read from the environment or any config file,
# so production can never turn it on.
_TEST_ALLOW_LOOPBACK = False


def _enable_test_loopback():
    global _TEST_ALLOW_LOOPBACK
    _TEST_ALLOW_LOOPBACK = True


def _loopback_only(resolved):
    return bool(resolved) and all(a in ("127.0.0.1", "::1") for a in resolved)


async def resolve(host):
    """Addresses for host (an IP literal resolves to itself)."""
    lit = ipcheck.host_literal(host)
    if lit is not None:
        return [lit]
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return []
    return sorted({i[4][0] for i in infos})


async def check(url, cache):
    """(ok, reason) for one request URL; cache maps host -> resolved list."""
    parsed = ipcheck.parse_url(url)
    if parsed is None:
        return False, "scheme"
    host = parsed[1]
    if host not in cache:
        cache[host] = await resolve(host)
    resolved = cache[host]
    if _TEST_ALLOW_LOOPBACK and _loopback_only(resolved):
        return True, "ok"
    return ipcheck.check_url(url, resolved)


class Renderer:
    def __init__(self):
        self._pw = None
        self._browser = None
        self._renders = 0
        self._lock = asyncio.Lock()
        self._waiting = 0
        self._tmp = tempfile.mkdtemp(prefix="duckfind-render-")
        os.environ["TMPDIR"] = self._tmp      # Chromium's temp profile lands here

    async def start(self):
        self._pw = await async_playwright().start()

    async def stop(self):
        await self._close_browser()
        if self._pw is not None:
            await self._pw.stop()
        shutil.rmtree(self._tmp, ignore_errors=True)

    async def _close_browser(self):
        b, self._browser = self._browser, None
        if b is not None:
            try:
                await b.close()
            except PWError:
                pass

    async def _browser_ready(self):
        if self._browser is None or not self._browser.is_connected() or self._renders >= RESTART_EVERY:
            await self._close_browser()
            self._browser = await self._pw.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage", "--no-first-run", "--disable-background-networking",
                      "--disable-component-update", "--disable-sync", "--mute-audio"],
            )
            self._renders = 0
        return self._browser

    def ua(self, mode):
        ver = self._browser.version if self._browser else "120.0.0.0"
        base = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/%s Safari/537.36" % ver)
        return base + " DuckFind-render/1.0 (+http://duckfind.com/about.php)" if mode == "honest" else base

    @property
    def busy(self):
        return self._lock.locked() and self._waiting >= MAX_WAITING

    async def render(self, url, ua_mode="chrome"):
        """Returns (http_status, payload dict)."""
        if self.busy:
            return 503, {"status": "busy"}
        self._waiting += 1
        try:
            await self._lock.acquire()
        finally:
            self._waiting -= 1
        try:
            try:
                return await asyncio.wait_for(self._render_locked(url, ua_mode), HARD_TIMEOUT_S)
            except asyncio.TimeoutError:
                await self._close_browser()           # restart after a kill
                return 504, {"status": "timeout"}
            except PWError as e:
                # any other browser-side failure: a documented error, never a
                # bare 500. Log the exception type only (never the URL).
                log.warning("render error %s", type(e).__name__)
                return 502, {"status": "render_error"}
        finally:
            self._lock.release()

    async def _render_locked(self, url, ua_mode):
        t0 = time.monotonic()
        cache = {}
        ok, reason = await check(url, cache)
        if not ok:
            return 400, {"status": "blocked", "reason": reason}
        browser = await self._browser_ready()
        self._renders += 1
        st = {"requests": 0, "bytes": 0, "refused_doc": None}
        ctx = await browser.new_context(
            user_agent=self.ua(ua_mode), viewport={"width": 1024, "height": 768},
            service_workers="block", accept_downloads=False, java_script_enabled=True,
        )
        try:
            async def route(r):
                req = r.request
                if req.resource_type in BLOCKED_TYPES:
                    stub = STUB_RESPONSES.get(req.resource_type)
                    if stub:                # empty 200, nothing fetched upstream
                        return await r.fulfill(status=200, content_type=stub[0], body=stub[1])
                    return await r.abort("blockedbyclient")
                if st["requests"] >= MAX_REQUESTS or st["bytes"] > MAX_BODY_BYTES:
                    return await r.abort("blockedbyclient")
                # Only a refused MAIN-frame navigation fails the render. Iframes
                # (ads, trackers, embeds) pointing somewhere refused -- often
                # sinkholed to 0.0.0.0 by kamino's DNS filter -- are aborted
                # quietly and the page renders without them (2026-11-12, wowhead).
                nav = req.is_navigation_request() and main_frame(req)
                ok2, why = await check(req.url, cache)
                if not ok2:
                    if nav:
                        st["refused_doc"] = why
                    return await r.abort("blockedbyclient")
                st["requests"] += 1
                # Fetch it ourselves with redirects OFF. Chromium follows a 3xx
                # internally and route() never sees the follow-up request
                # (verified: a 302 to 192.168.x was followed unchecked), so the
                # Location target is checked here, before Chromium gets the 3xx;
                # handed back via fulfill(), the next hop is a new request that
                # comes through this route again.
                left = NAV_TIMEOUT_S - (time.monotonic() - t0)
                if left <= 0.2:
                    return await r.abort("timedout")
                try:
                    resp = await r.fetch(max_redirects=0, timeout=left * 1000)
                except PWError:
                    return await r.abort("failed")
                if 300 <= resp.status < 400:
                    loc = resp.headers.get("location", "")
                    target = urljoin(req.url, loc) if loc else ""
                    ok3, why3 = await check(target, cache) if target else (False, "scheme")
                    if not ok3:
                        if nav:
                            st["refused_doc"] = why3
                        return await r.abort("blockedbyclient")
                    return await r.fulfill(response=resp)
                try:
                    body = await resp.body()
                except PWError:
                    return await r.abort("failed")
                st["bytes"] += len(body)
                if st["bytes"] > MAX_BODY_BYTES:
                    return await r.abort("blockedbyclient")
                await r.fulfill(response=resp, body=body)

            await ctx.route("**/*", route)
            page = await ctx.new_page()
            ctx.on("page", lambda p: asyncio.ensure_future(p.close()))   # popups: closed
            page.on("dialog", lambda d: asyncio.ensure_future(d.dismiss()))
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_S * 1000)
            except PWError:
                if st["refused_doc"]:
                    return 400, {"status": "blocked", "reason": st["refused_doc"]}
                return 502, {"status": "fetch_failed"}
            if st["refused_doc"]:          # a later navigation (JS redirect) was refused
                return 400, {"status": "blocked", "reason": st["refused_doc"]}
            left = NAV_TIMEOUT_S - (time.monotonic() - t0)
            if left > 0.2:
                try:
                    await page.wait_for_load_state("networkidle", timeout=min(SETTLE_IDLE_S, left) * 1000)
                except PWError:
                    pass                    # still loading: take the DOM as it is
            html = await page_html(page, t0, st)
            if html is None:
                if st["refused_doc"]:      # the late navigation was to a refused target
                    return 400, {"status": "blocked", "reason": st["refused_doc"]}
                return 502, {"status": "unstable"}   # still navigating when the budget ran out
            final = page.url
            raw = html.encode("utf-8", "replace")
            truncated = len(raw) > MAX_DOM_BYTES
            if truncated:
                html = raw[:MAX_DOM_BYTES].decode("utf-8", "ignore")
            return 200, {"status": "ok", "final_url": final, "html": html, "truncated": truncated,
                         "ms": int((time.monotonic() - t0) * 1000)}
        finally:
            try:
                await ctx.close()
            except PWError:
                pass


def main_frame(req):
    """True if the request belongs to the page's top-level frame."""
    try:
        return req.frame.parent_frame is None
    except Exception:          # frame already detached: not the page itself
        return False


CONTENT_TRIES = 3


async def page_html(page, t0, st, tries=CONTENT_TRIES):
    """page.content(), tolerating a client-side navigation in flight.

    A page that redirects itself after DOMContentLoaded (location.replace and
    friends; www.reddit.com does) makes Playwright's content() raise "page is
    navigating and changing the content". Wait for the new document's
    DOMContentLoaded within what is left of the navigation budget and try
    again, up to `tries` times. None = no stable DOM in time; the caller
    returns an error status instead of an unhandled 500 (2026-11-12, first
    deployment on kamino). The new document's own requests go through the
    same route() checks, so a late navigation to a refused target is aborted
    and recorded in st["refused_doc"] like any other.
    """
    for _ in range(max(1, tries)):
        try:
            return await page.content()
        except PWError:
            left = NAV_TIMEOUT_S - (time.monotonic() - t0)
            if left <= 0.2 or st.get("refused_doc"):
                return None
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=min(3.0, left) * 1000)
            except PWError:
                pass
    return None


def make_app(secret, renderer=None):
    app = web.Application(client_max_size=64 * 1024)
    app[RENDERER_KEY] = renderer or Renderer()

    def authed(request):
        got = request.headers.get("X-Relay-Secret", "")
        return bool(secret) and hmac.compare_digest(got.encode(), secret.encode())

    async def h_render(request):
        if not authed(request):
            return web.json_response({"status": "forbidden"}, status=403)
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return web.json_response({"status": "bad_request"}, status=400)
        url = body.get("url") if isinstance(body, dict) else None
        mode = body.get("ua", "chrome") if isinstance(body, dict) else "chrome"
        if not isinstance(url, str) or mode not in UA_MODES:
            return web.json_response({"status": "bad_request"}, status=400)
        t0 = time.monotonic()
        status, payload = await request.app[RENDERER_KEY].render(url, mode)
        # privacy: reason token + duration only, never the URL
        log.info("render %s %s %dms", status, payload.get("reason") or payload.get("status"),
                 int((time.monotonic() - t0) * 1000))
        headers = {"Retry-After": "5"} if status == 503 else None
        return web.json_response(payload, status=status, headers=headers)

    async def h_health(request):
        if not authed(request):
            return web.json_response({"status": "forbidden"}, status=403)
        return web.json_response({"status": "ok"})

    async def on_startup(app_):
        await app_[RENDERER_KEY].start()

    async def on_cleanup(app_):
        await app_[RENDERER_KEY].stop()

    app.router.add_post("/render", h_render)
    app.router.add_get("/health", h_health)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    secret = os.environ.get("RELAY_SECRET", "")
    if not secret:
        print("RELAY_SECRET is not set", file=sys.stderr)
        sys.exit(2)
    try:
        extra = ipcheck.set_extra_blocked(os.environ.get("RENDER_EXTRA_BLOCKED", ""))
    except ValueError as e:
        print("RENDER_EXTRA_BLOCKED: bad entry: %s" % e, file=sys.stderr)
        sys.exit(2)
    if extra:
        logging.info("extra blocked networks: %d", len(extra))   # counts only, never the list
    bind = os.environ.get("BIND", "127.0.0.1:8091")
    host, _, port = bind.rpartition(":")
    web.run_app(make_app(secret), host=host or "127.0.0.1", port=int(port), access_log=None)


if __name__ == "__main__":
    main()
