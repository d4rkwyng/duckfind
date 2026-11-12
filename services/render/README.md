# duckfind render service

This is headless Chromium for the reader's JavaScript fallback. bespin's `read.php` calls it only when a live page's own HTML extracts to almost no text (fewer than `render_min_text` characters), meaning the page is built by script. The service returns the rendered DOM HTML, and duckfind's existing extractor turns it into a vintage page.

It runs on **kamino** (VMID 1005, VLAN 30), next to `transcoder.service`. bespin reaches it through the relay hostname over the Cloudflare Tunnel, on the path `relay.duckfind.com/render`, as a separate process on its own port.

## API

`POST /render`, header `X-Relay-Secret: <relay_secret>` (the same secret as `/queue` and `/v`), body:

```json
{"url": "https://example.com/page", "ua": "chrome"}
```

`ua` is `chrome` (the default: Chromium's normal desktop UA, with "HeadlessChrome" never sent) or `honest` (the same UA plus `DuckFind-render/1.0 (+http://duckfind.com/about.php)`). duckfind sends whatever its `render_ua_mode` config says.

| Status | Body | Meaning |
|---|---|---|
| 200 | `{"status":"ok","final_url":"...","html":"...","truncated":false,"ms":2310}` | rendered |
| 400 | `{"status":"blocked","reason":"scheme"\|"port"\|"address"\|"resolve"}` | refused by the address policy (the initial URL, a redirect hop, or a script navigation) |
| 400 | `{"status":"bad_request"}` | not JSON, or no `url`, or an unknown `ua` |
| 403 | `{"status":"forbidden"}` | bad or missing secret |
| 502 | `{"status":"fetch_failed"}` | the page did not load |
| 503 + `Retry-After: 5` | `{"status":"busy"}` | one render running and one waiting |
| 504 | `{"status":"timeout"}` | past the 12 s hard limit (the browser is restarted) |

`GET /health` with the secret returns `{"status":"ok"}`.

## Limits

- **Time:** 10 s navigation budget (`domcontentloaded`, then up to 2 s waiting for network idle). The whole render is killed at 12 s and the browser restarted.
- **Resource types:**
  - Blocked: image, media, font, stylesheet, websocket, eventsource, manifest, texttrack, ping, csp_report, other.
  - Allowed: document, script, xhr, fetch.
- **Per render:** 150 allowed requests, 10 MB of response bodies, 3 MB of DOM returned (`truncated: true` past that). Downloads off, JS dialogs dismissed, popups closed, viewport 1024x768.
- **Concurrency:** one render at a time plus one waiting, then 503. The browser is restarted every 200 renders, and after any kill.

## Address safety

Two layers. **Both are required.**

1. **In the service** (`ipcheck.py`, wired in `render_service.py`). Every request the page makes goes through a Playwright route that checks it before anything is sent: the main document, each redirect hop, script-driven navigations, XHR/fetch and other subresources.
   - **Allowed:** http/https only, ports 80/443 only, and only if no resolved address falls in:
     - IPv4: 0/8, 10/8, 100.64/10 (Tailscale/CGNAT), 127/8, 169.254/16, 172.16/12, 192.0.0/24, the TEST-NETs, 192.168/16 (which includes the VLAN 30 peers), 198.18/15, multicast, 240/4
     - IPv6: loopback, ULA, link-local, multicast, documentation, NAT64, and v4-mapped, 6to4 or Teredo forms of any of the above
   - A host with one public and one private address is refused.
   - **Redirects:** the route fetches each request itself with redirects off (`route.fetch(max_redirects=0)`). It checks a 3xx's `Location` before handing the 3xx back to Chromium, and Chromium's next hop then comes through the route again. Without this, Chromium follows redirects internally and the route never sees the hop; the integration test caught exactly that, a 302 to 192.168.30.100 followed unchecked.
   - **Limit:** this layer has a DNS-rebinding race, because Chromium (or Playwright's fetch) resolves again after the check. It is a first filter only.
2. **In the kernel** (kamino nftables; HK-47 owns it). This is the guarantee. The service and its Chromium and Playwright-driver children run as the dedicated user `dfrender`, and an nftables output rule drops that user's packets to the same ranges: `meta skuid dfrender ip daddr { ... } drop`, plus IPv6. DNS to kamino's resolver is the only exception needed; Playwright talks to Chromium over a pipe, not TCP.

## No persistent browser profile

- The browser is started with Playwright's `chromium.launch()`, never `launch_persistent_context()`. Playwright gives each browser process a fresh temporary profile directory and deletes it when the browser closes.
- `TMPDIR` points at a per-process temp directory, inside the unit's `PrivateTmp`, which the service removes on exit.
- Every render runs in a new `BrowserContext`, closed in `finally`. Cookies, localStorage, cache and service workers (blocked anyway) never carry from one render to the next.

## Privacy

The service never logs a URL. Each render logs one line: the status code, a reason token, and the duration. aiohttp's access log is off. The URL does pass through Cloudflare on the way from bespin, so this path is not guaranteed log-free; duckfind's About page says so.

## Install on kamino (HK-47)

kamino runs Debian 13 (trixie). The browser is Playwright's own pinned Chromium (option a), so the driver and browser versions always match.

```sh
apt install libnss3 fonts-liberation        # the rest of Chromium's libs and python3-venv are already present (checked 2026-11-12)
# the user is dfrender, not render: Debian already has a system group `render` (GPU/dri)
useradd --system --user-group --home /opt/render --shell /usr/sbin/nologin dfrender
install -d -o dfrender -g dfrender /opt/render
cp render_service.py ipcheck.py /opt/render/            # from duckfind/services/render/
sudo -u dfrender python3 -m venv /opt/render/venv
sudo -u dfrender /opt/render/venv/bin/pip install 'playwright==1.65.1' 'aiohttp==3.14.5'
sudo -u dfrender env PLAYWRIGHT_BROWSERS_PATH=/opt/render/browsers /opt/render/venv/bin/python -m playwright install chromium
install -m 0600 -o root -g root /dev/null /etc/duckfind-render.env
#   then put in it:  RELAY_SECRET=<relay secret>   and   BIND=192.168.30.102:8091
cp duckfind-render.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now duckfind-render
```

Next:
- Add the nftables rule for user `dfrender` (above) and make it persistent.
- Route `relay.duckfind.com/render` to `192.168.30.102:8091` in the Cloudflare tunnel config. That is a Cloudflare change, so it needs Derek's OK.
- On bespin, set `render_url` in duckfind's `config.php` to `https://relay.duckfind.com`.

## Tests

```sh
python -m venv .venv && .venv/bin/pip install playwright aiohttp pytest pytest-asyncio pytest-aiohttp
.venv/bin/python -m playwright install chromium
.venv/bin/python -m pytest -q tests/
```

- `tests/test_ipcheck.py` is pure, with no browser or network.
- `tests/test_integration.py` runs the real service against a local `http.server` with real Chromium. It is skipped when Playwright is not installed. Its pages are on 127.0.0.1, which production refuses, so the harness calls `render_service._enable_test_loopback()`. That allows loopback only; every other private range stays refused, which is what the redirect tests rely on. The switch cannot be set from the environment or any config file.

### Extra blocked addresses (optional)

`RENDER_EXTRA_BLOCKED` in `/etc/duckfind-render.env`: comma-separated CIDRs or
addresses that are public but must never be reached from kamino, such as the
home WAN IP (a hairpin through the router to its port-forwards). A bad entry
stops the service at startup. This is a second layer only: the nftables
`skuid dfrender` drop set (which must contain the same addresses) is the real
guarantee, and a DDNS-resolved WAN address has to be kept current there.

### As installed on kamino (2026-11-12, HK-47)
- User/group `dfrender` (uid 997); `/opt/render` is about 951 MB with the browser.
- Playwright 1.65.1 installed Chrome Headless Shell 158.0.8127.18 into `/opt/render/browsers`.
- `/etc/duckfind-render.env`: `RELAY_SECRET` (the relay's), `BIND=192.168.30.102:8091`,
  `RENDER_EXTRA_BLOCKED` = the home WAN /32.
- nftables table `inet dfrender` (`/etc/nftables.d/dfrender.nft`):
  - output for skuid dfrender: established allowed, DNS only to 192.168.2.1:53, and the
    blocked v4/v6 sets rejected (incl. the WAN /32);
  - input to :8091 only from yavin (192.168.30.101).
- Memory: idle about 110 MB, peak about 280 MB on first tests.
