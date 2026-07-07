<p align="center">
  <img src="public/duck.gif" width="120" alt="DuckFind">
</p>

<h1 align="center">DuckFind</h1>

<p align="center"><i>The modern web, in plain HTML — for vintage browsers.</i></p>

DuckFind is a self-hosted web **search engine and article reader** for old computers.
It fetches modern, TLS-only, JavaScript-heavy web pages on the server and hands the
browser clean **HTML 3.2** — no CSS, no scripts — that renders on machines as old as a
System 7 Mac, a Windows 3.1 box, or an Apple II with a text browser.

It's a single-file-per-page PHP app with **zero dependencies** (no Composer, no
frameworks) — just PHP with the `curl`, `dom`, `gd`, and `mbstring` extensions.

Inspired by [FrogFind](https://frogfind.com) by Action Retro. DuckFind is an
independent implementation (none of FrogFind's code) that adds inline images,
low-colour/dithered image modes, a Wayback Machine reader, a sectioned news portal,
and SSRF hardening. Search results come from [DuckDuckGo](https://duckduckgo.com);
DuckFind is not affiliated with DuckDuckGo or FrogFind.

## Features

- **Search** — DuckDuckGo results reformatted as plain HTML, with pagination.
- **Reader** — any page distilled to readable HTML via a home-grown Readability-style
  extractor (semantic scoping, class/id hints, link-density penalty, junk stripping).
  Tables keep visible borders and cell spans; it honours `<base href>`, follows
  `rel=next` for multi-page articles, and detects anti-bot/JS challenge pages
  (offering a Wayback copy instead of rendering "Just a moment…").
- **Inline images** — an image proxy downscales JPEG/PNG/WebP/AVIF and re-encodes to
  **GIF** (the one format every old browser renders), with **grayscale** and **dithered
  black-&-white** modes for 1-bit displays. A 4000px DSLR photo becomes a 3 KB GIF.
- **Wayback mode** — read any page as it existed in a past year. Images and links stay
  in the same era (temporal consistency). An era switcher lives in the reader
  toolbar. Archived pages default to an **original-layout** render — tables,
  `<font>`, and image-nav preserved (they were built for old browsers) — with a
  one-click toggle to reader mode. A sanitiser strips scripts/handlers/`style`/
  `javascript:` so the passed-through HTML is safe.
- **Plain-text mode** — `text/plain` output for terminal browsers (MacLynx) and the
  oldest machines.
- **News portal** — RSS/Atom feeds grouped into sections (World, Technology, Science,
  Gaming, …), merged and date-sorted, each story opening in the reader.
- **Bang shortcuts** — `!w term` (Wikipedia), `!wb url [year]` (Wayback), `!r url`
  (read), `!weather place` (5-day forecast via Open-Meteo), `!define word`
  (dictionary), `!news`. Unknown bangs degrade to a normal search.
- **Persistent settings** — a cookie-backed settings page: default to text-only,
  grayscale/dithered images, or a **dark theme** site-wide (e.g. a 1-bit compact Mac).
  Dark mode is plain `<body>` colour attributes, so it works on the oldest browsers.
- **Charset handling** — non-UTF-8 pages (Shift-JIS, windows-1251, …) are detected and
  converted; typographic characters are transliterated to ASCII for pre-Unicode browsers.
- **Disk cache** — pages, converted images, and feeds are cached to spare slow clients
  and to be polite to upstreams.

## Security

DuckFind fetches arbitrary user-supplied URLs, so it is hardened against
[SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery):

- Resolves DNS itself and **rejects any non-public IP** — private ranges, loopback,
  link-local, cloud metadata (`169.254.169.254`), CGNAT/**Tailscale** (`100.64.0.0/10`),
  IPv4-mapped IPv6, and more.
- **Pins the connection to the validated IP** (defeats DNS rebinding) and re-validates
  every redirect hop.
- Allows only `http`/`https` (no `file://`, `gopher://`, …).
- Rate limiting keys on the client IP. Forwarded IP headers are spoofable, so
  DuckFind uses `REMOTE_ADDR` unless you list your proxy in `trusted_proxies`
  (config) — set that if you run behind Cloudflare/nginx, or a client could
  reset its own bucket at will.
- Per-IP **rate limiting** (race-safe file locks), `robots.txt` disallowing the fetch
  endpoints, and `noindex` on reader pages so crawlers can't turn DuckFind into a
  fetch cannon.
- **Image decompression-bomb guard** — image dimensions are read from the header and
  rejected (>30 MP) before GD decodes the bitmap, so a tiny file declaring huge
  dimensions can't exhaust memory.
- Output is escaped/whitelisted (tag allow-list, attributes dropped, `javascript:`/
  `data:` URIs stripped), and the disk cache self-prunes so it can't grow unbounded.

## Requirements

- PHP 8.0+ with `curl`, `dom`, `gd`, `mbstring`
- A web server that runs PHP (Caddy, nginx + php-fpm, Apache…)
- Outbound HTTPS access from the server

## Install

```sh
git clone https://github.com/d4rkwyng/duckfind.git /srv/duckfind
cd /srv/duckfind
cp config.example.php config.php     # then edit config.php
```

Point your web server's document root at **`public/`** (config.php stays one directory
up, outside the web root). See [`examples/`](examples/) for Caddy and nginx configs.

Make the cache directory writable by the web-server user (default:
`sys_get_temp_dir()/duckfind-cache`; set `cache_dir` in config.php).

**Serve over plain HTTP.** The whole point is reachability from browsers that can't do
modern TLS, so don't force HTTPS on the public hostname. (DuckFind does all the TLS work
server-side.)

## Configuration

Everything lives in `config.php` (see `config.example.php` for the full list):
site name, user-agent, cache directory, image sizes, per-IP rate limits, and the news
feed sections. No database.

## How it works

```
vintage browser ──HTTP/1.0, plain HTML── DuckFind (PHP) ──modern TLS/HTTP2── the web
```

The browser only ever speaks plain HTTP to DuckFind. DuckFind handles TLS, JavaScript-free
fetching, content extraction, image conversion, and character-set normalisation, then
emits minimal HTML the old browser can render.

## Caveats

- Search scrapes DuckDuckGo's HTML endpoint, which is unofficial and can change or
  rate-limit. This is inherent to every FrogFind-style tool.
- Wayback mode depends on the Internet Archive, which rate-limits heavily. DuckFind
  tries both its HTTP and HTTPS endpoints and caches aggressively, but a very
  image-heavy archived page can still hit the limit (images degrade to blank).
- JavaScript-rendered single-page apps have little server-rendered content to extract;
  they'll be sparse (as they are in any reader).

## Credits

- Inspired by **[FrogFind](https://frogfind.com)** by Action Retro.
- Search via **[DuckDuckGo](https://duckduckgo.com)**.
- Wayback reader via the **[Internet Archive](https://archive.org)**.

## License

[MIT](LICENSE)
