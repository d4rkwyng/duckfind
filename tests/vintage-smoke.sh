#!/usr/bin/env bash
# DuckFind vintage-client smoke test -- runs against the LIVE site.
#
# Fetches DuckFind the way old browsers do: HTTP/1.0, plain http://, no
# Accept-Encoding (curl sends none without --compressed) and no cookie jar, so
# every Set-Cookie is dropped -- exactly like MacWeb, Mosaic or early Netscape
# with cookies off or unsupported. The point is to prove the browser-proof
# cookie gate (df_pob_classify in public/lib.php) lets real vintage User-Agents
# through on every feature, while a modern UA without a cookie is still gated.
#
# Usage:   tests/vintage-smoke.sh            (exit 0 = all PASS, 1 = any FAIL)
# Cron:    15 6 * * *  /path/to/duckfind/tests/vintage-smoke.sh > /path/to/log 2>&1
#          (needs only bash 3.2+, curl and coreutils; takes ~4 minutes; grep the
#          log for '^FAIL' or check the exit status)
#
# Environment overrides:
#   DUCKFIND_BASE   base URL           (default http://duckfind.com -- keep http://)
#   DF_SLEEP        seconds between requests (default 1.5)
#   DF_TIMEOUT      per-request timeout in seconds (default 25)
#   DF_MAX_HTML_KB  HTML page-weight ceiling in KB (default 200, see below)
#   DF_COOKIE_RETRY 1 (default) / 0. When a vintage UA is gated (302 + df_pob
#                   cookie), the FAIL stands, and at the end of the run the
#                   request is retried once WITH that cookie; the retry is INFO
#                   only, to show whether a vintage browser that does keep
#                   cookies gets through.
#
# Cost/volume rules (it runs daily from cron):
#   - never ask.php with a query (bills AI), never ytsearch/watch queries;
#     their LANDING pages only.
#   - searches use ONE fixed query (plus the fixed calc/define/... queries the
#     feature test also uses) so repeats hit the 10-minute search cache and
#     don't eat the site-wide daily search cap.
#   - ~130 requests per run (129 on 2026-11-08, incl. 20 cookie retries),
#     spread over ~4 minutes by DF_SLEEP: ~32 requests/minute in total against
#     per-IP buckets of page 120/60, search 40/60 (38 search hits per run,
#     ~10/minute), map 30/60 (9 per run).
#
# Page weight: 200 KB. A 28.8k modem moves ~3 KB/s, so 200 KB is already over
# a minute of waiting, and Netscape 1.x-3.x on a 68k Mac with a few MB of
# application memory starts failing to lay out HTML well before 1 MB. DuckFind
# pages are normally a few KB to a few tens of KB (reader/news pages are the
# biggest), so 200 KB is a regression alarm, not a target.
#
# Result lines: PASS / FAIL / INFO. INFO never affects the exit code.

set -u

BASE="${DUCKFIND_BASE:-http://duckfind.com}"
BASE="${BASE%/}"
SLEEP="${DF_SLEEP:-1.5}"
TIMEOUT="${DF_TIMEOUT:-25}"
MAX_HTML_KB="${DF_MAX_HTML_KB:-200}"
RETRY="${DF_COOKIE_RETRY:-1}"
# img-proxy test URL carries a per-run cache-buster: img.php cache HITS are
# ungated, so a URL warmed by an earlier run would hide the cookieless gate.
RUN_ID=$(date -u +%Y%m%d%H%M%S)

command -v curl >/dev/null 2>&1 || { echo "FAIL: curl not found"; exit 2; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/df-vintage.XXXXXX") || { echo "FAIL: mktemp"; exit 2; }
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0; INFO=0; REQS=0
FAILED=()
MODE=""         # "" = normal cookieless run; "cookie" = INFO-only retry with df_pob
COOKIE=""       # cookie sent in MODE=cookie
GATE_COOKIE=""  # df_pob=... captured from the last gate 302
RETRY_Q=()      # cookie retries, run after ALL cookieless checks (see section 4)
# Queue a cookie retry. Deferred, not immediate: a retry that gets through
# warms the server's cache, and cache hits on img.php/map tiles are ungated --
# an immediate retry would make the NEXT UA's cookieless check pass falsely.
queue_retry() {   # queue_retry KIND LABEL UA ARG...
  [ "$RETRY" = 1 ] || return 0
  local IFS=$'\t'; RETRY_Q+=("$GATE_COOKIE"$'\t'"$*")
}

info() { INFO=$((INFO+1)); echo "INFO: $*"; }
pass() {
  if [ -n "$MODE" ]; then info "$* [retry WITH df_pob cookie: works for a vintage browser that keeps cookies]"
  else PASS=$((PASS+1)); echo "PASS: $*"; fi
}
fail() {
  if [ -n "$MODE" ]; then info "$* [retry WITH df_pob cookie: still fails]"
  else FAIL=$((FAIL+1)); FAILED+=("$*"); echo "FAIL: $*"; fi
}
# After a 3xx: remember the gate's df_pob cookie, return 2 if there was one.
gate_cookie() {
  GATE_COOKIE=$(hdr Set-Cookie | grep '^df_pob=' | cut -d';' -f1)
  [ -n "$GATE_COOKIE" ] && return 2
  return 1
}

# --- User-Agents ------------------------------------------------------------
# Every string below was taken from a real source, not composed. Where a string
# came out of the browser's own binary, the format string is quoted.
#   - Netscape 1.1N: 1995 www-talk log tally (Mosaic-era traffic stats)
#       ksi.cpsc.ucalgary.ca/archives/WWW-TALK/www-talk-1995q3/0282.html
#   - MSIE 2.0B Mac: 1996 www-talk post listing Mac IE's built-in UA choices
#       lists.w3.org/Archives/Public/www-talk/1996JanFeb/0121.html
#       (no verified MSIE 2.1 Mac string was found; 2.0B is the closest real one)
#   - Netscape 3.01 / 4.x, MSIE 4.5 / 5.2, iCab 2 / 3, Lynx: useragentstring.com
#   - MacWeb 2.0: binary format "User-Agent: %s/%s  libwww/%s"; app "MacWeb",
#       version "2.0", libwww "2.17" (the only libwww-shaped literal in the binary)
#   - NCSA Mosaic 2.0.1 Mac: binary format "NCSA Mosaic/%s (Macintosh)"
#   - NCSA Mosaic 1.0.3 Mac: binary literal "User-Agent:  MacMosaicB6  libwww2.09"
#   - Arachne: format from the Arachne source ("xChaos_Arachne/5.%s%s ..."),
#       quoted on bttr-software.de forum, entry 10725
#   - Netscape 2.02 Mac: no captured Mac 2.02 string was found; this follows
#       the Mac Netscape format every other Netscape version above uses
#       (Mozilla/<ver> (Macintosh; I; PPC)).
# Format: label|UA
VINTAGE_UAS=(
  "MacWeb 2.0|MacWeb/2.0  libwww/2.17"
  "NCSA Mosaic 2.0.1 Mac|NCSA Mosaic/2.0.1 (Macintosh)"
  "NCSA Mosaic 1.0.3 Mac|MacMosaicB6  libwww2.09"
  "Netscape 1.1N Mac PPC|Mozilla/1.1N (Macintosh; I; PPC)"
  "Netscape 1.1N Mac 68K|Mozilla/1.1N (Macintosh; I; 68K)"
  "Netscape 2.02 Mac|Mozilla/2.02 (Macintosh; I; PPC)"
  "Netscape 3.01 Mac|Mozilla/3.01 (Macintosh; U; PPC)"
  "Netscape 3.01 Gold 68K|Mozilla/3.01Gold (Macintosh; I; 68K)"
  "Netscape 4.08 Mac|Mozilla/4.08 (Macintosh; I; PPC, Nav)"
  "Netscape 4.74 Mac|Mozilla/4.74 (Macintosh; U; PPC)"
  "MSIE 2.0B Mac|Mozilla/1.21 (compatible; MSIE 2.0B; Mac_PowerPC)"
  "MSIE 2.0B Mac (NS2 spoof default)|Mozilla/2.0b3(Macintosh; I; PowerPC)"
  "MSIE 4.5 Mac|Mozilla/4.0 (compatible; MSIE 4.5; Mac_PowerPC)"
  "MSIE 5.2 Mac|Mozilla/4.0 (compatible; MSIE 5.2; Mac_PowerPC)"
  "iCab 2.9.9 68K|Mozilla/4.5 (compatible; iCab 2.9.9; Macintosh; U; 68K)"
  "iCab 3.0.5 PPC|Mozilla/5.0 (compatible; iCab 3.0.5; Macintosh; U; PPC Mac OS)"
  "Lynx 2.8.8|Lynx/2.8.8dev.3 libwww-FM/2.14 SSL-MM/1.4.1"
  "Arachne 1.95 DOS|xChaos_Arachne/5.1.95;GPL,387+ (www.glennmcc.org)"
)
# These three get the full feature list; the rest get front page + search.
FULL_LABELS=("Netscape 3.01 Mac" "MSIE 5.2 Mac" "MacWeb 2.0")

MODERN_UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

# --- Features: name|path|marker (ERE) -- same list/markers as HK-47's
# duckfind-feature-test.sh, minus the costly real-query variants.
SEARCH_Q="telescope"
FEATURES=(
  "homepage|/|Quack!"
  "search|/?q=$SEARCH_Q|read\.php\?url="
  "about|/about.php|What is"
  "calculator|/calc.php?q=12*4|48"
  "dictionary|/define.php?q=hello|<p>"
  "download-proxy|/dl.php|Download:"
  "ebook|/ebook.php?q=sherlock+holmes|ebook\.php\?id=|unavailable"
  "feeds|/feeds.php|feed"
  "ftp|/ftp.php?url=ftp://ftp.gnu.org/gnu/|\[DIR\]|\[FILE\]"
  "gopher|/gopher.php?url=gopher://gopher.floodgap.com/|DIR|TXT"
  "guestbook|/guestbook.php|[Gg]uestbook"
  "hackernews|/hn.php|points by"
  "map|/map.php?q=Boston|gif=1"
  "news|/news.php|<h2>"
  "pdf-landing|/pdf.php|PDF"
  "reader|/read.php?url=https%3A%2F%2Fexample.com%2F|Example Domain|could not"
  "settings|/settings.php|[Ss]ettings|[Tt]heme"
  "translate|/translate.php?q=hello|<p>|translat"
  "weather|/weather.php?q=Boston|&deg;|Mainly|Overcast|cloudy"
  "wiby|/wiby.php|[Ww]iby"
  "wiki|/wiki.php?q=HTML|<h2>"
  "ask-landing|/ask.php|[Aa]sk|AI"
  "watch-landing|/watch.php|[Ww]atch|video"
  "ytsearch-landing|/ytsearch.php|[Ss]earch|YouTube"
)
SMOKE_FEATURES=("homepage" "search")

# --- HTTP helper --------------------------------------------------------------
# fetch UA URL [extra curl args...] -> sets CODE SIZE CTYPE, body in $TMP/body,
# headers in $TMP/hdr. HTTP/1.0, no compression, no cookie jar, no redirects.
fetch() {
  local ua="$1" url="$2"; shift 2
  [ "$REQS" -gt 0 ] && sleep "$SLEEP"
  REQS=$((REQS+1))
  local out
  rm -f "$TMP/hdr" "$TMP/body"
  if [ -n "$COOKIE" ]; then set -- -b "$COOKIE" "$@"; fi
  out=$(curl -s --http1.0 -A "$ua" --max-time "$TIMEOUT" \
        -D "$TMP/hdr" -o "$TMP/body" \
        -w '%{http_code} %{size_download} %{content_type}' "$@" "$url" 2>/dev/null)
  CODE="${out%% *}"; out="${out#* }"
  SIZE="${out%% *}"; CTYPE="${out#* }"
  [ "$CTYPE" = "$SIZE" ] && CTYPE=""
  [ -f "$TMP/body" ] || : > "$TMP/body"
  [ -f "$TMP/hdr" ]  || : > "$TMP/hdr"
}

hdr() {   # hdr Name -> first value of that response header (CR stripped)
  tr -d '\r' < "$TMP/hdr" | awk -v n="$1" 'BEGIN{n=tolower(n)":"}
    tolower(substr($0,1,length(n)))==n {sub(/^[^:]*:[ \t]*/,""); print; exit}'
}

is_gif() { head -c 6 "$TMP/body" | grep -qE '^GIF8[79]a$'; }

# check_page UA_LABEL UA FEATURE_NAME PATH MARKER
check_page() {
  local label="$1" ua="$2" name="$3" path="$4" marker="$5"
  local tag="[$label] $name ($path)"
  fetch "$ua" "$BASE$path"

  if [ "$CODE" = "000" ]; then fail "$tag: no response (timeout/connection error)"; return 1; fi
  if [ "$CODE" = "301" ] || [ "$CODE" = "302" ] || [ "$CODE" = "303" ] || \
     [ "$CODE" = "307" ] || [ "$CODE" = "308" ]; then
    fail "$tag: HTTP $CODE redirect to '$(hdr Location)' (vintage client gated/redirected)"
    gate_cookie; return $?
  fi
  if [ "$CODE" = "429" ]; then fail "$tag: HTTP 429 rate-limited (raise DF_SLEEP?)"; return 1; fi
  if [ "$CODE" != "200" ]; then fail "$tag: HTTP $CODE"; return 1; fi
  if grep -q 'Cookies are required' "$TMP/body"; then
    fail "$tag: got the 'Cookies are required' page"; return 1
  fi

  local problems=""
  grep -qE "$marker" "$TMP/body" || problems="$problems; marker /$marker/ missing"

  # charset: header first, then <meta>
  local cs_h cs_m cs
  cs_h=$(printf '%s' "$CTYPE" | tr 'A-Z' 'a-z' | sed -nE 's/.*charset="?([a-z0-9_-]+).*/\1/p')
  cs_m=$(head -c 4096 "$TMP/body" | tr 'A-Z' 'a-z' | grep -oE '<meta[^>]+charset="?[a-z0-9_-]+' | head -1 \
         | sed -E 's/.*charset="?//')
  cs="${cs_h:-$cs_m}"
  if [ -z "$cs" ]; then
    problems="$problems; no charset declared (header or meta)"
  elif [ -n "$cs_h" ] && [ -n "$cs_m" ] && [ "$cs_h" != "$cs_m" ]; then
    problems="$problems; charset mismatch: header=$cs_h meta=$cs_m"
  elif [ "$cs" != "iso-8859-1" ]; then
    info "$tag: charset is $cs, not iso-8859-1 (declared, so not a FAIL)"
  fi

  local kb=$(( (SIZE + 1023) / 1024 ))
  [ "$SIZE" -gt $((MAX_HTML_KB * 1024)) ] && problems="$problems; page weight ${kb}KB > ${MAX_HTML_KB}KB"

  if [ -n "$problems" ]; then fail "$tag: ${problems#; }"; return 1; fi

  # <script>: curl runs no JS, so if the marker was found the feature works
  # without it -- report the tag as progressive enhancement, not a failure.
  local nscript
  nscript=$(grep -oi '<script' "$TMP/body" | wc -l | tr -d ' ')
  [ "$nscript" -gt 0 ] && info "$tag: $nscript <script> tag(s); feature content present without JS -> progressive enhancement"

  pass "$tag: 200, marker ok, charset ${cs}, ${kb}KB"
  return 0
}

# check_gif UA_LABEL UA NAME URL
check_gif() {
  local label="$1" ua="$2" name="$3" url="$4"
  local tag="[$label] $name"
  fetch "$ua" "$url"
  if [ "$CODE" != "200" ]; then
    fail "$tag: HTTP $CODE${CODE:+ }$(hdr Location | sed 's/^/-> /') ($url)"
    case "$CODE" in 30*) gate_cookie; return $? ;; esac
    return 1
  fi
  local ct_ok=0 magic_ok=0
  case "$CTYPE" in image/gif*) ct_ok=1 ;; esac
  is_gif && magic_ok=1
  if [ $ct_ok = 1 ] && [ $magic_ok = 1 ]; then
    pass "$tag: image/gif, $(head -c 6 "$TMP/body") magic, ${SIZE}B"; return 0
  else
    fail "$tag: not a GIF (Content-Type '$CTYPE', first bytes '$(head -c 6 "$TMP/body" | tr -c '[:print:]' '.')', ${SIZE}B)"
    return 1
  fi
}

# gif_feature LABEL UA NAME URL -- check_gif plus the INFO-only cookie retry
gif_feature() {
  local rc=0
  check_gif "$@" || rc=$?
  if [ $rc = 2 ] && [ -z "$MODE" ]; then queue_retry gif "$@"; fi
}

feature_line() {   # feature_line NAME -> prints "name|path|marker"
  local f; for f in "${FEATURES[@]}"; do [ "${f%%|*}" = "$1" ] && { echo "$f"; return; }; done
}

run_feature() {    # run_feature LABEL UA "name|path|marker"
  local label="$1" ua="$2" line="$3"
  local name="${line%%|*}" rest="${line#*|}"
  local path="${rest%%|*}" marker="${rest#*|}"
  local rc=0
  check_page "$label" "$ua" "$name" "$path" "$marker" || rc=$?
  if [ $rc = 2 ] && [ -z "$MODE" ]; then queue_retry page "$@"; return 0; fi
  [ $rc = 0 ] || return 0
  if [ "$name" = "map" ]; then
    # follow the stitched-map GIF the page embeds (the tile feature promises GIF)
    local src
    src=$(grep -oE 'src="/map\.php\?gif=1[^"]*"' "$TMP/body" | head -1 | sed -E 's/^src="//; s/"$//; s/&amp;/\&/g')
    if [ -n "$src" ]; then gif_feature "$label" "$ua" "map-gif" "$BASE$src"
    else fail "[$label] map-gif: no map.php?gif=1 <img> found on map page"; fi
  fi
}

echo "DuckFind vintage smoke test -- $BASE -- $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "HTTP/1.0, no Accept-Encoding, no cookies; sleep ${SLEEP}s between requests"
echo

# --- 1. Plain-HTTP behaviour (no forced HTTPS redirect for any UA) ------------
echo "== plain http:// handling"
fetch "$MODERN_UA" "$BASE/robots.txt"
case "$CODE" in
  200) pass "[modern] http:// robots.txt served over plain HTTP (no forced https redirect)" ;;
  30*) fail "[modern] http:// robots.txt redirected ($CODE -> $(hdr Location)); plain HTTP must not be forced to https" ;;
  *)   fail "[modern] http:// robots.txt HTTP $CODE" ;;
esac
echo

# --- 2. Control: modern UA, no cookie -> gate's 302 -------------------------
echo "== control: modern UA without cookie must be gated"
fetch "$MODERN_UA" "$BASE/about.php"
loc=$(hdr Location); sc=$(hdr Set-Cookie)
if [ "$CODE" = "302" ] && printf '%s' "$loc" | grep -q '_pob=1' && printf '%s' "$sc" | grep -q '^df_pob='; then
  pass "[Chrome 131] /about.php: 302 -> $loc with Set-Cookie df_pob (gate active)"
  # Follow once, still without the cookie: must land on the cookies page, not loop.
  case "$loc" in /*) next="$BASE$loc" ;; *) next="$loc" ;; esac
  fetch "$MODERN_UA" "$next"
  if [ "$CODE" = "200" ] && grep -q 'Cookies are required' "$TMP/body"; then
    pass "[Chrome 131] $loc without cookie: 200 'Cookies are required' page (no loop)"
  else
    fail "[Chrome 131] $loc without cookie: expected 200 cookies page, got HTTP $CODE"
  fi
else
  fail "[Chrome 131] /about.php: expected 302 + Location _pob=1 + Set-Cookie df_pob, got HTTP $CODE, Location '$loc', Set-Cookie '${sc%%;*}'"
fi
echo

# --- 3. Vintage UAs ---------------------------------------------------------
for entry in "${VINTAGE_UAS[@]}"; do
  label="${entry%%|*}"; ua="${entry#*|}"
  full=0
  for f in "${FULL_LABELS[@]}"; do [ "$f" = "$label" ] && full=1; done
  if [ $full = 1 ]; then
    echo "== $label (full feature list) -- UA: $ua"
    for line in "${FEATURES[@]}"; do run_feature "$label" "$ua" "$line"; done
    gif_feature "$label" "$ua" "img-proxy" \
      "$BASE/img.php?url=https%3A%2F%2Fwww.google.com%2Ffavicon.ico%3Fdfsmoke%3D$RUN_ID"
  else
    echo "== $label (smoke) -- UA: $ua"
    for name in "${SMOKE_FEATURES[@]}"; do run_feature "$label" "$ua" "$(feature_line "$name")"; done
  fi
  echo
done

# --- 4. Deferred cookie retries (INFO only) --------------------------------
if [ "${#RETRY_Q[@]}" -gt 0 ] 2>/dev/null && [ "$RETRY" = 1 ]; then
  echo "== gated requests retried WITH the df_pob cookie the gate set (INFO only)"
  for r in "${RETRY_Q[@]}"; do
    IFS=$'\t' read -r COOKIE kind label ua arg1 arg2 <<EOF_R
$r
EOF_R
    MODE=cookie
    if [ "$kind" = gif ]; then gif_feature "$label" "$ua" "$arg1" "$arg2"
    else run_feature "$label" "$ua" "$arg1"; fi
    MODE=""; COOKIE=""
  done
  echo
fi

# --- 5. Host-less HTTP/1.0 request (Mosaic 1.x era) -- informational only ----
echo "== HTTP/1.0 request with no Host header (informational)"
fetch "MacMosaicB6  libwww2.09" "$BASE/" -H 'Host:'
if [ "$CODE" = "200" ] && grep -q 'Quack!' "$TMP/body"; then
  info "no-Host GET /: 200 with the DuckFind homepage"
else
  info "no-Host GET /: HTTP $CODE, Location '$(hdr Location)', Server '$(hdr Server)' (not counted as FAIL)"
fi
echo

echo "---"
echo "SUMMARY: PASS=$PASS FAIL=$FAIL INFO=$INFO requests=$REQS"
if [ "$FAIL" -gt 0 ]; then
  printf 'FAILED:\n'; printf '  - %s\n' "${FAILED[@]}"
  exit 1
fi
exit 0
