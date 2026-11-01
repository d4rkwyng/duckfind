#!/bin/bash
# DuckFind auto-deploy with a lint gate. Run from cron (e.g. every 10 min):
#   */10 * * * * root /usr/local/bin/duckfind-deploy.sh
#
# Fetches origin/main, syntax-checks every added/modified .php file at the
# incoming revision with the HOST's php, and only fast-forwards if all of them
# parse. A broken push therefore never reaches the live site — it stays
# blocked (and logged) until a fixed commit lands, and the site keeps serving
# the last good revision.
#
# Every step fails closed: a failed fetch, an unresolvable revision, a failed
# diff or `git show`, or a merge that does not land exactly on the fetched
# commit logs one line and exits 1 without touching the tree. (2026-10-31: with
# github.com unresolvable the fetch failed silently, `git rev-parse FETCH_HEAD`
# echoed the literal string "FETCH_HEAD", and the log claimed a deploy that
# never happened.)
LOG=/var/log/duckfind-deploy.log
log() { echo "$(date -Is) $*" >> "$LOG"; }

cd /var/www/duckfind.com || { log "FAILED: cannot cd to /var/www/duckfind.com"; exit 1; }

if ! git fetch --quiet origin main 2>>"$LOG"; then
  log "fetch failed; nothing deployed"
  exit 1
fi
before=$(git rev-parse --verify --quiet 'HEAD^{commit}') \
  || { log "FAILED: cannot resolve HEAD"; exit 1; }
after=$(git rev-parse --verify --quiet 'FETCH_HEAD^{commit}') \
  || { log "FAILED: cannot resolve FETCH_HEAD after fetch"; exit 1; }
[ "$before" = "$after" ] && exit 0

# Collect the list first: inside `done < <(...)` a failing git diff would just
# yield no files and let the gate pass.
files=$(git diff --name-only --diff-filter=AM "$before" "$after" -- '*.php') \
  || { log "BLOCKED $before -> $after: git diff failed"; exit 1; }

tmp=$(mktemp) || { log "BLOCKED $before -> $after: mktemp failed"; exit 1; }
trap 'rm -f "$tmp"' EXIT
while IFS= read -r f; do
  [ -z "$f" ] && continue
  # Write the blob out first: piped straight into `php -l`, a failing `git show`
  # would hand php empty input, which lints clean.
  if ! git show "$after:$f" > "$tmp" 2>/dev/null; then
    log "BLOCKED $before -> $after: git show failed on $f"
    exit 1
  fi
  if ! php -l "$tmp" >/dev/null 2>&1; then
    log "BLOCKED $before -> $after: php -l failed on $f"
    exit 1
  fi
done <<< "$files"

if ! git merge --ff-only --quiet "$after" 2>>"$LOG"; then
  log "BLOCKED $before -> $after: fast-forward failed"
  exit 1
fi
now=$(git rev-parse --verify --quiet 'HEAD^{commit}')
if [ "$now" != "$after" ]; then
  log "FAILED: HEAD is ${now:-unresolvable} after merging $after"
  exit 1
fi
chown -R www-data:www-data .
log "deployed $before -> $now"
