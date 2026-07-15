#!/bin/bash
# DuckFind auto-deploy with a lint gate. Run from cron (e.g. every 10 min):
#   */10 * * * * root /usr/local/bin/duckfind-deploy.sh
#
# Fetches origin/main, syntax-checks every added/modified .php file at the
# incoming revision with the HOST's php, and only fast-forwards if all of them
# parse. A broken push therefore never reaches the live site — it stays
# blocked (and logged) until a fixed commit lands, and the site keeps serving
# the last good revision.
cd /var/www/duckfind.com || exit 1
git fetch --quiet origin main 2>>/var/log/duckfind-deploy.log
before=$(git rev-parse HEAD 2>/dev/null)
after=$(git rev-parse FETCH_HEAD 2>/dev/null)
[ -z "$after" ] && exit 1
[ "$before" = "$after" ] && exit 0

while IFS= read -r f; do
  [ -z "$f" ] && continue
  if ! git show "$after:$f" 2>/dev/null | php -l >/dev/null 2>&1; then
    echo "$(date -Is) BLOCKED $before -> $after: php -l failed on $f" >> /var/log/duckfind-deploy.log
    exit 1
  fi
done < <(git diff --name-only --diff-filter=AM "$before" "$after" -- '*.php')

git merge --ff-only --quiet FETCH_HEAD 2>>/var/log/duckfind-deploy.log || exit 1
chown -R www-data:www-data .
echo "$(date -Is) deployed $before -> $after" >> /var/log/duckfind-deploy.log
