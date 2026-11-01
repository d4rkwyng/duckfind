# Flood protection

DuckFind runs on small hosts: one vCPU, a php-fpm pool of about ten workers.
A few hundred machines each holding a few dozen connections open can exhaust
that pool and the web server's connection table without ever tripping the app's
per-IP rate buckets. This happened to duckfind.com on 2026-11-01: about 15,000
established connections from about 400 hosts in one cloud range.

The protection is in three layers. Each is optional and works on its own.

| Layer | File | Stops |
|---|---|---|
| Firewall | `flood-protection.nft` | Too many concurrent connections or new connections from one source; escalating temporary bans |
| Web server | `Caddyfile` / `nginx.conf` | Idle and slow-drip connections that are held open |
| App | `config.php` `'rate' => ['page' => …]` | Floods of cheap PHP pages that no other bucket counts |

## Privacy

DuckFind keeps no access logs, and this protection keeps that promise:

- `flood-protection.nft` has **no `log` statement**. Don't add one.
- **Ban and strike sets** hold only offending addresses, each with a timeout. They
  live in kernel memory, are never written to disk, and are emptied by a reboot or
  a reload.
- **Meters** are the kernel's per-source counters. A connection-rate entry expires a
  minute after a source goes quiet, and a concurrent-connection entry vanishes when
  that source's last connection closes. They are kernel memory too, the same kind
  of transient state as the kernel's own connection tracking.
- **Normal visitors** never enter a ban or strike set.
- **The app's `page` bucket** uses the same salted-hash files as every other bucket,
  never the address.

If you run the firewall layer, set `'flood_protection' => true` in `config.php`
so `about.php` discloses it. Leave it `false` otherwise.

## What counts as an offense

Offenses are counted for ports 80 and 443 only, per IPv4 address and per IPv6 /64:

- more than **60 concurrent connections**, or
- new connections faster than **30 per second**, after a **burst of 1000**.

The thresholds are large on purpose: no real user behind a shared or NAT'd
address should ever be banned. HTTP/1.0 browsers without keep-alive open one
connection per image, up to about 4 at once, and a reader page can carry
dozens of images. A room of 15 vintage machines behind one address loading
image-heavy pages together comes to about 60 concurrent connections, and about
750 new ones in a few seconds. That sits at or under the caps, not over them.
A tighter meter bans exactly the visitors DuckFind exists for. Such a room will
still meet the app's own per-IP limits (for example 200 images a minute), but
those only answer "slow down". They never ban.

A whole IPv4 /24 (IPv6 /48) with more than 300 concurrent connections gets its new
connections reset. Nobody is banned for that, so a busy neighbour on the same
network isn't punished.

## Ban ladder

| Offense | Ban | Remembered for |
|---|---|---|
| First | 1 hour | 25 hours (1st strike) |
| While holding a 1st strike | 24 hours | 48 hours (2nd strike) |
| While holding a 2nd strike | 7 days | 8 days (2nd strike refreshed) |

A strike outlasts its ban by 24 hours, so "caught again within a day" counts
from the moment the ban ends. A source that stays quiet that long starts over at
one hour. A banned source's packets are all dropped before any meter runs, so a
ban can't escalate itself.

## Install: firewall (Linux, nftables)

You need nftables and a kernel of 4.18 or newer (for `ct count`). The table sits
beside ufw or firewalld and doesn't modify them.

> **Do not** put this into `/etc/nftables.conf` and enable `nftables.service`.
> Distribution stock files start with `flush ruleset`, which wipes every other
> table on the host, including ufw's or firewalld's rules.

Use a dedicated unit instead:

```sh
sudo install -m 644 flood-protection.nft /etc/duckfind-flood.nft
# Add your own monitoring/admin egress so it is never metered: edit the
# allow4 / allow6 sets, e.g.  elements = { 203.0.113.7 }
sudo nft -c -f /etc/duckfind-flood.nft          # syntax check, changes nothing

sudo tee /etc/systemd/system/duckfind-flood.service >/dev/null <<'EOF'
[Unit]
Description=DuckFind flood protection (nftables table inet duckfind_flood)
After=network-pre.target ufw.service firewalld.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/duckfind-flood.nft
ExecReload=/usr/sbin/nft -f /etc/duckfind-flood.nft
ExecStop=/usr/sbin/nft delete table inet duckfind_flood

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now duckfind-flood
sudo nft list table inet duckfind_flood | head
```

A reload or restart re-creates the table, which **clears every ban and strike**.
To change the allowlist without that, edit it live and then mirror the change in
the file:

```sh
sudo nft add element inet duckfind_flood allow4 '{ 203.0.113.7 }'
```

### Operating it

```sh
sudo nft list counters table inet duckfind_flood   # totals only, no addresses
sudo nft list set inet duckfind_flood ban4         # current offenders (and ban6)
sudo nft delete element inet duckfind_flood ban4 '{ 198.51.100.9 }'    # lift one ban
sudo nft flush set inet duckfind_flood ban4        # lift all IPv4 bans
```

### Tuning

All four thresholds are in the `web` chain of `/etc/duckfind-flood.nft`:

- the two `ct count over 60` rules: per address, and per IPv6 /64
- the two `limit rate over 30/second burst 1000 packets` rules: the rate meter
- the two `ct count over 300` rules: per /24 and per /48

Reloading the file re-creates the table, which clears every ban and strike. To
raise a threshold live and keep the bans, replace just that rule by its
handle, then make the same edit in the file so it survives a reboot:

```sh
sudo nft -a list chain inet duckfind_flood web       # note the rule's "# handle N"
sudo nft replace rule inet duckfind_flood web handle N \
    add @conn4 '{ ip saddr ct count over 100 }' counter name over_conn jump offend4
```

Bans, strikes and connection counts live in the sets, not in the rules, so
they are unaffected. One exception: a source already in the rate meter keeps
its old limit until its entry expires, a minute after it goes quiet.

### Ban count for monitoring

Counts only, never addresses. A timer writes the size of each ban and strike set
to a world-readable file once a minute, so an unprivileged monitor can alert on
a spike:

```sh
sudo tee /usr/local/sbin/duckfind-flood-count >/dev/null <<'SH'
#!/bin/sh
# Writes ONLY element counts of the duckfind_flood ban/strike sets -- never an
# address -- to /run/duckfind-flood.count (world-readable).
out=/run/duckfind-flood.count
line=$(/usr/sbin/nft -j list table inet duckfind_flood 2>/dev/null | /usr/bin/python3 -I -c '
import json, sys
want = ("ban4", "ban6", "strike1_4", "strike1_6", "strike2_4", "strike2_6")
try:
    j = json.load(sys.stdin)
except ValueError:
    sys.exit()
n = {o["set"]["name"]: len(o["set"].get("elem") or [])
     for o in j.get("nftables", []) if "set" in o and o["set"]["name"] in want}
print(" ".join("%s=%d" % (k, n.get(k, 0)) for k in want))
')
[ -n "$line" ] || line="table=missing"
printf '%s ts=%s\n' "$line" "$(date +%s)" > "$out.tmp" && chmod 644 "$out.tmp" && mv "$out.tmp" "$out"
SH
sudo chmod 755 /usr/local/sbin/duckfind-flood-count

sudo tee /etc/systemd/system/duckfind-flood-count.service >/dev/null <<'UNIT'
[Unit]
Description=Write duckfind_flood ban-set counts (no addresses) to /run/duckfind-flood.count

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/duckfind-flood-count
UNIT
sudo tee /etc/systemd/system/duckfind-flood-count.timer >/dev/null <<'UNIT'
[Unit]
Description=Every minute: duckfind_flood ban-set counts

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=5s

[Install]
WantedBy=timers.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now duckfind-flood-count.timer
cat /run/duckfind-flood.count    # e.g. ban4=0 ban6=0 strike1_4=0 ... ts=1793500000
```

Rollback: `sudo systemctl disable --now duckfind-flood-count.timer`, then remove
the two unit files, the script and `/run/duckfind-flood.count`.

### Rollback

```sh
sudo systemctl disable --now duckfind-flood        # ExecStop deletes the table
sudo rm /etc/systemd/system/duckfind-flood.service /etc/duckfind-flood.nft
sudo systemctl daemon-reload
```

`sudo nft delete table inet duckfind_flood` on its own removes the rules at once.
The unit would load them again on the next boot.

## Install: web server timeouts

**Caddy:** add the global `servers { timeouts { … } }` block from `Caddyfile` to
the top of your own Caddyfile, then:

```sh
sudo caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

**nginx:** add the three `client_header_timeout` / `client_body_timeout` /
`keepalive_timeout` lines from `nginx.conf` to your server block, then
`sudo nginx -t && sudo systemctl reload nginx`.

Don't add an overall response `write` timeout. Downloads and video streams to slow
vintage clients legitimately take minutes.

Rollback is to remove the lines, validate, and reload.

## Install: app bucket

New installs get it from `config.example.php`. On an existing install, add
`'page' => [120, 60],` to the `'rate'` array in `config.php`. Without that key, the
bucket still applies at the built-in default of 60 requests per 60 seconds.
