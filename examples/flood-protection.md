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

- more than **20 concurrent connections**, or
- new connections faster than **5 per second**, after a **burst of 100**.

The burst is large on purpose. HTTP/1.0 browsers without keep-alive open one
connection per image, and a reader page can carry dozens of images. A tighter
meter bans exactly the visitors DuckFind exists for.

A whole IPv4 /24 (IPv6 /48) with more than 100 concurrent connections gets its new
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
