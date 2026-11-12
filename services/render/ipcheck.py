"""URL / address policy for the duckfind render service.

Pure functions (no network) so they are unit-testable. The service resolves a
host with getaddrinfo and passes every resolved address to check_url(); ANY
refused address refuses the request (a host with one public and one private
A record is refused, so a rebinding-shaped answer can't slip a private address
through).

This is the in-browser first layer. It has a DNS-rebinding race (Chromium
resolves again after this check), so the guarantee is the kernel layer on
kamino: nftables `meta skuid render ... drop` for the same ranges.
"""
import ipaddress
from urllib.parse import urlsplit

ALLOWED_SCHEMES = ("http", "https")
ALLOWED_PORTS = (80, 443)

# Refused IPv4 / IPv6 networks. v4-mapped and v4-compatible IPv6 forms are
# unwrapped to IPv4 before checking, so ::ffff:192.168.1.1 is caught by
# 192.168.0.0/16.
BLOCKED_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",        # "this" network
    "10.0.0.0/8",       # RFC1918
    "100.64.0.0/10",    # CGNAT / Tailscale
    "127.0.0.0/8",      # loopback
    "169.254.0.0/16",   # link-local
    "172.16.0.0/12",    # RFC1918
    "192.0.0.0/24",     # IETF protocol assignments
    "192.0.2.0/24",     # TEST-NET-1
    "192.168.0.0/16",   # RFC1918 (includes the 192.168.30.x VLAN 30 peers)
    "198.18.0.0/15",    # benchmarking
    "198.51.100.0/24",  # TEST-NET-2
    "203.0.113.0/24",   # TEST-NET-3
    "224.0.0.0/4",      # multicast
    "240.0.0.0/4",      # reserved + broadcast
    "::/128",           # unspecified
    "::1/128",          # loopback
    "64:ff9b::/96",     # NAT64 (can map to private v4)
    "64:ff9b:1::/48",   # local-use NAT64
    "100::/64",         # discard
    "2001:db8::/32",    # documentation
    "fc00::/7",         # unique local
    "fe80::/10",        # link-local
    "ff00::/8",         # multicast
)]


def _unwrap(ip):
    """IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) -> IPv4."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip.sixtofour is not None:          # 2002::/16 embeds a v4 address
            return ip.sixtofour
        if ip.teredo is not None:             # 2001::/32 embeds the client v4 (obfuscated)
            return ip.teredo[1]
        packed = ip.packed
        if packed[:12] == b"\x00" * 12 and packed[12:] != b"\x00\x00\x00\x00" and packed[12:] != b"\x00\x00\x00\x01":
            return ipaddress.IPv4Address(packed[12:])   # deprecated v4-compatible
    return ip


def address_allowed(addr):
    """True if a single resolved address may be contacted."""
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])   # drop an IPv6 zone id
    except ValueError:
        return False
    ip = _unwrap(ip)
    return not any(ip in net for net in BLOCKED_NETS if net.version == ip.version)


def parse_url(url):
    """(scheme, host, port) or None when the URL is not a usable http(s) URL."""
    if not isinstance(url, str) or not url or len(url) > 4096:
        return None
    if any(c in url for c in "\x00\r\n\t "):
        return None
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return None
    scheme = (p.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return None
    host = (p.hostname or "").rstrip(".").lower()
    if not host or p.username is not None or p.password is not None:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port


def check_url(url, resolved):
    """Policy decision for one request.

    url:      the request URL (main document, redirect hop or subresource)
    resolved: list of address strings getaddrinfo returned for its host
              (for an IP-literal host, that literal)
    Returns (ok, reason). reason is a short token, never the URL.
    """
    parsed = parse_url(url)
    if parsed is None:
        return False, "scheme"
    _scheme, _host, port = parsed
    if port not in ALLOWED_PORTS:
        return False, "port"
    if not resolved:
        return False, "resolve"
    for a in resolved:
        if not address_allowed(a):
            return False, "address"
    return True, "ok"


def host_literal(host):
    """The host as an IP address string if it is a literal, else None."""
    h = host.strip("[]")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        return None
