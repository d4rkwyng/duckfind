import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ipcheck  # noqa: E402

PUB4 = "93.184.215.14"
PUB6 = "2606:2800:21f:cb07:6820:80da:af6b:8b2c"


@pytest.mark.parametrize("addr", [PUB4, PUB6, "1.1.1.1", "8.8.8.8"])
def test_public_allowed(addr):
    assert ipcheck.address_allowed(addr)


@pytest.mark.parametrize("addr", [
    "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.1",
    "192.168.30.100", "192.168.30.101", "192.168.30.102",   # VLAN 30 peers: deathstar, yavin, kamino
    "100.64.0.1", "100.89.204.83", "100.127.255.254",        # CGNAT / Tailscale
    "127.0.0.1", "127.1.2.3", "169.254.169.254", "169.254.0.1", "0.0.0.0", "0.1.2.3",
    "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.0.1",
    "::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "fe80::1%eth0", "ff02::1",
])
def test_private_refused(addr):
    assert not ipcheck.address_allowed(addr)


@pytest.mark.parametrize("addr", [
    "::ffff:192.168.1.1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:100.64.0.1",
    "::ffff:169.254.169.254", "::ffff:c0a8:0101",           # hex form of 192.168.1.1
    "2002:c0a8:0101::1",                                    # 6to4 wrapping 192.168.1.1
    "64:ff9b::c0a8:0101",                                   # NAT64 of 192.168.1.1
    "::192.168.1.1",                                        # deprecated v4-compatible
])
def test_mapped_and_embedded_private_refused(addr):
    assert not ipcheck.address_allowed(addr)


def test_mapped_public_allowed():
    assert ipcheck.address_allowed("::ffff:93.184.215.14")


def test_garbage_address_refused():
    assert not ipcheck.address_allowed("not-an-ip")
    assert not ipcheck.address_allowed("")


def test_check_url_ok():
    assert ipcheck.check_url("https://example.com/a?b=c", [PUB4]) == (True, "ok")
    assert ipcheck.check_url("http://example.com/", [PUB4, PUB6]) == (True, "ok")


def test_multi_a_record_with_one_private_refused():
    # a rebinding-shaped answer: any private address refuses the request
    assert ipcheck.check_url("https://evil.example/", [PUB4, "192.168.30.100"]) == (False, "address")
    assert ipcheck.check_url("https://evil.example/", ["127.0.0.1", PUB4]) == (False, "address")
    assert ipcheck.check_url("https://evil.example/", [PUB6, "::ffff:10.0.0.1"]) == (False, "address")


def test_unresolved_refused():
    assert ipcheck.check_url("https://nx.example/", []) == (False, "resolve")


@pytest.mark.parametrize("url", [
    "data:text/html,<h1>x</h1>", "file:///etc/passwd", "blob:https://example.com/uuid",
    "javascript:alert(1)", "ftp://example.com/", "gopher://example.com/", "about:blank",
    "chrome://settings", "view-source:https://example.com/", "ws://example.com/",
    "", "https://", "http:///nohost", "https://user:pw@example.com/",
    "https://exa mple.com/", "https://example.com/\r\nX: y",
])
def test_bad_schemes_and_shapes_refused(url):
    ok, reason = ipcheck.check_url(url, [PUB4])
    assert not ok and reason == "scheme"


@pytest.mark.parametrize("url", [
    "http://example.com:8080/", "https://example.com:8443/", "http://example.com:22/",
    "http://example.com:6379/", "https://example.com:81/",
])
def test_non_default_ports_refused(url):
    assert ipcheck.check_url(url, [PUB4]) == (False, "port")


def test_explicit_default_ports_ok():
    assert ipcheck.check_url("http://example.com:80/", [PUB4])[0]
    assert ipcheck.check_url("https://example.com:443/", [PUB4])[0]
    assert ipcheck.check_url("http://example.com:443/", [PUB4])[0]     # odd, but not a LAN admin port


def test_bad_port_number_refused():
    assert ipcheck.check_url("http://example.com:99999/", [PUB4]) == (False, "scheme")


def test_parse_url_normalises_host():
    assert ipcheck.parse_url("HTTPS://Example.COM./x") == ("https", "example.com", 443)


def test_host_literal():
    assert ipcheck.host_literal("192.168.1.1") == "192.168.1.1"
    assert ipcheck.host_literal("[::1]") == "::1"
    assert ipcheck.host_literal("example.com") is None


def test_ip_literal_url_refused_end_to_end():
    for url in ("http://192.168.30.101/", "http://[::1]/", "http://169.254.169.254/latest/meta-data/",
                "http://100.100.100.100/"):
        p = ipcheck.parse_url(url)
        lit = ipcheck.host_literal(p[1])
        assert ipcheck.check_url(url, [lit]) == (False, "address")


def test_reason_never_contains_url():
    for url, res in (("https://secret.example/token=abc", ["10.0.0.1"]), ("ftp://x/y", [PUB4])):
        _, reason = ipcheck.check_url(url, res)
        assert "secret" not in reason and "/" not in reason
