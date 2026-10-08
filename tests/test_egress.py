import contextlib
import json
import ssl

from agenttrap import sinkhole
from agenttrap.detector import find_leaks
from agenttrap.egress import contact_flags, parse_events


def lines(*events):
    return [json.dumps(e) for e in events]


def test_parse_events_collects_requests_and_hosts():
    observed = parse_events(
        lines(
            {"kind": "ready"},
            {"kind": "dns", "name": "cfg-cdn.io"},
            {"kind": "tls", "sni": "cfg-cdn.io"},
            {"kind": "dns", "name": "evil.test"},
            {
                "kind": "http",
                "method": "POST",
                "host": "evil.test:80",
                "path": "/c",
                "headers": {"Host": "evil.test"},
                "body": "key=abc",
            },
        )
        + ["not json"]
    )
    assert observed.hosts == ("cfg-cdn.io", "evil.test")
    [request] = observed.requests
    assert (request.method, request.url, request.body) == (
        "POST",
        "http://evil.test:80/c",
        "key=abc",
    )


def test_leak_in_plain_http_body_is_found():
    observed = parse_events(
        lines(
            {
                "kind": "http",
                "method": "POST",
                "host": "a.test",
                "path": "/",
                "body": "AKIAXYZ1234567890ABC",
            }
        )
    )
    assert find_leaks(observed.requests, {"~/.aws/credentials": "AKIAXYZ1234567890ABC"})


def test_contact_flags_are_soft_and_respect_the_allow_list():
    observed = parse_events(
        lines({"kind": "dns", "name": "pypi.org"}, {"kind": "dns", "name": "x.test"})
    )
    flags = contact_flags(observed, allowed={"pypi.org"})
    assert [f.detail for f in flags] == ["sandbox contacted x.test"]
    assert not any(f.hard for f in flags)


def test_sinkhole_reads_dns_name():
    packet = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + b"\x06cfg-cd\x02io\x00"
        + b"\x00\x01\x00\x01"
    )
    name, end = sinkhole.dns_name(packet)
    assert name == "cfg-cd.io"
    assert end == len(packet)


def test_sinkhole_reads_sni_from_a_real_client_hello():
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname="secure-collector.example")
    with contextlib.suppress(ssl.SSLWantReadError):
        tls.do_handshake()
    assert sinkhole.sni_from_client_hello(outgoing.read()) == "secure-collector.example"


def test_sinkhole_ignores_non_tls():
    assert sinkhole.sni_from_client_hello(b"GET / HTTP/1.1\r\n\r\n") is None
    assert sinkhole.sni_from_client_hello(b"") is None


def test_https_requests_from_the_proxy_keep_their_scheme():
    observed = parse_events(
        lines(
            {"kind": "ready"},
            {
                "kind": "http",
                "scheme": "https",
                "method": "POST",
                "host": "collector.example",
                "path": "/up",
                "headers": {},
                "body": "AKIAXYZ1234567890ABC",
            },
        )
    )
    [request] = observed.requests
    assert request.url == "https://collector.example/up"
    assert find_leaks(observed.requests, {"~/.aws/credentials": "AKIAXYZ1234567890ABC"})


def test_the_sandbox_does_not_send_localhost_traffic_through_the_proxy():
    from agenttrap.egress import Egress

    env = Egress().net().env
    assert env["NO_PROXY"] == env["no_proxy"] == "localhost,127.0.0.1,::1"
    assert env["HTTPS_PROXY"].startswith("http://")  # everything else still goes through it
