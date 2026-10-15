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


def test_events_since_a_mark_are_counted_per_container(monkeypatch):
    from agenttrap import egress
    from agenttrap.egress import Egress
    from agenttrap.sandbox import CommandResult

    logs = {
        "sink": lines({"kind": "dns", "name": "old.test"}),
        "proxy": lines({"kind": "ready"}, {"kind": "tls", "sni": "older.test"}),
    }

    def docker(*args, **_):
        container = "sink" if args[1] == "sink" else "proxy"
        return CommandResult(0, "\n".join(logs[container]) + "\n", "")

    monkeypatch.setattr(egress, "_docker", docker)
    net = Egress()
    net.name, net.proxy_name = "sink", "proxy"
    mark = net.mark()
    assert tuple(mark) == (1, 2)

    logs["sink"] += lines({"kind": "dns", "name": "new.test"})
    logs["proxy"] += lines({"kind": "tls", "sni": "newer.test"})
    assert set(net.observed(mark).hosts) == {"new.test", "newer.test"}
    assert set(net.observed().hosts) == {"old.test", "older.test", "new.test", "newer.test"}


def test_the_pool_lends_one_egress_at_a_time_and_removes_every_one(monkeypatch):
    import threading

    from agenttrap import egress

    made, exited = [], []

    class Fake:
        def __init__(self, served):
            made.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            exited.append(self)

    monkeypatch.setattr(egress, "Egress", Fake)
    with egress.EgressPool({}, 2) as pool:
        with pool.lend() as first:
            with pool.lend() as second:
                assert first is not second
            waiting = []
            third = threading.Thread(target=lambda: waiting.append(pool.lend().__enter__()))
            third.start()
            third.join(timeout=5)  # the second was returned, so this does not block
            assert waiting == [second]
        with pool.lend() as again:
            assert again in (first, second)
        assert len(made) == 2  # never more than the size, and reused rather than remade
    assert sorted(map(id, exited)) == sorted(map(id, made))


def test_a_pool_that_is_left_by_an_error_still_removes_its_egress(monkeypatch):
    import pytest

    from agenttrap import egress

    exited = []

    class Fake:
        def __init__(self, served): ...
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            exited.append(self)

    monkeypatch.setattr(egress, "Egress", Fake)
    with pytest.raises(KeyError), egress.EgressPool({}, 1) as pool, pool.lend():
        raise KeyError
    assert len(exited) == 1


def test_warnings_on_stderr_do_not_hide_new_events(monkeypatch):
    from agenttrap import egress
    from agenttrap.egress import Egress
    from agenttrap.sandbox import CommandResult

    out = lines({"kind": "dns", "name": "old.test"})
    err = ["warning: one"]

    def docker(*args, **_):
        return CommandResult(0, "\n".join(out) + "\n", "\n".join(err) + "\n")

    monkeypatch.setattr(egress, "_docker", docker)
    net = Egress()
    mark = net.mark()
    out += lines({"kind": "dns", "name": "new.test"})
    err += ["warning: two", "warning: three"]
    assert "new.test" in net.observed(mark).hosts


def test_runs_starting_together_create_the_interception_ca_only_once(monkeypatch, tmp_path):
    import threading
    import time

    from agenttrap import egress
    from agenttrap.sandbox import CommandResult

    made = []

    def docker(*args, **_):
        made.append(args)
        time.sleep(0.05)  # creating the CA takes a while, which is when others would join in
        (tmp_path / "mitmproxy-ca-cert.pem").write_text("cert")
        return CommandResult(0, "", "")

    monkeypatch.setattr(egress, "_docker", docker)
    monkeypatch.setattr(egress, "CA_DIR", tmp_path)
    monkeypatch.setattr(egress, "CA_CERT", tmp_path / "mitmproxy-ca-cert.pem")
    runs = [threading.Thread(target=egress.ensure_ca) for _ in range(4)]
    for run in runs:
        run.start()
    for run in runs:
        run.join()
    assert len(made) == 1
