"""Exercise shipped networking code without opening sockets."""

import errno
import hashlib
import http.client
import socket
import ssl
from unittest.mock import Mock

import pytest

from aws_network_asserts import _application_handler as handler
from aws_network_asserts.probe_session import ProbeSession


def event(kind="tcp", target="service.example", **options):
    spec = ProbeSession._prepare(kind, target, **options)
    return {**spec, "resolved_ip": "10.1.2.3"}


@pytest.fixture
def connection(monkeypatch):
    conn = Mock()
    conn.getsockname.return_value = ("10.0.1.10", 45000)
    monkeypatch.setattr(handler.socket, "socket", Mock(return_value=conn))
    return conn


def test_tcp_records_actual_source_and_closes(connection):
    result = handler.handler(event(), None)
    assert result["outcome"] == "connected"
    assert result["source_ip"] == "10.0.1.10"
    assert result["source_port"] == 45000
    assert result["elapsed_ms"] >= 0
    connection.connect.assert_called_once_with(("10.1.2.3", 443))
    connection.sendall.assert_not_called()
    connection.close.assert_called_once()


def test_dns_deduplicates_inside_vpc(monkeypatch):
    lookup = Mock(
        return_value=[
            (None, None, None, None, (ip, 0)) for ip in ("10.1.2.3", "10.1.2.3", "10.1.2.4")
        ]
    )
    monkeypatch.setattr(handler.socket, "getaddrinfo", lookup)
    result = handler.handler({"kind": "dns", "host": "service.example"}, None)
    assert result["addresses"] == ["10.1.2.3", "10.1.2.4"]
    lookup.assert_called_once_with("service.example", None, socket.AF_INET, socket.SOCK_STREAM)


def test_tls_checks_trust_hostname_and_records_certificate(connection, monkeypatch):
    wrapped = Mock()
    wrapped.version.return_value = "TLSv1.3"
    wrapped.getpeercert.return_value = b"certificate"
    context = Mock()
    context.wrap_socket.return_value = wrapped
    factory = Mock(return_value=context)
    monkeypatch.setattr(handler.ssl, "create_default_context", factory)
    result = handler.handler(event("tls"), None)
    factory.assert_called_once_with(cadata=None)
    context.wrap_socket.assert_called_once_with(connection, server_hostname="service.example")
    assert result["certificate_sha256"] == hashlib.sha256(b"certificate").hexdigest()
    assert result["outcome"] == "tls_verified"
    wrapped.close.assert_called_once()


@pytest.mark.parametrize("tls", [False, True])
def test_http_exact_target_host_header_bounded_body_no_redirect(connection, monkeypatch, tls):
    if tls:
        connection.version.return_value = "TLSv1.3"
        connection.getpeercert.return_value = b"certificate"
        monkeypatch.setattr(
            handler.ssl,
            "create_default_context",
            Mock(return_value=Mock(wrap_socket=Mock(return_value=connection))),
        )
    response = Mock(status=302)
    response.read.return_value = b"ready12345"
    factory = Mock(return_value=response)
    monkeypatch.setattr(handler.http.client, "HTTPResponse", factory)
    result = handler.handler(
        event(
            "http",
            f"{'https' if tls else 'http'}://service.example:8443/health?q=1",
            body_contains="ready",
            max_body_bytes=8,
        ),
        None,
    )
    assert result["outcome"] == "http_response"
    assert result["status"] == 302
    assert result["body_matches"] is True
    assert result["body_truncated"] is True
    assert "ready" not in str(result)  # no response body retained
    response.read.assert_called_once_with(9)
    connection.sendall.assert_called_once_with(
        b"GET /health?q=1 HTTP/1.1\r\nHost: service.example:8443\r\n"
        b"Connection: close\r\nAccept-Encoding: identity\r\n\r\n"
    )
    response.close.assert_called_once()
    connection.close.assert_called_once()


@pytest.mark.parametrize(
    "error,outcome",
    [
        (TimeoutError(), "timeout"),
        (ConnectionRefusedError(), "refused"),
        (OSError(errno.ENETUNREACH, "down"), "unreachable"),
    ],
)
def test_connect_failures_are_failed_positive_observations(connection, error, outcome):
    connection.connect.side_effect = error
    assert handler.handler(event(), None)["outcome"] == outcome
    connection.close.assert_called_once()


def test_unknown_socket_error_propagates_and_closes(connection):
    connection.connect.side_effect = OSError(errno.EINVAL, "invalid")
    with pytest.raises(OSError):
        handler.handler(event(), None)
    connection.close.assert_called_once()


def test_certificate_failure_is_distinct_from_connection_failure(connection, monkeypatch):
    context = Mock()
    context.wrap_socket.side_effect = ssl.SSLCertVerificationError("hostname mismatch")
    monkeypatch.setattr(handler.ssl, "create_default_context", Mock(return_value=context))
    result = handler.handler(event("tls"), None)
    assert result["stage"] == "tls"
    assert result["outcome"] == "tls_error"
    connection.close.assert_called_once()


def test_http_parse_failure_is_distinct(connection, monkeypatch):
    response = Mock()
    response.begin.side_effect = http.client.BadStatusLine("bad")
    monkeypatch.setattr(handler.http.client, "HTTPResponse", Mock(return_value=response))
    result = handler.handler(event("http", "http://service.example"), None)
    assert result["stage"] == "http"
    assert result["outcome"] == "http_error"
    response.close.assert_called_once()
    connection.close.assert_called_once()


def test_cancellation_during_http_body_read_closes_response_and_socket(connection, monkeypatch):
    response = Mock(status=200)
    interrupt = KeyboardInterrupt("body read interrupted")
    response.read.side_effect = interrupt
    monkeypatch.setattr(handler.http.client, "HTTPResponse", Mock(return_value=response))
    with pytest.raises(KeyboardInterrupt) as caught:
        handler.handler(event("http", "http://service.example", body_contains="ready"), None)
    assert caught.value is interrupt
    response.close.assert_called_once()
    connection.close.assert_called_once()


def test_ipv6_socket_uses_ipv6_family_and_four_part_address(connection, monkeypatch):
    connection.getsockname.return_value = ("2001:db8:1::10", 45000, 0, 0)
    request = event("tcp", "2001:db8:2::10", address_family="ipv6")
    request["resolved_ip"] = "2001:db8:2::10"
    result = handler.handler(request, None)
    handler.socket.socket.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
    connection.connect.assert_called_once_with(("2001:db8:2::10", 443, 0, 0))
    assert result["source_ip"] == "2001:db8:1::10"
    assert result["outcome"] == "connected"
    connection.close.assert_called_once()


def test_ipv6_http_retains_bracketed_host_header(connection, monkeypatch):
    connection.getsockname.return_value = ("2001:db8:1::10", 45000, 0, 0)
    response = Mock(status=200)
    monkeypatch.setattr(handler.http.client, "HTTPResponse", Mock(return_value=response))
    request = event("http", "http://[2001:db8:2::10]:8080/health", address_family="ipv6")
    request["resolved_ip"] = "2001:db8:2::10"
    result = handler.handler(request, None)
    assert result["outcome"] == "http_response"
    assert b"Host: [2001:db8:2::10]:8080\r\n" in connection.sendall.call_args.args[0]
    connection.connect.assert_called_once_with(("2001:db8:2::10", 8080, 0, 0))
    connection.close.assert_called_once()


def test_dual_dns_queries_both_families_and_keeps_them_separate(monkeypatch):
    def lookup(host, port, family, socktype):
        address = "10.1.2.3" if family == socket.AF_INET else "2001:db8:2::10"
        return [(family, socktype, 0, "", (address, 0))]

    resolver = Mock(side_effect=lookup)
    monkeypatch.setattr(handler.socket, "getaddrinfo", resolver)
    result = handler.handler(
        {"kind": "dns", "host": "service.example", "address_family": "dual"}, None
    )
    assert result["addresses"] == ["10.1.2.3", "2001:db8:2::10"]
    assert result["addresses_by_family"] == {"ipv4": ["10.1.2.3"], "ipv6": ["2001:db8:2::10"]}
    assert resolver.call_count == 2


def test_dual_dns_preserves_missing_aaaa_instead_of_falling_back(monkeypatch):
    resolver = Mock(
        side_effect=[
            [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.1.2.3", 0))],
            socket.gaierror(socket.EAI_NONAME, "No AAAA record"),
        ]
    )
    monkeypatch.setattr(handler.socket, "getaddrinfo", resolver)
    result = handler.handler(
        {"kind": "dns", "host": "service.example", "address_family": "dual"}, None
    )
    assert result["addresses_by_family"] == {"ipv4": ["10.1.2.3"], "ipv6": []}


def test_dns_transient_failure_does_not_become_missing_family(monkeypatch):
    monkeypatch.setattr(
        handler.socket,
        "getaddrinfo",
        Mock(side_effect=socket.gaierror(socket.EAI_AGAIN, "Try later")),
    )
    with pytest.raises(socket.gaierror):
        handler.handler({"kind": "dns", "host": "service.example", "address_family": "dual"}, None)
