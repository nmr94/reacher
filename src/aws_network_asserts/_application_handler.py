"""Standard-library-only protocol operations shipped inside the probe ZIP."""

import errno
import hashlib
import http.client
import socket
import ssl
import time
from ipaddress import ip_address


def handler(event, context):
    started = time.monotonic()
    if event["kind"] == "dns":
        family = event.get("address_family", "ipv4")
        versions = (4, 6) if family == "dual" else (6,) if family == "ipv6" else (4,)
        addresses = []
        by_family = {}
        for version in versions:
            try:
                records = socket.getaddrinfo(
                    event["host"],
                    None,
                    socket.AF_INET6 if version == 6 else socket.AF_INET,
                    socket.SOCK_STREAM,
                )
            except socket.gaierror as error:
                # A dual-family query can have no A or AAAA records. Preserve that
                # absence for the caller instead of falling back to the other family.
                if family != "dual" or error.errno not in {
                    socket.EAI_NONAME,
                    getattr(socket, "EAI_NODATA", socket.EAI_NONAME),
                }:
                    raise
                records = []
            resolved = list(dict.fromkeys(str(ip_address(record[4][0])) for record in records))
            by_family[f"ipv{version}"] = resolved
            addresses.extend(resolved)
        return {
            "kind": "dns",
            "addresses": addresses,
            "addresses_by_family": by_family,
            "dns_ms": (time.monotonic() - started) * 1000,
        }
    kind = event["kind"]
    observation = {
        "kind": kind,
        "resolved_ip": event["resolved_ip"],
        "port": event["port"],
        "stage": "tcp",
        "outcome": "connected",
        "timings": {},
    }
    version = ip_address(event["resolved_ip"]).version
    connection = socket.socket(
        socket.AF_INET6 if version == 6 else socket.AF_INET, socket.SOCK_STREAM
    )
    try:
        connection.settimeout(event["connect_timeout"])
        target = (event["resolved_ip"], event["port"])
        if version == 6:
            target += (0, 0)
        connection.connect(target)
        observation["timings"]["tcp_ms"] = (time.monotonic() - started) * 1000
        observation["source_ip"], observation["source_port"] = connection.getsockname()[:2]
        connection.settimeout(event["read_timeout"])
        if kind == "tls" or event.get("tls"):
            observation["stage"] = "tls"
            step = time.monotonic()
            tls_context = ssl.create_default_context(cadata=event.get("ca_pem"))
            connection = tls_context.wrap_socket(
                connection, server_hostname=event["server_hostname"]
            )
            observation["timings"]["tls_ms"] = (time.monotonic() - step) * 1000
            observation.update(
                outcome="tls_verified",
                tls_version=connection.version(),
                certificate_sha256=hashlib.sha256(
                    connection.getpeercert(binary_form=True)
                ).hexdigest(),
            )
        if kind == "http":
            observation["stage"] = "http"
            step = time.monotonic()
            request = (
                f"{event['http_method']} {event['path']} HTTP/1.1\r\n"
                f"Host: {event['host_header']}\r\nConnection: close\r\n"
                "Accept-Encoding: identity\r\n\r\n"
            )
            connection.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(connection, method=event["http_method"])
            try:
                response.begin()
                observation["status"] = response.status
                if event.get("body_contains") is not None:
                    body = response.read(event["max_body_bytes"] + 1)
                    observation["body_truncated"] = len(body) > event["max_body_bytes"]
                    observation["body_matches"] = (
                        event["body_contains"].encode() in body[: event["max_body_bytes"]]
                    )
                observation["outcome"] = "http_response"
            finally:
                response.close()
            observation["timings"]["http_ms"] = (time.monotonic() - step) * 1000
    except TimeoutError:
        observation["outcome"] = "timeout"
    except ConnectionRefusedError:
        observation["outcome"] = "refused"
    except ssl.SSLError as error:
        observation.update(outcome="tls_error", error=str(error))
    except http.client.HTTPException as error:
        observation.update(outcome="http_error", error=str(error))
    except OSError as error:
        if error.errno not in {
            errno.ENETUNREACH,
            errno.EHOSTUNREACH,
            errno.ECONNRESET,
            errno.EPIPE,
        }:
            raise
        observation.update(
            outcome="unreachable" if observation["stage"] == "tcp" else "connection_reset",
            error=str(error),
        )
    finally:
        connection.close()
    observation["elapsed_ms"] = (time.monotonic() - started) * 1000
    return observation
