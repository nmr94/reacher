"""Standard-library-only code uploaded as the temporary Lambda's handler."""

import errno
import socket
import time


def handler(event, context):
    """Observe one TCP handshake to the first IPv4 address returned by DNS."""
    if "kind" in event:
        from application_handler import handler as application_handler

        return application_handler(event, context)
    host, port = event["host"], event["port"]
    # Resolution failures are execution errors, never a failed connectivity result.
    address = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4]
    started = time.monotonic()
    observation = {"resolved_ip": address[0], "port": port}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(event["connect_timeout"])
        try:
            connection.connect(address)
            observation["outcome"] = "connected"
        except TimeoutError:
            observation["outcome"] = "timeout"
        except ConnectionRefusedError:
            observation["outcome"] = "refused"
        except OSError as error:
            if error.errno not in {errno.ENETUNREACH, errno.EHOSTUNREACH}:
                raise
            observation["outcome"] = "unreachable"
    observation["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return observation
