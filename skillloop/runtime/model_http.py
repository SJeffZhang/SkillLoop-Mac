"""Single-attempt local model HTTP with an absolute transport deadline."""

import http.client
import math
import socket
import threading
import time
from urllib.parse import urlparse


class ModelHTTPIncomplete(OSError):
    def __init__(self, partial, status=None):
        super().__init__('model_http_incomplete')
        self.partial, self.status = partial, status


def request_model(endpoint, path, body, *, timeout, unix_socket_path=None,
                  peer_validator=None, maximum_bytes=4194304, method='POST'):
    if (type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0
            or type(maximum_bytes) is not int or maximum_bytes <= 0):
        raise ValueError('model_http_limits')
    if method not in {'POST', 'GET'}:
        raise ValueError('model_http_method')
    target = urlparse(endpoint)
    if (target.scheme != 'http' or target.hostname not in
            {'127.0.0.1', 'localhost', 'host.docker.internal'}
            or target.username or target.password or target.query or target.fragment):
        raise ValueError('model_http_local_endpoint')
    deadline = time.monotonic() + timeout
    # Resolve before dispatch. Never retry a different address after POST.
    if unix_socket_path is None:
        host = '127.0.0.1' if target.hostname == 'localhost' else target.hostname
        address = ((host, target.port or 80) if host == '127.0.0.1' else
                   socket.getaddrinfo(host, target.port or 80,
                                      socket.AF_INET, socket.SOCK_STREAM)[0][4])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        address = unix_socket_path
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    expired = threading.Event()
    connection = http.client.HTTPConnection(target.hostname, target.port or 80,
                                            timeout=timeout)
    raw = bytearray()
    status = None
    def interrupt():
        expired.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        sock.close()
        raise TimeoutError('model_http_resolution_deadline')
    watchdog = threading.Timer(remaining, interrupt)
    watchdog.daemon = True
    watchdog.start()
    try:
        sock.settimeout(remaining)
        sock.connect(address)
        connection.sock = sock
        if expired.is_set():
            raise TimeoutError('model_http_deadline')
        if peer_validator is not None:
            peer_validator(sock)
        connection.request(method, target.path.rstrip('/') + path, body=body,
                           headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        status = response.status
        declared = response.getheader('Content-Length')
        if declared is not None and (not declared.isdecimal()):
            raise ModelHTTPIncomplete(bytes(raw), status)
        # Keep bounded raw custody on oversized and malformed responses too.
        while len(raw) <= maximum_bytes:
            chunk = response.read1(min(65536, maximum_bytes + 1 - len(raw)))
            raw.extend(chunk)
            if expired.is_set():
                raise TimeoutError('model_http_deadline')
            if not chunk:
                break
        if declared is not None and len(raw) <= maximum_bytes and len(raw) != int(declared):
            raise ModelHTTPIncomplete(bytes(raw), status)
        if time.monotonic() >= deadline:
            raise TimeoutError('model_http_deadline')
        return status, bytes(raw)
    except (OSError, http.client.HTTPException) as error:
        if isinstance(error, http.client.IncompleteRead):
            raw.extend(error.partial[:max(0, maximum_bytes + 1 - len(raw))])
        raise ModelHTTPIncomplete(bytes(raw), status) from error
    finally:
        watchdog.cancel()
        watchdog.join()
        connection.close()
        sock.close()
