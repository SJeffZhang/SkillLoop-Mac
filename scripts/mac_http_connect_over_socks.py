"""Loopback HTTP CONNECT adapter for the existing SSH SOCKS5 tunnel.

The SOCKS request uses the destination domain name, so DNS resolution stays on
the SSH peer. This is a temporary download transport, never a scanner endpoint.
"""

from __future__ import annotations

import argparse
import select
import socket
import socketserver
import struct


def read_exact(stream: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        block = stream.recv(count - len(result))
        if not block:
            raise ConnectionError("short_socks_reply")
        result.extend(block)
    return bytes(result)


def socks_connect(host: str, port: int, proxy_port: int) -> socket.socket:
    upstream = socket.create_connection(("127.0.0.1", proxy_port), timeout=20)
    try:
        upstream.sendall(b"\x05\x01\x00")
        if read_exact(upstream, 2) != b"\x05\x00":
            raise ConnectionError("socks_auth_failed")
        encoded = host.encode("idna")
        if not 1 <= len(encoded) <= 255:
            raise ValueError("invalid_destination")
        upstream.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded + struct.pack("!H", port))
        header = read_exact(upstream, 4)
        if header[:2] != b"\x05\x00":
            raise ConnectionError("socks_connect_failed")
        address_size = {1: 4, 4: 16}.get(header[3])
        if header[3] == 3:
            address_size = read_exact(upstream, 1)[0]
        if address_size is None:
            raise ConnectionError("invalid_socks_address")
        read_exact(upstream, address_size + 2)
        upstream.settimeout(None)
        return upstream
    except Exception:
        upstream.close()
        raise


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        client.settimeout(20)
        request = bytearray()
        while b"\r\n\r\n" not in request and len(request) <= 4096:
            block = client.recv(1024)
            if not block:
                return
            request.extend(block)
        if b"\r\n\r\n" not in request:
            return
        first = bytes(request).split(b"\r\n", 1)[0]
        try:
            method, authority, version = first.decode("ascii").split(" ")
            host, port_text = authority.rsplit(":", 1)
            port = int(port_text)
            if method != "CONNECT" or version != "HTTP/1.1" or port != 443 or not host:
                raise ValueError("unsupported_connect")
            with socks_connect(host, port, self.server.socks_port) as upstream:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                client.settimeout(None)
                remainder = bytes(request).split(b"\r\n\r\n", 1)[1]
                if remainder:
                    upstream.sendall(remainder)
                sockets = [client, upstream]
                while sockets:
                    ready, _, _ = select.select(sockets, [], [], 600)
                    if not ready:
                        break
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is client else client).sendall(data)
        except (OSError, ValueError, ConnectionError):
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-port", type=int, default=1081)
    parser.add_argument("--socks-port", type=int, default=1080)
    args = parser.parse_args()
    with Server(("127.0.0.1", args.listen_port), Handler) as server:
        server.socks_port = args.socks_port
        server.serve_forever()


if __name__ == "__main__":
    main()
