"""Loopback DNS forwarder using AliDNS HTTPS over the migration tunnel."""
import socketserver
import struct
import threading
import urllib.request

DOMAINS = ('ollama.ai', 'ollama.com', 'docker.com', 'pypi.org',
           'pythonhosted.org', 'huggingface.co', 'hf.co',
           'dd20bb891979d25aebc8bec07b2b3bbc.r2.cloudflarestorage.com')

def answer(query):
    if len(query) < 17 or struct.unpack('!H', query[4:6])[0] != 1:
        raise ValueError('invalid_dns_query')
    offset, labels = 12, []
    while query[offset]:
        size = query[offset]
        if size > 63 or offset + size + 1 >= len(query):
            raise ValueError('invalid_dns_name')
        labels.append(query[offset + 1:offset + size + 1].decode('ascii'))
        offset += size + 1
    domain = '.'.join(labels).lower()
    if not any(domain == suffix or domain.endswith('.' + suffix) for suffix in DOMAINS):
        raise ValueError('domain_not_allowed')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(
        {'https': 'http://127.0.0.1:1081'}))
    req = urllib.request.Request('https://dns.alidns.com/dns-query', data=query,
        headers={'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message'})
    with opener.open(req, timeout=10) as response:
        data = response.read(65536)
    if len(data) < 12 or data[:2] != query[:2]:
        raise ValueError('invalid_dns_response')
    return data

def failure(query):
    return query[:2] + struct.pack('!5H', 0x8182, 0, 0, 0, 0)

class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        try:
            data = answer(query)
        except Exception:
            data = failure(query)
        sock.sendto(data, self.client_address)

class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        def read(count):
            data = b''
            while len(data) < count:
                block = self.request.recv(count - len(data))
                if not block:
                    raise ConnectionError('short_dns_query')
                data += block
            return data
        try:
            query = read(struct.unpack('!H', read(2))[0])
            try:
                data = answer(query)
            except Exception:
                data = failure(query)
            self.request.sendall(struct.pack('!H', len(data)) + data)
        except (OSError, ValueError):
            pass

class UDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True

class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == '__main__':
    with UDPServer(('127.0.0.1', 1053), UDP) as udp, TCPServer(('127.0.0.1', 1053), TCP) as tcp:
        threading.Thread(target=tcp.serve_forever, daemon=True).start()
        udp.serve_forever()
