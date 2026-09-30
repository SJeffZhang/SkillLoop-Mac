import json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from skillloop.runtime.gateway import OllamaGateway

class Tokenizer:
    def count(self,*args,**kwargs):return 10

class SocketGatewayTests(unittest.TestCase):
    def test_unix_transport_has_no_tcp_fallback(self):
        gateway=OllamaGateway('http://127.0.0.1:11434',Tokenizer(),template_overhead_tokens=0,unix_socket_path='/model-bridge/model.sock')
        with patch('urllib.request.urlopen',side_effect=AssertionError('TCP forbidden')):
            with self.assertRaisesRegex(Exception,'provider_timeout'):
                gateway.complete([],[],remaining_seconds=1)
