"""Small Docker Engine client for trusted controllers only."""
from __future__ import annotations
import http.client,json,socket
from urllib.parse import quote

class DockerEngine:
    def __init__(self,socket_path='/var/run/docker.sock'):
        self.socket_path=socket_path
    def request(self,method,path,body=None,*,timeout=30,raw=False):
        connection=http.client.HTTPConnection('localhost',timeout=timeout)
        connection.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            connection.sock.settimeout(timeout);connection.sock.connect(self.socket_path)
            encoded=body if isinstance(body,bytes) else json.dumps(body).encode() if body is not None else None
            connection.request(method,path,body=encoded,headers={'Content-Type':'application/json'})
            response=connection.getresponse();data=response.read()
            if response.status>=300:raise RuntimeError('docker_engine_'+str(response.status)+':'+data.decode(errors='replace')[:400])
            return data if raw else json.loads(data) if data else None
        finally:connection.close()
    def create_volume(self,name):return self.request('POST','/volumes/create',{'Name':name})
    def create(self,name,config):return self.request('POST','/containers/create?name='+quote(name),config)['Id']
    def start(self,identifier):self.request('POST','/containers/'+identifier+'/start')
    def wait(self,identifier,timeout):return self.request('POST','/containers/'+identifier+'/wait?condition=not-running',timeout=timeout)
    def inspect(self,identifier):return self.request('GET','/containers/'+identifier+'/json')
    def archive(self,identifier,path):return self.request('GET','/containers/'+identifier+'/archive?path='+quote(path,safe=''),raw=True)
    def remove(self,identifier):self.request('DELETE','/containers/'+identifier+'?force=true&v=true')
    def remove_volume(self,name):self.request('DELETE','/volumes/'+quote(name))

    def logs(self,identifier):
        raw=self.request('GET','/containers/'+identifier+'/logs?stdout=1&stderr=1',raw=True)
        output=bytearray();offset=0
        while offset<len(raw):
            if len(raw)-offset<8:raise ValueError('invalid_docker_log_frame')
            size=int.from_bytes(raw[offset+4:offset+8],'big');offset+=8
            if offset+size>len(raw):raise ValueError('invalid_docker_log_frame')
            output.extend(raw[offset:offset+size]);offset+=size
        return bytes(output)
