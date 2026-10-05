"""Small Docker Engine client for trusted controllers only."""
from __future__ import annotations
import http.client,json,math,socket,threading
from urllib.parse import quote

class DockerEngineError(RuntimeError):
    """An actual HTTP rejection, distinct from an unknown transport outcome."""
    def __init__(self,status,detail):
        self.status=status
        super().__init__('docker_engine_'+str(status)+':'+detail)

class DockerEngine:
    def __init__(self,socket_path='/var/run/docker.sock'):
        self.socket_path=socket_path
    def request(self,method,path,body=None,*,timeout=30,raw=False,maximum_response_bytes=None):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or timeout<=0:
            raise ValueError('docker_request_deadline')
        if maximum_response_bytes is None:
            if raw:raise ValueError('docker_response_capacity_required')
            maximum_response_bytes=2097152
        if type(maximum_response_bytes) is not int or maximum_response_bytes<1:
            raise ValueError('docker_response_capacity')
        connection=http.client.HTTPConnection('localhost',timeout=timeout)
        transport=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        connection.sock=transport
        expired=threading.Event()
        def expire():
            expired.set()
            # Shutdown the original socket even when HTTPResponse holds a makefile
            # reference. A per-read timeout alone does not bound a trickling body.
            try:transport.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        watchdog=threading.Timer(timeout,expire)
        watchdog.daemon=True
        watchdog.start()
        try:
            connection.sock.settimeout(timeout);connection.sock.connect(self.socket_path)
            encoded=body if isinstance(body,bytes) else json.dumps(body).encode() if body is not None else None
            connection.request(method,path,body=encoded,headers={'Content-Type':'application/json'})
            response=connection.getresponse()
            declared=response.getheader('Content-Length')
            if declared is not None and (int(declared)<0 or int(declared)>maximum_response_bytes):
                raise ValueError('docker_response_capacity')
            data=response.read(maximum_response_bytes+1)
            if expired.is_set():raise TimeoutError('docker_request_deadline')
            if len(data)>maximum_response_bytes:raise ValueError('docker_response_capacity')
            if declared is not None and len(data)!=int(declared):
                raise ConnectionError('docker_response_incomplete')
            if response.status>=300:raise DockerEngineError(response.status,data.decode(errors='replace')[:400])
            return data if raw else json.loads(data) if data else None
        except Exception as error:
            if expired.is_set():raise TimeoutError('docker_request_deadline') from error
            raise
        finally:
            watchdog.cancel();watchdog.join()
            connection.close()
    def create_volume(self,name,*,driver_options=None,labels=None,timeout=30):
        body={'Name':name}
        if driver_options is not None:body.update(Driver='local',DriverOpts=driver_options)
        if labels is not None:body['Labels']=labels
        return self.request('POST','/volumes/create',body,timeout=timeout)
    def inspect_volume(self,name,*,timeout=30):return self.request('GET','/volumes/'+quote(name,safe=''),timeout=timeout)
    def create(self,name,config,*,timeout=30):return self.request('POST','/containers/create?name='+quote(name),config,timeout=timeout)['Id']
    def start(self,identifier,*,timeout=30):self.request('POST','/containers/'+identifier+'/start',timeout=timeout)
    def wait(self,identifier,timeout):return self.request('POST','/containers/'+identifier+'/wait?condition=not-running',timeout=timeout)
    def inspect(self,identifier,*,timeout=30):return self.request('GET','/containers/'+identifier+'/json',timeout=timeout)
    def archive(self,identifier,path,*,maximum_bytes=None):return self.request('GET','/containers/'+identifier+'/archive?path='+quote(path,safe=''),raw=True,maximum_response_bytes=maximum_bytes)
    def remove(self,identifier):self.request('DELETE','/containers/'+identifier+'?force=true&v=true')
    def remove_volume(self,name):self.request('DELETE','/volumes/'+quote(name))

    def logs(self,identifier,*,maximum_bytes=1048576,timeout=30):
        raw=self.request('GET','/containers/'+identifier+'/logs?stdout=1&stderr=1',raw=True,maximum_response_bytes=maximum_bytes,timeout=timeout)
        output=bytearray();offset=0
        while offset<len(raw):
            if len(raw)-offset<8:raise ValueError('invalid_docker_log_frame')
            size=int.from_bytes(raw[offset+4:offset+8],'big');offset+=8
            if offset+size>len(raw):raise ValueError('invalid_docker_log_frame')
            output.extend(raw[offset:offset+size]);offset+=size
        return bytes(output)
