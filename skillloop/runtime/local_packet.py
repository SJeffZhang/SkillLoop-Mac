"""One authenticated local packet exchange under one original deadline."""
import math
import socket
import struct
import threading
import time


def exchange_packet(path, raw, *, timeout, expected_server_uid, maximum_bytes):
    if (type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=10
            or type(raw) is not bytes or not 0<len(raw)<=262144
            or type(maximum_bytes) is not int or not 1<=maximum_bytes<=262145
            or expected_server_uid is not None and
                (type(expected_server_uid) is not int or expected_server_uid<0)):
        raise ValueError('local_packet_original_limits')
    if expected_server_uid is not None and not hasattr(socket,'SO_PEERCRED'):
        raise PermissionError('local_packet_kernel_identity_unavailable')
    end=time.monotonic()+timeout
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as connection:
        expired=threading.Event()
        def interrupt():
            expired.set()
            try:connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        timer=threading.Timer(timeout,interrupt);timer.daemon=True;timer.start()
        def remaining():
            left=end-time.monotonic()
            if left<=0 or expired.is_set():raise TimeoutError('local_packet_original_deadline')
            connection.settimeout(left)
        try:
            remaining();connection.connect(str(path))
            if expected_server_uid is not None:
                peer=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if peer[1]!=expected_server_uid:
                    raise PermissionError('local_packet_server_identity_mismatch')
            # Identity is verified before any private material or request leaves.
            remaining();connection.sendall(raw)
            remaining();reply,_,flags,_=connection.recvmsg(maximum_bytes+1)
            remaining()
            if not reply or len(reply)>maximum_bytes or flags&socket.MSG_TRUNC:
                raise ConnectionError('local_packet_response_incomplete_or_exceeded')
            return reply
        finally:
            timer.cancel();timer.join()
