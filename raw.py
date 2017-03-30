# raw.py

import threading
import queue

import ipv4
import net
from common import *

import logging
log = logging.getLogger(__name__)

class _stat:
    noproto = 0
    rawout = 0

_pcbs = []
_lock = threading.Lock()

class SockError(Exception):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg

class _Socket:
    def __init__(self, proto, IP_HDRINCL):
        self.proto = proto
        self.lip = self.fip = ip4()
        self.IP_HDRINCL = IP_HDRINCL
        self._opt = {}
        self._closed = False
        self._inq = queue.Queue()

    def __repr__(self):
        return ('<RAW socket: proto=%d IP_HDRINCL=%s l_ip=%d f_ip=%d>'
                % (self.proto, self.IP_HDRINCL, self.lip, self.fip))

    def setsockopt(self, **opt):
        self._opt = opt

    def getsockopt(self, ):
        return self._opt

    def bind(self, ip):
        if self._closed:
            raise SockError('socket closed')
        self.lip = ip4(ip)
        return self

    def connect(self, ip):
        if self._closed:
            raise SockError('socket closed')
        self.fip = ip4(ip)

    def send(self, pkt):
        if self._closed:
            raise SockError('socket closed')
        if self.IP_HDRINCL:
            if not isinstance(pkt, ipv4.Pack):
                raise SockError('not a IPv4 packet')
            _stat.rawout += 1
            log.info('SEND %s', pkt)
            ipv4.send_ip(pkt)
        else:
            fip = self.fip
            if not fip:
                raise SockError('foreign address not bound')
            lip = self.lip
            if not lip:
                lip = net.ip_hint(fip)
                if not lip:
                    raise SockError('no route to %s' % fip)
            log.info('SEND %s -> %s, %r', lip, fip, pkt)
            ipv4.send(lip, fip, pkt)

    def sendto(self, ip, pkt):
        if self._closed:
            raise SockError('socket closed')
        if self.fip:
            raise SockError('foreign address already bound')
        if self.IP_HDRINCL:
            raise SockError('calling sendto() with IP_HDRINCL')
        ip = ip4(ip)
        if ip == 0:
            raise SockError('not a valid IP address')
        lip = self.lip
        if not lip:
            lip = net.ip_hint(ip)
            if not lip:
                raise SockError('no route to %s' % ip)
        log.info('SEND %s -> %s, %r', lip, ip, pkt)
        ipv4.send(lip, ip, pkt)

    def eof(self):
        return self._closed and self._inq.qsize() <= 1

    def recv(self, block=True, timeout=None):
        p = self.recvfrom(block, timeout)
        return p if p is None else p[1]

    def recvfrom(self, block=True, timeout=None):
        try:
            p = self._inq.get(block, timeout)
        except queue.Empty:
            return None
        if p is None:
            assert self._closed
            self._inq.put_nowait(None)
        return p

    def close(self):
        self._closed = True
        self._inq.put_nowait(None)
        with _lock:
            _pcbs.remove(self)

    def _recv(self, sip, ippkt):
        self._inq.put_nowait((sip, ippkt))

def socket(proto, IP_HDRINCL=False):
    sock = _Socket(proto, IP_HDRINCL)
    with _lock:
        _pcbs.append(sock)
    return sock

def recv(sip, dip, ip_pkt, handled):
    log.debug('RECV %r', ip_pkt)

    with _lock:
        for s in _pcbs:
            if ((s.proto and s.proto != ip_pkt.proto)
                or (s.lip and dip != s.lip)
                or (s.fip and sip != s.fip)):
                continue
            handled = True
            s._recv(sip, ip_pkt)

    if not handled:
        _stat.noproto += 1
        log.warning('unhandled packet [%s -> %s]: %s', sip, dip, ip_pkt)
