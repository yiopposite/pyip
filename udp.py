# udp.py

import threading
import queue

import logging
log = logging.getLogger('udp')

import ipv4
import icmp
import net
from common import *

class _stat:
    rx_count = 0
    rx_dropped = 0
    rx_unreach = 0
    tx_count = 0
    tx_dropped = 0

_pcbs = []
_pcbs_lock = threading.Lock()

class Pack:
    kind = 'UDP'
    ip_proto = 17

    def __init__(self, sport=None, dport=None, data=None, _raw=None):
        self._raw = _raw
        if _raw is None:
            self._hdr = bytearray(8)
            if isinstance(data, str):
                data = data.decode()
            self._data = data
            self.sport = sport
            self.dport = dport
            self.length = 8 + len(data)
        else:
            if any(p is not None for p in (sport, dport, data)):
                raise ValueError('_raw with arguments')

    def __len__(self):
        return 8 + len(self.data)

    def __repr__(self):
        return ('<UDP: src=%d dst=%d len=%d%s>'
                % (self.sport, self.dport, len(self) - 8,
                   ' %s' % self.data if hasattr(self.data, 'pack') else ''))

    @property
    def sport(self):
        return r16be(self._raw or self._hdr, 0)

    @sport.setter
    def sport(self, val):
        w16be(self._raw or self._hdr, 0, val)

    @property
    def dport(self):
        return r16be(self._raw or self._hdr, 2)

    @dport.setter
    def dport(self, val):
        w16be(self._raw or self._hdr, 2, val)

    @property
    def length(self):
        return r16be(self._raw or self._hdr, 4)

    @length.setter
    def length(self, val):
        w16be(self._raw or self._hdr, 4, val)

    @property
    def checksum(self):
        return r16be(self._raw or self._hdr, 6)

    @checksum.setter
    def checksum(self, val):
        w16be(self._raw or self._hdr, 6, val)

    @property
    def data(self):
        if self._raw:
            return memoryview(self._raw)[8:]
        else:
            return self._data

    @data.setter
    def data(self, val):
        if self._raw:
            self._raw[8:] = val
        else:
            self._data = val
        self.length = 8 + len(self.data)

    def pack(self, iphdr=None):
        if self._raw:
            return self._raw
        ba = bytearray(len(self))
        ba[:8] = self._hdr
        if hasattr(self.data, 'pack'):
            ba[8:] = self.data.pack()
        else:
            ba[8:] = self.data
        if iphdr:
            w16be(ba, 6, 0)
            w16be(ba, 6, chksum_iphdr2(17, iphdr, ba))
        return ba

def decode(bs, ip_hdr=None):
    # idempotent
    if isinstance(bs, Pack):
        return bs
    if len(bs) < 8:
        raise DecodeError('datagram too short')
    if ip_hdr:
        checksum = r16be(bs, 6)
        if checksum != 0:
            if chksum_iphdr2(17, ip_hdr, bs) != 0:
                raise DecodeError('checksum errors')
        else:
            log.info("packet w/o checksum (%s -> %s)",
                     ip4(ip_hdr, 12), ip4(ip_hdr, 16))
    return Pack(_raw=bs)

# IANA: 49152 to 65535
# TODO: a simplistic implementation that will overflow
_ephemeral_port = 49152

def _alloc_port():
    global _ephemeral_port
    with _pcbs_lock:
        p = _ephemeral_port
        _ephemeral_port += 1
    assert p <= 65535
    return p

class SockError(Exception):
    def __init__(self, sock, msg):
        self.sock = sock
        self.msg = msg
    def __str__(self):
        return '%s: %s' % (self.sock, self.msg)

class _Socket:
    def __init__(self, blocking, timeout):
        self.blocking = blocking
        self.timeout = timeout
        self.laddr = None
        self.faddr = None
        self._opt = {}
        self._closed = False
        # Using queue to have the blocking/timeout semantic for free.
        # Note: infinite capacity of the input queue
        self._inq = queue.Queue()

    def __repr__(self):
        return '[%s:%s]' % (self.laddr, self.faddr)
    def setsockopt(self, **opt):
        self._opt = opt

    def getsockopt(self):
        return self._opt

    def bind(self, laddr):
        if self._closed:
            raise SockError('socket closed')
        if self.laddr is not None:
            raise SockError(self, 'sock already bound')
        ip, port = laddr
        ip = ip4(ip)
        # local ip/port can both be 0
        if not 0 <= port <= 65535:
            raise SockError(self, 'invalid port number %d' % port)
        if ip and not net.is_local_ip(ip):
            raise SockError(self, 'error binding to %s' % ip)
        laddr = sockaddr(ip, port)
        with _pcbs_lock:
            # Cannot have two sockets bound to the same port number
            # even when they have different local ip addresses.
            if any(s.laddr.port == port for s in _pcbs):
                raise SockError(self, 'port %d already in use' % port)
            self.laddr = laddr
            _pcbs.append(self)
        return self

    def connect(self, faddr):
        if self.faddr is not None:
            raise SockError(self, 'foreign address already bound')
        self.faddr = self._connect(faddr)

    def _connect(self, faddr):
        if self._closed:
            raise SockError('socket closed')
        ip, port = faddr
        ip = ip4(ip)
        # foreign ip/port cannot be 0
        if not 0 < port <= 65535:
            raise SockError(self, 'invalid port number %d' % port)
        if ip == 0:
            raise SockError(self, 'invalid ip address %s' % ip)
        return sockaddr(ip, port)

    def _bind(self):
        if self._closed:
            raise SockError('socket closed')
        if self.laddr is None:
            self.bind((0, _alloc_port()))
        assert self.laddr
        return self.laddr

    def send(self, data):
        if self.faddr is None:
            raise SockError('foreign address not bound')
        assert self.faddr[0] and self.faddr[1]
        send(self._bind(), self.faddr, data, self._opt)

    def sendto(self, addr, data):
        if self.faddr:
            raise SockError('foreign address already bound')
        send(self._bind(), self._connect(addr), data, self._opt)

    def eof(self):
        return self._closed and self._inq.qsize() <= 1

    def recv(self, block=True, timeout=None):
        p = self.recvfrom(block, timeout)
        return p if p is None else p[1]

    def recvfrom(self, block=None, timeout=None):
        if block is None:
            block = self.blocking
        if timeout is None:
            timeout = self.timeout
        try:
            msg = self._inq.get(block, timeout)
        except queue.Empty:
            return None

        if msg is None:
            # closed
            self._inq.put_nowait(None)
        return msg

    def _recv(self, sip, dip, pkt):
        # dip is lost here
        self._inq.put(((sip, pkt.sport), pkt.data))

    def close(self):
        self._closed = True
        self._inq.put_nowait(None)
        with _pcbs_lock:
            if self in _pcbs:
                _pcbs.remove(self)

def socket(blocking=True, timeout=None):
    return _Socket(blocking, timeout)

def send(laddr, faddr, data, opts):
    pkt = Pack(laddr.port, faddr.port, data)
    log.debug('SEND %s', pkt)
    _stat.tx_count += 1
    return ipv4.send(laddr.ip, faddr.ip, pkt, **opts)

def notify(sip, icmppkt, ippkt):
    assert isinstance(icmppkt, icmp.Pack)
    try:
        pac = decode(ippkt.pdu)
    except DecodeError as e:
        log.error('cannot retrive the offending datagram from'
                  ' ICMP packet: %s', e)
        return
    # TODO
    log.warning('ICMP from %s: %s, original packet: %s', sip, icmppkt, ippkt)

def recv(iphdr, sip, dip, pdu):
    log.debug('RECV %s -> %s: %s', sip, dip, pdu)
    try:
        pkt = decode(pdu, iphdr)
    except DecodeError as e:
        log.warn('dropping bad packet: %s', e)
        _stat.rx_dropped += 1
        return

    with _pcbs_lock:
        for s in _pcbs:
            if s.laddr.ip != 0 and dip != s.laddr.ip:
                continue
            if s.laddr.port == 0 or s.laddr.port != pkt.dport:
                continue
            s._recv(sip, dip, pkt)
            _stat.rx_count += 1
            return

    if (pkt.sport != 0
        and not dip.is_multicast()
        and sip.is_single_host()):
        log.info('port %d unavailable', pkt.dport)
        icmp.send(dip, sip,
                  icmp.Pack.Unreach(icmp.UNREACH_PORT,
                                    (iphdr + pkt.pack())[:icmp.return_data_bytes]))
        _stat.rx_unreach += 1
    elif not (sip == 0 and dip.is_broadcast()):
        log.warn('packet dropped: %s', pkt)
        _stat.rx_dropped += 1
