# -*- coding: utf-8 -*-

'''DNS - host name to IP address resolver.'''

import collections
import enum
import random

import udp
from common import *
import logging

servers = []

class Qr(enum.IntEnum):
    Q = 0
    R = 1

class Opc(enum.IntEnum):
    QUERY = 0
    IQUERY = 1
    STATUS = 2
    NOTIFY = 4
    UPDATE = 5

class RCode(enum.IntEnum):
    NOERR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5
    YXDOMAIN = 6
    YXRRSET = 7
    NXRRSET = 8
    NOTAUTH = 9
    NOTZONE = 10

class RRT(enum.IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    HINFO = 13
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33

class RRC(enum.IntEnum):
    IN = 1
    CHAOS = 3
    HESIOD = 4
    ANY = 255

QR = collections.namedtuple('QR', 'nam typ cls')
RR = collections.namedtuple('RR', 'nam typ cls ttl data')

def mkquery(ident, name):
    pac = bytearray(12 + len(name) + 2 + 4)
    w16be(pac, ident, 0)
    pac[2] = 0x01           # RD
    pac[5] = 0x01           # 1 question
    off = 12
    for label in name.split('.'):
        bs = label.encode()
        n = len(bs)
        pac[off] = n
        off += 1
        pac[off:off+n] = bs
        off += n
    pac[off] = 0
    w16be(pac, off+1, RRT.A)
    w16be(pac, off+3, RRC.IN)
    return pac

def read_name(mem, off):
    ptr = None
    def label(off, acc):
        nonlocal ptr
        n = mem[off]
        if n == 0:
            return (off + 1, acc)
        if n >= 192:
            if ptr is None:
                ptr = off
            return label(r16be(mem, off) & 0x3fff, acc)
        acc.append(mem[off+1:off+n+1])
        return label(off+n+1, acc)
    off, acc = label(off, [])
    return (off if ptr is None else ptr + 2,
            '.'.join(bytes(l).decode() for l in acc))

def read_query(mem, off):
    off, nam = read_name(mem, off)
    typ = r16be(mem, off)
    cls = r16be(mem, off+2)
    return (off + 4, QR(nam, RRT(typ), RRC(cls)))

def read_rr(mem, off):
    off, qr = read_query(mem, off)
    ttl = r32be(mem, off)
    off += 4
    dlen = r16be(mem, off)
    off += 2
    return (off+dlen, RR(qr.nam, qr.typ, qr.cls, ttl, mem[off:off+dlen]))

class Response:
    def __init__(self, raw):
        self._raw = raw

    def __repr__(self):
        return ('<DNS_%s: id=%d opc=%s %srcode=%s %s>'
                % (self.QR.name, self.ident, self.opc.name, self.flagstr(),
                   self.rcode.name, self.QRs))

    def flagstr(self):
        flags = []
        if self.AA:
            flags.append('AA')
        if self.TC:
            flags.append('TC')
        if self.RD:
            flags.append('RD')
        if self.RA:
            flags.append('RA')
        if flags:
            return ' '.join(flags) + ' '
        return ''

    @classmethod
    def decode(cls, raw):
        if len(raw) < 12:
            return None
        return cls(raw)

    @property
    def ident(self):
        return r16be(self._raw, 0)

    @property
    def QR(self):
        return Qr(self._raw[2] >> 7)

    @property
    def opc(self):
        return Opc((self._raw[2] >> 3) & 0xf)

    @property
    def AA(self):
        return (self._raw[2] >> 2) & 0x1

    @property
    def TC(self):
        return (self._raw[2] >> 1) & 0x1

    @property
    def RD(self):
        return self._raw[2] & 0x1

    @property
    def RA(self):
        return self._raw[3] >> 7

    @property
    def rcode(self):
        return RCode(self._raw[3] & 0xf)

    @rcode.setter
    def rcode(self, val):
        self._raw[3] = (self._raw[3] & ~0xf0) | val

    @property
    def qdcount(self):
        return r16be(self._raw, 4)

    @property
    def ancount(self):
        return r16be(self._raw, 6)

    @property
    def nscount(self):
        return r16be(self._raw, 8)

    @property
    def arcount(self):
        return r16be(self._raw, 10)

    @property
    def QRs(self):
        off = 12

        qrs = []
        for i in range(self.qdcount):
            off, res = read_query(self._raw, off)
            qrs.append(res)

        ans = []
        for i in range(self.ancount):
            off, res = read_rr(self._raw, off)
            ans.append(res)

        nss = []
        for i in range(self.nscount):
            off, res = read_rr(self._raw, off)
            nss.append(res)

        ars = []
        for i in range(self.arcount):
            off, res = read_rr(self._raw, off)
            ars.append(res)

        return (qrs, ans, nss, ars)

# TODO: negative results
_cache = {}

def gethostbyname(hostname, timeout=5):
    sock = udp.socket()
    try:
        for sip in servers:
            ident = random.getrandbits(16)
            sock.sendto((sip, 53), mkquery(ident, hostname))
            res = sock.recv(timeout=timeout)
            if res is None:
                continue
            res = Response.decode(res)
            if res is None:
                continue
            #if res.ident != ident:
            #    continue
            if res.QR != Qr.R:
                continue
            if res.rcode != RCode.NOERR:
                continue
            # only look at the answers reccord, skip auth/extra RRs
            # TODO: alias
            for r in res.QRs[1]:
                if r.typ == RRT.A and r.cls == RRC.IN:
                    _cache.setdefault(hostname, []).append(ip4(r.data))
    finally:
        sock.close()

    if hostname in _cache:
        return _cache[hostname][0]
    return None

# TODO
def gethostbyaddr(hostip, timeout=5):
    return None
