# -*- coding: utf-8 -*-

import threading
import time
import enum

import logging
log = logging.getLogger(__name__)

import arp
import icmp
import udp
import tcp
import raw
import net
from common import *

# IP protocols
@enum.unique
class IPPROT(enum.IntEnum):
    ICMP = 1
    IGMP = 2
    IP = 4
    TCP = 6
    EGP = 8
    UDP = 17
    IPv6 = 41
    RSVP = 46
    OSPF = 89

# default IP settings
_def_ttl = 64
_frags_timeout_interval = 60                 # RFC 1122

# statistics
class _stat:
    rx_count = 0
    rx_fragmented = 0
    rx_dropped = 0
    tx_count = 0
    tx_fragmented = 0
    tx_dropped = 0

# frag buffer
_rx_frags = {}
_fragslock = threading.Lock()

# options

class Opt:
    def __init__(self, kind, val):
        assert kind != 0 and kind != 1
        self.kind = kind
        self.val = val
    def __len__(self):
        return 2 + len(self.val)
    def __repr__(self):
        return '<%d: %d %s>' % (self.kind, len(self), self.val)

    @property
    def Copy(self):
        return bool(self.kind & 0x80)

    @property
    def Class(self):
        return self.kind >> 5 & 0x3

    @property
    def Number(self):
        return self.kind & 0x1f

    @classmethod
    def read(cls, mem, off):
        return cls(mem[off], mem[off+2:off+2+mem[off+1]])

    def write(self, mem, off):
        mem[off] = self.kind
        n = len(self)
        mem[off+1] = n
        mem[off+2:off+2+n] = self.val
        return n + 2

_optclstbl = [Opt] * 256

def option(cls):
    _optclstbl[cls.kind] = cls
    return cls

@option
class OptEol(Opt):
    kind = 0
    def __init__(self):
        pass
    def __len__(self):
        return 1
    def __repr__(self):
        return '<EOL>'
    @classmethod
    def read(cls, mem, off):
        assert mem[off] == 0
        return cls()
    def write(self, mem, off):
        mem[off] = 0
        return 1

@option
class OptNop(Opt):
    kind = 1
    def __init__(self):
        pass
    def __len__(self):
        return 1
    def __repr__(self):
        return '<NOP>'
    @classmethod
    def read(cls, mem, off):
        assert mem[off] == 1
        return cls()
    def write(self, mem, off):
        mem[off] = 1
        return 1

def _readopt(mem, off):
    return _optclstbl[mem[off]].read(mem, off)

class Pack:
    kind = 'IPv4'
    eth_proto = 0x0800

    def __init__(self, src, dst, pdu, *,
                 proto=None, ident=None,
                 ttl=64, E=0, DSCP=0, ECN=0, DF=0, MF=0, offset=0,
                 opts=()):
        self.src = ip4(src)
        self.dst = ip4(dst)
        self.ttl = ttl
        self.DSCP = DSCP
        self.ECN = ECN
        self.E = E
        self.DF = DF
        self.MF = MF
        self.offset = offset
        self.pdu = pdu
        if hasattr(pdu, 'ip_proto'):
            if proto is not None and proto!=pdu.ip_proto:
                raise ValueError('bad argument `proto`')
            proto = pdu.ip_proto
        if ident is None:
            ident = _stat.tx_count
        self.ident = ident
        self.proto = proto
        self.opts = opts
        self._hdr = None

    def __len__(self):
        return (self.opts and 60 or 20) + len(self.pdu)

    def __repr__(self):
        return ('<IPv4 %d: %s -> %s %s %s%s ident=%d%s%s%s%s TTL=%d%s %s>'
                % (len(self), self.src, self.dst,
                   (IPPROT(self.proto).name if self.proto in IPPROT.__members__.values()
                    else 'proto=%d' % self.proto),
                   self.DSCP and (' DSCP=%02x' % self.DSCP) or '',
                   self.ECN and (' ECN=d' % self.ECN) or '',
                   self.ident, self.E and ' \U0001F631' or '',
                   self.DF and ' DF' or '', self.MF and ' MF' or '',
                   self.offset and (' offset=%d' % self.offset) or '',
                   self.ttl, self.opts and (' %s' % self.opts) or '',
                   self.pdu if hasattr(self.pdu, 'pack')
                   else ('len=%d' % len(self.pdu))))

    @property
    def hdr(self):
        if not self._hdr:
            n = self.opts and 60 or 20
            h = bytearray(n)
            h[0] = 4 << 4 | (n >> 2)
            h[1] = self.DSCP << 2 | self.ECN
            w16be(h, 2, len(self))
            w16be(h, 4, self.ident)
            w16be(h, 6, self.E << 15 | self.DF << 14 | self.MF << 13 | self.offset)
            h[8] = self.ttl
            h[9] = self.proto
            w16be(h, 10, 0)     # set checksum to 0
            w32be(h, 12, self.src)
            w32be(h, 16, self.dst)
            off = 20
            for opt in self.opts:
                off += opt.write(h, off)
            self._hdr = h
        return self._hdr

    def pack(self):
        hdr = self.hdr
        w16be(hdr, 10, chksum(hdr))
        if hasattr(self.pdu, 'pack'):
            data = self.pdu.pack(hdr)
        else:
            data = self.pdu
        return hdr + data


class _Pack:
    def __init__(self, raw):
        self._raw = raw

    def __len__(self):
        return len(self.raw)

    def __repr__(self):
        opts = self.options
        proto = self.proto
        off = self.offset
        return ('<IPv4 %d: %s -> %s %s IHL=%d%s%s ident=%d%s%s%s%s TTL=%d%s>'
                % (self.total, self.src, self.dst,
                   (IPPROT(proto).name if proto in IPPROT.__members__.values()
                    else 'proto=%d' % proto),
                   self.IHL,
                   self.DSCP and (' DSCP=%02x' % self.DSCP) or '',
                   self.ECN and (' ECN=d' % self.ECN) or '',
                   self.ident, self.E and ' \U0001F631' or '',
                   self.DF and ' DF' or '', self.MF and ' MF' or '',
                   off and (' offset=%d' % off) or '',
                   self.ttl, opts and (' %s' % opts) or ''))

    @property
    def hdr(self):
        return memoryview(self._raw)[0 : self.IHL*4]

    @property
    def pdu(self):
        return memoryview(self._raw)[self.IHL*4:self.total]

    @property
    def IHL(self):
        return self._raw[0] & 0xf

    @property
    def DSCP(self):
        return self._raw[1] >> 2

    @property
    def ECN(self):
        return self._raw[1] & 0x3

    @property
    def total(self):
        return r16be(self._raw, 2)

    @property
    def ident(self):
        return r16be(self._raw, 4)

    @property
    def E(self):
        return self._raw[6] >> 7 & 1

    @property
    def DF(self):
        return self._raw[6] >> 6 & 1

    @property
    def MF(self):
        return self._raw[6] >> 5 & 1

    @property
    def offset(self):
        return r16be(self._raw, 6) & 0x1fff

    @property
    def ttl(self):
        return self._raw[8]

    @property
    def proto(self):
        return self._raw[9]

    @property
    def src(self):
        return ip4(r32be(self._raw, 12))

    @property
    def dst(self):
        return ip4(r32be(self._raw, 16))

    @property
    def options(self):
        end = self.IHL * 4
        off = 20
        opts = []
        mem = self._raw
        while off < end:
            opt = _readopt(mem, off)
            opts.append(opt)
            off += len(opt)
            if opt.kind == 0:
                break
        return opts


def decode(bs, check_crc=True):
    if isinstance(bs, Pack):
        return bs

    if len(bs) < 20:
        raise DecodeError('packet too short')

    ver = (bs[0] >> 4) & 0xf
    if ver != 4:
        raise DecodeError('bad version')

    nhdr = (bs[0] & 0xf) * 4
    if check_crc and chksum_upto(bs, nhdr) != 0:
        raise DecodeError('bad checksum')

    return _Pack(bs)


# scans frags for timeout
class _Timer(threading.Thread):
    def __init__(self, seconds, fun):
        threading.Thread.__init__(self, name='ipv4', daemon=True)
        self.interval = seconds
        self.fun = fun
        self.stopped = threading.Event()

    def stop(self):
        self.stopped.set()

    def run(self):
        while not self.stopped.wait(self.interval):
            self.fun()

def _frag_timeout():
    now = int(time.time())
    fs = []
    with _fragslock:
        for (i, f) in _rx_frags.items():
            if now > f[3]:
                fs.append((i, f))
        for (i, _) in fs:
            del _rx_frags[i]
            _stat.rx_dropped += 1
    for (i, (_, hdr, _, _)) in fs:
        log.warning('fragment reassembly time exceeded')
        if hdr:
            # TODO: send back ICMP type 11 code 1 with
            # 64 bits of the payload of the first datagram
            pass

def recv(ifc, pkt):
    log.debug('RECV %r', pkt)
    _stat.rx_count += 1
    if pkt.MF or pkt.offset:
        log.info('fragmented packet %s', pkt)
        MF = pkt.MF
        offset = pkt.offset
        ident = pkt.ident
        with _fragslock:
            if not ident in _rx_frags:
                hdr = pkt.hdr if offset == 0 else None
                total = offset * 8 + len(pkt.pdu) if not MF else 0
                _rx_frags[ident] = (total, hdr, [(offset, pkt.pdu)],
                                    int(time.time()) + _frags_timeout_interval)
                return
            (total, hdr, frags, timeo) = _rx_frags[ident]
            if offset == 0:
                if hdr:
                    log.error('duplicated first fragment')
                    del _rx_frags[ident]
                    return
                hdr = pkt.hdr
            if not MF:
                if total != 0:
                    log.error('duplicated last fragment')
                    del _rx_frags[ident]
                    return
                total = offset * 8 + len(pkt.pdu)
            frags.append((offset, pkt.pdu))
            if hdr is None or total == 0:
                # we have not seen enough
                _rx_frags[ident] = (total, hdr, frags, timeo)
                return
            # check if we can reassembly
            remains = total
            for (_, p) in frags:
                remains -= len(p)
            if remains < 0:
                log.error('fragment does not add up!')
                del _rx_frags[ident]
                return
            if remains > 0:
                _rx_frags[ident] = (total, hdr, frags, timeo)
                return
            # we seem to have a complete packet, try reassembly
            del _rx_frags[ident]
            nhdr = len(hdr)
            raw = bytearray(nhdr+total)
            raw[:nhdr] = hdr
            j = 0
            for (i, p) in sorted(frags):
                i *= 8
                if j != i:
                    log.error('fragment offset error!')
                    return
                j += len(p)
                raw[nhdr+i:nhdr+j] = p
            # patch the TotalLength field
            # don't bother with checksum
            w16be(raw, 2, len(raw))
            pkt = _Pack(raw)
            _stat.rx_fragmented += 1
        log.debug('reassembly %r', pkt)

    if pkt.proto == 6:
        tcp.recv(pkt.hdr, pkt.src, pkt.dst, pkt.pdu)
    elif pkt.proto == 17:
        udp.recv(pkt.hdr, pkt.src, pkt.dst, pkt.pdu)
    elif (pkt.proto == 1):
        icmp.recv(ifc, pkt.src, pkt.dst, pkt)
    else:
        raw.recv(pkt.src, pkt.dst, pkt, False)

def send_ip(pkt):
    assert type(pkt) is ipv4.Pack
    # TODO: fragmentation
    if len(pkt) > 1500:
        log.warn('send_ip: sending large packet %s', pkt)
    log.debug('SEND %s', pkt)
    net.send(pkt)

def send(from_ip, to_ip, pdu, **extras):
    if to_ip == 0:
        log.error('target IP cannot be 0!')
        return 0

    if from_ip == 0:
        from_ip = net.ip_hint(to_ip)

    _stat.tx_count += 1

    pac = Pack(from_ip, to_ip, pdu, **extras)

    log.debug('SEND %s', pac)

    # TODO: obtain MTU from the sending interface
    mtu = 1500

    # Fast path - no fragmentation
    if len(pac) <= mtu:
        net.send(pac)
        return 1

    # fragmentation
    if pac.DF:
        # TODO: ICMP error
        log.warning('cannot send large packet with DF set')
        _stat.tx_dropped += 1
        return 0

    _stat.tx_fragmented += 1
    log.info('fragmenting large packet')

    hdr = pac.hdr
    nhdr = len(hdr)
    if hasattr(pdu, 'pack'):
        pdu = pdu.pack(None)
    npdu = len(pdu)

    ps = (mtu - nhdr) >> 3 << 3
    (n, r) = divmod(npdu, ps)
    if r == 0:
        n -= 1

    # send the last frag first
    net.send(Pack(from_ip, to_ip, pdu[n * ps:],
                  DSCP=pac.DSCP, ECN=pac.ECN,
                  proto=pac.proto, ttl=pac.ttl, ident=pac.ident,
                  MF=0, offset=n*ps>>3,
                  opts=tuple(opt for opt in pac.opts if opt.Copy)))

    # send remaining frags in reversed order
    while n > 0:
        n -= 1
        offset = n * ps
        net.send(Pack(from_ip, to_ip, pdu[offset:offset+ps],
                      DSCP=pac.DSCP, ECN=pac.ECN,
                      proto=pac.proto, ttl=pac.ttl, ident=pac.ident,
                      MF=1, offset=offset>>3,
                      opts=tuple(opt for opt in pac.opts if n==0 or opt.Copy)))

    return 1

_tmo = _Timer(_frags_timeout_interval, _frag_timeout)

def shutdown():
    _tmo.stop()
    _rx_frags.clear()

def start():
    _tmo.start()
