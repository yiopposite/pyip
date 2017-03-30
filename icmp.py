# -*- coding: utf-8 -*-
'''ICMPv4'''

from datetime import datetime, date

import net
import ipv4
import udp
import tcp
import raw
from common import *

import logging
log = logging.getLogger(__name__)

# global IP setting
return_data_bytes = 64

# statistics
class _stat:
    rx_count = 0
    rx_dropped = 0
    tx_count = 0
    tx_dropped = 0

ICMP_ECHOREPLY = 0
ICMP_UNREACH = 3
ICMP_SOURCEQUENCH = 4
ICMP_REDIRECT = 5
ICMP_ECHO = 8
ICMP_ROUTEADVENT = 9
ICMP_ROUTESOLICIT = 10
ICMP_TIMXCEED = 11
ICMP_PARAMPROB = 12
ICMP_TS = 13
ICMP_TSREPLY = 14
ICMP_IREQ = 15
ICMP_IREQREPLY = 16
ICMP_MASKREQ = 17
ICMP_MASKREPLY = 18

UNREACH_NET = 0
UNREACH_HOST = 1
UNREACH_PROTOCAL = 2
UNREACH_PORT = 3
UNREACH_NEEDFRAG = 4
UNREACH_SRCFAIL = 5
UNREACH_NET_UNKNOWN = 6
UNREACH_HOST_UNKNOWN = 7
UNREACH_HOST_ISOLATED = 8
UNREACH_NET_PROHIB = 9
UNREACH_HOST_PROHIB = 10
UNREACH_TOSNET = 11
UNREACH_TOSHOST = 12
UNREACH_ADMIN_PROHIB = 13
UNREACH_HOSTPREC = 14
UNREACH_PREC_CUTOFF = 15

REDIRECT_NET = 0
REDIRECT_HOST = 1
REDIRECT_TOSNET = 2
REDIRECT_TOSHOST = 3

TIMXCEED_INTRANS = 0
TIMXCEED_REASS = 1

PARAMPROB_IPBAD = 0
PARAMPROB_OPTABSENT = 1

enum_convert('Type', __name__, lambda c: c.startswith('ICMP_'))
enum_convert('Unreach', __name__, lambda c: c.startswith('UNREACH_'))
enum_convert('Redirect', __name__, lambda c: c.startswith('REDIRECT_'))
enum_convert('Timxceed', __name__, lambda c: c.startswith('TIMXCEED_'))
enum_convert('Paramprob', __name__, lambda c: c.startswith('PARAMPROB_'))

class Pack:
    kind = 'ICMP'
    ip_proto = 1

    def __init__(self, type=0, code=0, _raw=None, **args):
        if _raw is not None:
            # called from recv()
            if type or code or args:
                raise ValueError('_raw with arguments')
            if len(_raw) < 8:
                raise DecodeError('packet too short')
            crc = r16be(_raw, 2)
            if crc and chksum(_raw) != 0:
                raise DecodeError('checksum errors')
            self._pac = _raw
        else:
            size = 8
            if 'data' in args:
                size += len(args['data'])
            if type == ICMP_TS or type == ICMP_TSREPLY:
                size += 12
            if type == ICMP_MASKREQ or type == ICMP_MASKREPLY:
                size += 4
            self._pac = bytearray(size)
            self.type = type
            self.code = code
            for (k, v) in args.items():
                setattr(self, k, v)

    def __len__(self):
        return len(self._pac)

    def __repr__(self):
        return '<%s>' % self._repr_impl()

    @classmethod
    def EchoReply(cls, id, seq, data):
        return cls(ICMP_ECHOREPLY, 0, id=id, seq=seq, data=data)

    @classmethod
    def Echo(cls, id, seq, data):
        return cls(ICMP_ECHO, 0, id=id, seq=seq, data=data)

    @classmethod
    def MaskRequest(cls, id, seq, mask=0):
        return cls(ICMP_MASKREQ, 0, id=id, seq=seq, addrmask=mask)

    @classmethod
    def MaskReply(cls, id, seq, mask):
        return cls(ICMP_MASKREPLY, 0, id=id, seq=seq, addrmask=mask)

    @classmethod
    def TimestampRequest(cls, id, seq, orig, recv, xmit):
        return cls(ICMP_TS, 0, id=id, seq=seq,
                   origtime=orig, recvtime=recv, xmittime=xmit)

    @classmethod
    def TimestampReply(cls, id, seq, orig, recv, xmit):
        return cls(ICMP_TSREPLY, 0, id=id, seq=seq,
                   origtime=orig, recvtime=recv, xmittime=xmit)

    @classmethod
    def Unreach(cls, code, data, nhmtu=0):
        pac = cls(ICMP_UNREACH, code, data=data)
        if code == UNREACH_NEEDFRAG and nhmtu:
            pac.nhmtu = nhmtu
        return pac

    @property
    def length(self):
        return len(self) - 8

    @property
    def type(self):
        return self._pac[0]

    @type.setter
    def type(self, val):
        self._pac[0] = val

    @property
    def code(self):
        return self._pac[1]

    @code.setter
    def code(self, val):
        self._pac[1] = val

    @property
    def data(self):
        return memoryview(self._pac)[8:]

    @data.setter
    def data(self, val):
        self._pac[8:] = val

    @property
    def id(self):
        if self.type in (ICMP_ECHO, ICMP_ECHOREPLY,
                         ICMP_MASKREQ, ICMP_MASKREPLY,
                         ICMP_TS, ICMP_TSREPLY):
            return r16be(self._pac, 4)
        raise TypeError('`id` nonexists in %s' % self.type)

    @id.setter
    def id(self, val):
        if not self.type in (ICMP_ECHO, ICMP_ECHOREPLY,
                             ICMP_MASKREQ, ICMP_MASKREPLY,
                             ICMP_TS, ICMP_TSREPLY):
            raise TypeError('`id` nonexists in %s' % self.type)
        w16be(self._pac, 4, val)

    @property
    def seq(self):
        if self.type in (ICMP_ECHO, ICMP_ECHOREPLY,
                         ICMP_MASKREQ, ICMP_MASKREPLY,
                         ICMP_TS, ICMP_TSREPLY):
            return r16be(self._pac, 6)
        raise TypeError('`seq` nonexists in %s' % self.type)

    @seq.setter
    def seq(self, val):
        if not self.type in (ICMP_ECHO, ICMP_ECHOREPLY,
                             ICMP_MASKREQ, ICMP_MASKREPLY,
                             ICMP_TS, ICMP_TSREPLY):
            raise TypeError('`seq` nonexists in %s' % self.type)
        w16be(self._pac, 6, val)

    @property
    def nhmtu(self):
        if self.type == ICMP_UNREACH and self.code == UNREACH_NEEDFRAG:
            return r16be(self._pac, 6)
        raise TypeError('`nhmtu` nonexists in %s' % self.type)

    @nhmtu.setter
    def nhmtu(self, val):
        if not (self.type == ICMP_UNREACH and self.code == UNREACH_NEEDFRAG):
            raise TypeError('`nhmtu` nonexists in %s' % self.type)
        w16be(self._pac, 6, val)

    @property
    def gwaddr(self):
        if self.type == ICMP_REDIRECT:
            return ip4(self._pac, 4)
        raise TypeError('`gwaddr` nonexists in %s' % self.type)

    @gwaddr.setter
    def gwaddr(self, val):
        if self.type != ICMP_REDIRECT:
            raise TypeError('`gwaddr` nonexists in %s' % self.type)
        w32be(self._pac, 4, val)

    @property
    def origtime(self):
        t = self.type
        if t == ICMP_TSREPLY or t == ICMP_TS:
            return r32be(self._pac, 8)
        raise TypeError('`origtime` nonexists in %s' % self.type)

    @origtime.setter
    def origtime(self, val):
        t = self.type
        if not (t == ICMP_TSREPLY or t == ICMP_TS):
            raise TypeError('`origtime` nonexists in %s' % self.type)
        w32be(self._pac, 8, val)

    @property
    def recvtime(self):
        t = self.type
        if t == ICMP_TSREPLY or t == ICMP_TS:
            return r32be(self._pac, 12)
        raise TypeError('`recvtime` nonexists in %s' % self.type)

    @recvtime.setter
    def recvtime(self, val):
        t = self.type
        if not (t == ICMP_TSREPLY or t == ICMP_TS):
            raise TypeError('`recvtime` nonexists in %s' % self.type)
        w32be(self._pac, 12, val)

    @property
    def xmittime(self):
        t = self.type
        if t == ICMP_TSREPLY or t == ICMP_TS:
            return r32be(self._pac, 16)
        raise TypeError('`xmittime` nonexists in %s' % self.type)

    @xmittime.setter
    def xmittime(self, val):
        t = self.type
        if not (t == ICMP_TSREPLY or t == ICMP_TS):
            raise TypeError('`xmittime` nonexists in %s' % self.type)
        w32be(self._pac, 16, val)

    @property
    def addrmask(self):
        t = self.type
        if t == ICMP_MASKREQ or t == ICMP_MASKREPLY:
            return ip4(self._pac, 8)
        raise TypeError('`addrmask` nonexists in %s' % self.type)

    @addrmask.setter
    def addrmask(self, val):
        t = self.type
        if not (t == ICMP_MASKREQ or t == ICMP_MASKREPLY):
            raise TypeError('`addrmask` nonexists in %s' % self.type)
        import sys
        w32be(self._pac, 8, val)

    def _repr_impl(self):
        if self.type in (ICMP_ECHO, ICMP_ECHOREPLY):
            return ('%s: id=%d seq=%d len=%d'
                    % (Type(self.type).name, self.id, self.seq, self.length))

        elif self.type == ICMP_SOURCEQUENCH:
            return ('%s: %s'% (Type(self.type).name, self.data))

        elif self.type == ICMP_REDIRECT:
            return ('ICMP_%s: gw=%s iphdr=%s'
                    % (Redirect(self.code).name, self.gwaddr, self.data))

        elif self.type == ICMP_TIMXCEED:
            return ('ICMP_%s: %s'
                    % (Timxceed(self.code).name, self.data))

        elif self.type == ICMP_PARAMPROB:
            return ('ICMP_%s: len=%d' % (Paramprob(self.code).name, self.length))

        elif self.type == ICMP_UNREACH:
            return ('ICMP_%s: %s'
                    % (Unreach(self.code).name,  self.data))

        elif self.type in (ICMP_MASKREPLY, ICMP_MASKREQ):
            return ('%s: id=%d seq=%d addrmask=%s'
                    % (Type(self.type).name, self.id, self.seq, self.addrmask))

        elif self.type in (ICMP_TS, ICMP_TSREPLY):
            return ('%s: id=%d seq=%d ts=%d,%d,%d'
                    % (Type(self.type).name, self.id, self.seq,
                       self.origtime, self.recvtime, self.xmittime))
        else:
            return ('ICMP (type=%d code=%d): len=%d'
                    % (self.type, self.code, self.length))
        
    def pack(self, _):
        w16be(self._pac, 2, 0)
        w16be(self._pac, 2, chksum(self._pac))
        return self._pac


def decode(bs, check_crc=True):
    if isinstance(bs, Pack):
        return bs
    return Pack(_raw = bs)

def _timestamp():
    t = date.today()
    d = datetime.now() - datetime(t.year, t.month, t.day)
    return d.seconds * 1000 + d.microseconds // 1000

def recv(ifc, sip, dip, ippkt):
    try:
        pkt = decode(ippkt.pdu)
    except DecodeError as e:
        log.error('%s')
        return

    log.info('RECV %s -> %s, %r', sip, dip, pkt)

    # Note: By not checking dip, we accept broadcast ICMP packets.

    ty = pkt.type
    co = pkt.code

    reply = None
    if ty == ICMP_ECHO and co == 0:
        reply = Pack.EchoReply(pkt.id, pkt.seq, pkt.data)
    elif ty == ICMP_TS and co == 0:
        ts = _timestamp()
        reply = Pack.TimestampReply(pkt.id, pkt.seq, pkt.origtime, ts, ts)
    elif ty == ICMP_MASKREQ and co == 0:
        reply = Pack.MaskReply(pkt.id, pkt.seq, ifc.netmask)
    if reply:
        log.info('SEND %s -> %s, %r', dip, sip, reply)
        ipv4.send(dip, sip, reply)
        # do not pass to raw
        return

    handled = False
    if ty == ICMP_REDIRECT and 0 <= co <= 3:
        log.warn('TODO: %s', pkt)
        handled = True

    if ty == ICMP_SOURCEQUENCH and co == 0:
        log.warn('TODO: %s', pkt)
        handled = True

    if ty == ICMP_UNREACH or pkt.type == ICMP_TIMXCEED:
        try:
            ip = ipv4.decode(pkt.data)
        except DecodeError as e:
            log.error('cannot retrive ip header from %r: %s',
                      pkt, e)
            return
        handled = True
        if ip.proto == 6:
            tcp.notify(sip, pkt, ip)
        elif ip.proto == 17:
            udp.notify(sip, pkt, ip)

    # pass to raw for further processing
    raw.recv(sip, dip, ippkt, handled)

def send(sip, dip, pkt):
    assert isinstance(pkt, Pack)
    log.info('SEND %s -> %s, %r', sip, dip, pkt)
    ipv4.send(sip, dip, pkt)

def ping(ip):
    '''For testing only'''
    ip = ip4(ip)
    sip = net.ip_hint(ip)
    if not sip:
        raise ValueError('no route to %s', ip)
    send(sip, ip, Pack.Echo(12345, 1, b'1234567' * 8))

def time(ip):
    '''For testing only'''
    ip = ip4(ip)
    sip = net.ip_hint(ip)
    if not sip:
        raise ValueError('no route to %s', ip)
    ts = _timestamp()
    send(sip, ip, Pack.TimestampRequest(12345, 1, ts, 0, 0))

def addrmask(ip):
    '''For testing only'''
    ip = ip4(ip)
    sip = net.ip_hint(ip)
    if not sip:
        raise ValueError('no route to %s', ip)
    send(sip, ip, Pack.MaskRequest(12345, 1))
