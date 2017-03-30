# -*- coding: utf-8 -*-

'''Dynamic Host Configuration Protocol client.'''

import enum
import random
import logging
log = logging.getLogger(__name__)

import net
import udp
import dns
from common import *

OP_REQUEST = 1
OP_REPLY = 2

enum_convert('OpCode', __name__, lambda c: c.startswith('OP_'))

MAGIC = 0x63825363

@enum.unique
class Tag(enum.IntEnum):
    PAD = 0
    NETMASK = 1
    TIMEOFFSET = 2
    ROUTER = 3
    DNS_SVRS = 6
    DOMAIN = 15
    REQ_IP = 50
    LEASE_SEC = 51
    MSGTYPE = 53
    SERVER_ID = 54
    PARAM_REQ = 55
    MESSAGE = 56
    MAXMSGSIZE = 57
    RENEWTIME =  58
    REBINDTIME = 59
    VENDOR_ID = 60
    CLIENT_ID = 61
    DOMAIN_SEARCH_LIST = 119
    END = 255

@enum.unique
class DHCP(enum.IntEnum):
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8

class OptUnknown:
    __slots__ = ('tag', 'data')
    def __init__(self, tag, data):
        assert 0 < tag < 255
        assert len(data) <= 255
        self.tag = tag
        self.data = data
    def __len__(self):
        return 2 + len(self.data)
    def __repr__(self):
        return ('(%d %d %s)'
                % (self.tag, len(self.data), ''.join('%02x' % b for b in self.data)))
    @classmethod
    def read(cls, mem, off):
        tag = mem[off]
        if tag == 0:
            return OptPad()
        if tag == 255:
            return OptEnd()
        return cls(tag, mem[off+2:off+2+mem[off+1]])
    def write(self, mem, off):
        mem[off] = self.tag
        n = len(self.data)
        mem[off+1] = n
        mem[off+2:off+2+n] = self.data
        return n + 2

_optclstbl = [OptUnknown] * 256

def _readopt(mem, off):
    return _optclstbl[mem[off]].read(mem, off)

def option(cls):
    _optclstbl[cls.tag] = cls
    return cls

class Opt:
    pass

@option
class OptPad(Opt):
    tag = Tag.PAD
    def __len__(self):
        return 1
    def __repr__(self):
        return self.tag.name
    @classmethod
    def read(cls, mem, off):
        assert mem[off] == cls.tag
        return cls()
    def write(self, mem, off):
        mem[off] = 0
        return 1

@option
class OptEnd(Opt):
    tag = Tag.END
    def __len__(self):
        return 1
    def __repr__(self):
        return self.tag.name
    @classmethod
    def read(cls, mem, off):
        assert mem[off] == cls.tag
        return cls()
    def write(self, mem, off):
        mem[off] = 0xff
        return 1

@option
class OptNetMask(Opt):
    tag = Tag.NETMASK
    def __init__(self, val):
        self.val = val
    def __len__(self):
        return 6
    def __repr__(self):
        return '%s=%s' % (self.tag.name, self.val)
    @classmethod
    def read(cls, mem, off):
        assert mem[off] == cls.tag
        return cls(ip4(mem, off+2))
    def write(self, mem, off):
        mem[off] = self.tag
        mem[off+1] = 4
        w32be(mem, off+2, self.val)
        return len(self)

@option
class OptRouter(Opt):
    tag = Tag.ROUTER
    def __init__(self, val):
        self.val = val
    def __len__(self):
        return 6
    def __repr__(self):
        return '%s=%s' % (self.tag.name, self.val)
    @classmethod
    def read(cls, mem, off):
        assert mem[off] == cls.tag
        return cls(ip4(mem, off+2))
    def write(self, mem, off):
        mem[off] = self.tag
        mem[off+1] = 4
        w32be(mem, off+2, self.val)
        return len(self)

@option
class OptDnsSvrs(Opt):
    tag = Tag.DNS_SVRS
    def __init__(self, val):
        self.val = val
    def __len__(self):
        return 2 + 4 * len(self.val)
    def __repr__(self):
        return '%s=%s' % (self.tag.name, self.val)
    @classmethod
    def read(cls, mem, off):
        assert mem[off] == cls.tag
        n = mem[off+1] >> 2
        svrs = []
        for i in range(n):
            svrs.append(ip4(mem, off+2+i*4))
        return cls(svrs)
    def write(self, mem, off):
        mem[off] = self.tag
        mem[off+1] = len(self) - 2
        i = 0
        for (i, svr) in enumerate(self.val):
            w32be(mem, off+2+i*4, svr)
        return len(self)

@option
class OptMsgType(Opt):
    tag = Tag.MSGTYPE
    def __init__(self, val):
        self.val = val
    def __len__(self):
        return 3
    def __repr__(self):
        return '%s' % self.val
    @classmethod
    def read(cls, mem, off):
        assert mem[off] == cls.tag
        return cls(DHCP(mem[off+2]))
    def write(self, mem, off):
        mem[off] = self.tag
        mem[off+1] = 1
        mem[off+2] = self.val
        return len(self)

@option
class OptReqIp(Opt):
    tag = Tag.REQ_IP
    def __init__(self, val):
        self.val = val
    def __len__(self):
        return 6
    def __repr__(self):
        return '%s=%s' % (self.tag.name, self.val)
    @classmethod
    def read(cls, mem, off):
        assert mem[off] == cls.tag
        return cls(ip4(mem, off+2))
    def write(self, mem, off):
        mem[off] = self.tag
        mem[off+1] = 4
        w32be(mem, off+2, self.val)
        return len(self)

@option
class OptLeaseSec(Opt):
    tag = Tag.LEASE_SEC
    def __init__(self, val):
        self.val = val
    def __len__(self):
        return 6
    def __repr__(self):
        return '%s=%s' % (self.tag.name, self.val)
    @classmethod
    def read(cls, mem, off):
        assert mem[off] == cls.tag
        return cls(r32be(mem, off+2))
    def write(self, mem, off):
        mem[off] = self.tag
        mem[off+1] = 4
        w32be(mem, off+2, self.val)
        return len(self)

@option
class OptServerId(Opt):
    tag = Tag.SERVER_ID
    def __init__(self, val):
        self.val = val
    def __len__(self):
        return 6
    def __repr__(self):
        return '%s=%s' % (self.tag.name, self.val)
    @classmethod
    def read(cls, mem, off):
        assert mem[off] == cls.tag
        return cls(ip4(mem, off+2))
    def write(self, mem, off):
        mem[off] = self.tag
        mem[off+1] = 4
        w32be(mem, off+2, self.val)
        return len(self)

@option
class OptParamReq(Opt):
    tag = Tag.PARAM_REQ
    def __init__(self, val):
        self.val = val
    def __len__(self):
        return 2 + len(self.val)
    def __repr__(self):
        return '%s=%s' % (self.tag.name, self.val)
    @classmethod
    def read(cls, mem, off):
        assert mem[off] == cls.tag
        n = mem[off+1]
        params = []
        for i in range(n):
            params.append(Tag(mem[off+2+i]))
        return cls(params)
    def write(self, mem, off):
        mem[off] = self.tag
        mem[off+1] = len(self) - 2
        i = 0
        for (i, p) in enumerate(self.val):
            mem[off+2+i] = p
        return len(self)


class Pack:
    kind = 'DHCP'

    def __init__(self, raw=None, **args):
        if raw is None:
            self._raw = bytearray(548)
            for (k, v) in args.items():
                setattr(self, k, v)
            if self.op == 0:
                self.op = OP_REQUEST
            if self.htype == 0:
                self.htype = 1
            if self.hlen == 0:
                self.hlen = 6
            if self.magic == 0:
                self.magic = MAGIC
        else:
            self._raw = raw

    def __len__(self):
        return len(self._raw)

    def __repr__(self):
        return ('<DHCP_%s: hops=%d xid=%#x secs=%d flags=0x%04x'
                ' ciaddr=%s yiaddr=%s siaddr=%s giaddr=%s chaddr=%s'
                ' options=%s>'
                % (OpCode(self.op).name,
                   self.hops,
                   self.xid,
                   self.secs,
                   self.flags,
                   self.ciaddr,
                   self.yiaddr,
                   self.siaddr,
                   self.giaddr,
                   self.chaddr,
                   self.options))
    @property
    def op(self):
        return self._raw[0]
    @op.setter
    def op(self, val):
        self._raw[0] = val

    @property
    def htype(self):
        return self._raw[1]
    @htype.setter
    def htype(self, val):
        self._raw[1] = val

    @property
    def hlen(self):
        return self._raw[2]
    @hlen.setter
    def hlen(self, val):
        self._raw[2] = val

    @property
    def hops(self):
        return self._raw[3]
    @hops.setter
    def hops(self, val):
        self._raw[3] = val

    @property
    def xid(self):
        return r32be(self._raw, 4)
    @xid.setter
    def xid(self, val):
        w32be(self._raw, 4, val)

    @property
    def secs(self):
        return r16be(self._raw, 8)
    @secs.setter
    def secs(self, val):
        w16be(self._raw, 8, val)

    @property
    def flags(self):
        return r16be(self._raw, 10)
    @flags.setter
    def flags(self, val):
        w16be(self._raw, 10, val)

    @property
    def ciaddr(self):
        return ip4(r32be(self._raw, 12))
    @ciaddr.setter
    def ciaddr(self, val):
        w32be(self._raw, 12, val)

    @property
    def yiaddr(self):
        return ip4(r32be(self._raw, 16))
    @yiaddr.setter
    def yiaddr(self, val):
        w32be(self._raw, 16, val)

    @property
    def siaddr(self):
        return ip4(r32be(self._raw, 20))
    @siaddr.setter
    def siaddr(self, val):
        w32be(self._raw, 20, val)

    @property
    def giaddr(self):
        return ip4(r32be(self._raw, 24))
    @giaddr.setter
    def giaddr(self, val):
        w32be(self._raw, 24, val)

    @property
    def chaddr(self):
        return macaddr(self._raw, 28)
    @chaddr.setter
    def chaddr(self, val):
        self._raw[28:34] = val

    @property
    def sname(self):
        res = bytearray(64)
        for i in range(64):
            res[i] = self._raw[44+i]
            if res[i] == 0:
                break
        return bytes(res[:i+1])
    @sname.setter
    def sname(self, val):
        n = min(len(val), 64)
        self._raw[44:44+n] = val

    @property
    def file(self):
        res = bytearray(128)
        for i in range(128):
            res[i] = self._raw[108+i]
            if res[i] == 0:
                break
        return bytes(res[:i+1])
    @file.setter
    def file(self, val):
        n = min(len(val), 128)
        self._raw[108:108+n] = val

    @property
    def magic(self):
        return r32be(self._raw, 236)
    @magic.setter
    def magic(self, val):
        return w32be(self._raw, 236, val)

    @property
    def options(self):
        size = len(self._raw)
        opts = []
        off = 240
        while off < size:
            opt = _readopt(self._raw, off)
            opts.append(opt)
            if opt.tag == 0xff:
                break
            off += len(opt)
        return opts

    @options.setter
    def options(self, opts):
        off = 240
        for opt in opts:
            off += opt.write(self._raw, off)

    def pack(self):
        return self._raw

def decode(bs):
    if isinstance(bs, Pack):
        return bs
    if len(bs) < 300:
        raise DecodeError('packet too small (%d < 300)' % len(bs))
    return Pack(raw=bs)
        
def _boot(sock, hint_ip, timeout):
    nic = net.get_default_nic()
    chaddr = nic.mac
    xid = random.getrandbits(32)

    # discover
    options = [OptMsgType(DHCP.DISCOVER)]
    if hint_ip:
        options.append(OptReqIp(hint_ip))
    options.append(OptParamReq((Tag.NETMASK,
                                Tag.ROUTER,
                                Tag.DOMAIN,
                                Tag.DNS_SVRS)))
    options.append(OptEnd())
    discover = Pack(op=1, xid=xid, chaddr=nic.mac, options=options)
    sock.sendto((-1, 67), discover)

    # offer
    reply = sock.recvfrom(timeout=timeout)
    if reply is None:
        return
    (server, offer) = reply
    offer = decode(offer)
    if offer.op != OP_REPLY:
        return
    if offer.xid != xid:
        return

    dhcp_type = None
    router = None
    netmask = None
    dns_servers = None
    dhcp_server = None
    for opt in offer.options:
        if opt.tag == Tag.MSGTYPE:
            dhcp_type = opt
            is_offer = True
        if opt.tag == Tag.ROUTER:
            router = opt.val
        if opt.tag == Tag.NETMASK:
            netmask = opt.val
        if opt.tag == Tag.DNS_SVRS:
            dns_servers = opt.val
        if opt.tag == Tag.SERVER_ID:
            dhcp_server = opt.val
    if not all((dhcp_type.val == DHCP.OFFER, router, netmask, dhcp_server)):
        return

    # request
    options = [OptMsgType(DHCP.REQUEST),
               OptReqIp(offer.yiaddr),
               OptServerId(dhcp_server),
               OptEnd()]
    request = Pack(op=1, xid=xid, chaddr=nic.mac, siaddr=offer.siaddr,
                   options=options)
    sock.sendto((-1, 67), request)

    # ack
    reply = sock.recvfrom(timeout=timeout)
    if reply is None:
        return
    (server, ack) = reply
    ack = decode(ack)
    if ack.op != OP_REPLY:
        return
    if ack.xid != xid:
        return
    options = ack.options
    is_ack = False
    for opt in options:
        if opt.tag == Tag.MSGTYPE and opt.val == DHCP.ACK:
            is_ack = True
        if opt.tag == Tag.ROUTER:
            router = opt.val
        if opt.tag == Tag.NETMASK:
            netmask = opt.val
        if opt.tag == Tag.DNS_SVRS:
            dns_servers = opt.val
        if opt.tag == Tag.SERVER_ID:
            dhcp_server = opt.val

    if not is_ack:
        return

    #TODO: probe with gratuitous ARP packets

    # config NIC and route table
    nic.config(ack.yiaddr, netmask)
    net.add_route(nic.ip & netmask, 0, netmask, nic)
    if router:
        net.add_route(0, router, 0, nic)

    # config DNS servers
    for svr in dns_servers:
        dns.servers.append(svr)

    return True

def boot(hint_ip=None, timeout=5):
    sock = udp.socket().bind((0, 68))
    try:
        return _boot(sock, hint_ip, timeout)
    finally:
        sock.close()
