# -*- coding: utf-8 -*-

import sys
import os
import random
import threading
import select

import logging
log = logging.getLogger(__name__)

from common import *

ETH_IPv4 = 0x0800
ETH_ARP  = 0x0806
ETH_RARP = 0x8035
ETH_QTAG = 0x8100
ETH_IPv6 = 0x86DD

enum_convert('Eth', __name__, lambda c: c.startswith('ETH_'))

BROADCASTADDR = b'\xff' * 6

# statistics
class _stat:
    rx_frames = 0
    rx_bytes = 0
    rx_runt = 0
    rx_unknown_ethertype = 0
    rx_dropped = 0
    tx_frames = 0
    tx_bytes = 0
    tx_runt = 0
    tx_dropped = 0
    loopback = 0

class Pack:
    kind = 'eth'

    def __init__(self, dst=None, src=None, pdu=None, raw=None):
        self._dst = dst
        self._src = src
        self._pdu = pdu
        self._raw = raw
        if raw is None:
            if not hasattr(pdu, 'eth_proto'):
                raise ValueError('not a valid eth PDU')
            self._pdu = pdu
            self._dst = macaddr(dst) if dst else macaddr()
            self._src = macaddr(src) if src else macaddr()
        elif any(p is not None for p in (dst, src, pdu)):
            raise ValueError('bad arguments')

    def __len__(self):
        if self._raw is None:
            return 14 + len(self._pdu)
        return len(self._raw)

    def __repr__(self):
        if self._pdu:
            return ('<%s: dst=%s src=%s %s>'
                    % (self.type.name, self.dst, self.src, self._pdu))
        else:
            return ('<%s: dst=%s src=%s len=%d>'
                    % (self.type.name, self.dst, self.src, len(self.pdu)))

    @property
    def dst(self):
        if self._raw is None:
            return self._dst
        return macaddr(self._raw, 0)

    @dst.setter
    def dst(self, val):
        val = macaddr(val)
        if self._raw is None:
            self._dst = val
        else:
            self._raw[:6] = val

    @property
    def src(self):
        if self._raw is None:
            return self._src
        return macaddr(self._raw, 6)

    @src.setter
    def src(self, val):
        val = macaddr(val)
        if self._raw is None:
            self._src = val
        else:
            self._raw[6:12] = val

    @property
    def type(self):
        if self._raw is None:
            return Eth(self._pdu.eth_proto)
        return Eth(r16be(self._raw, 12))

    @property
    def pdu(self):
        if self._raw is None:
            return self._pdu
        return memoryview(self._raw)[14:]

    def pack(self, padding=True):
        if self._raw is None:
            # TODO
            return (self._dst + self._src
                    + self.type.to_bytes(2, 'big') + self._pdu.pack())
        return self._raw

def decode(frame):
    if isinstance(frame, Pack):
        return frame
    if len(frame) < 42:
        raise DecodeError('runt frame: %s' % ''.join('%02x' % b for b in frame))
    ty = r16be(frame, 12)
    if not ty in Eth.__members__.values():
        raise DecodeError('unknown ether type: %#x' % ty)
    return Pack(raw = frame)

def random_mac():
    return macaddr(b'\x02\x59\x49' + random.getrandbits(32).to_bytes(4,'big')[:3])

class Nic(threading.Thread):
    ''' NIC as a TAP master '''
    def __init__(self, index, inq, tapname=None, mac=None):
        self.index = index
        self.inq = inq
        self.tap_fd, tapname = open_tap(tapname)

        if mac:
            self.mac = macaddr(mac)
        else:
            self.mac = random_mac()

        self.mtu = 1500
        self.ip = 0
        self.netmask = 0
        self.broadcast_ip = 0
        self.promisc = False

        self.pipe = os.pipe()
        self.exc_info = None
        threading.Thread.__init__(self, name=tapname, daemon=True)

    def __repr__(self):
        return '<NIC #%d: %s>' % self

    def __str__(self):
        return self.name

    def config(self, ip=None, netmask=None, broadcast_ip=None,
               promisc=None, mtu=None):
        if ip is not None:
            if netmask is None:
                raise ValueError('netmask is not provided')
            self.ip = ip
            self.netmask = netmask
            if broadcast_ip is None:
                broadcast_ip = (ip & netmask) | ~netmask
            self.broadcast_ip = ip4(broadcast_ip)
        elif netmask is not None:
            raise ValueError('ip is not provided')
        if mtu:
            self.mtu = mtu
        if promisc is not None:
            self.promisc = promisc

    def info(self):
        print('\n'.join((' %12s : %s',) * 4)
              % ('MAC', self.mac, 'IP', self.ip, 'Netmask', self.netmask,
                 'Broadcast IP', self.broadcast_ip))

    def is_running(self): return self.is_alive()

    def run(self):
        self.exc_info = None
        try:
            while True:
                ready = select.select([self.tap_fd, self.pipe[0]], [], [])
                if self.pipe[0] in ready[0]:
                    data = os.read(self.pipe[0], 1)
                    log.info('%s: shutting down...', self.name)
                    break;
                if self.tap_fd in ready[0]:
                    data = os.read(self.tap_fd, 1600)
                    if not data:
                        log.info('%s: TAP closed', self.name)
                        break
                    self.recv(data)
        #except Exception:
        #    self.exc_info = sys.exc_info()
        #    _thread.interrupt_main()
        finally:
            log.info('%s: STOPPED', self.name)

    def shutdown(self):
        if self.is_alive():
            os.write(self.pipe[1], b'.')
            self.join()
        os.close(self.tap_fd)
        os.close(self.pipe[0])
        os.close(self.pipe[1])

    def recv(self, bs):
        _stat.rx_frames += 1
        _stat.rx_bytes += len(bs)

        try:
            frm = decode(bs)
        except DecodeError as e:
            log.debug('dropping frame: %s', e)
            if 'runt' in ('%s' % e):
                _stat.rx_runt += 1
            else:
                _stat.rx_unknown_ethertype += 1
            return

        log.debug('RECV %s', frm)

        if (not self.promisc
            and frm.dst != self.mac and frm.dst != BROADCASTADDR):
            _stat.rx_dropped += 1
            return

        self.inq.put_nowait((self, frm))

    def xmit(self, bs):
        minlen = 42
        maxlen = self.mtu + 14
        size = len(bs)
        if size < minlen:
            log.warning("sending runt frame (%d < %d)", size, minlen)
            _stat.tx_runt += 1
        if size > maxlen:
            log.warning("sending too large frame (%d > %d)", size, maxlen)
        try:
            os.write(self.tap_fd, bs)
        except OSError as e:
            # bail out?
            log.error('%s', e)
            _stat.tx_dropped += 1
        else:
            _stat.tx_frames += 1
            _stat.tx_bytes += len(bs)

    def send(self, pac):
        assert isinstance(pac, Pack)
        log.debug('SEND %s', pac)
        dst = pac.dst
        if dst == self.mac:
            log.warning('sending to self')
            _stat.tx_dropped += 1
            return
        if dst == BROADCASTADDR:
            # loopback a copy if broadcasting
            self.inq.put_nowait((self, pac))
            _stat.loopback += 1
        self.xmit(pac.pack())
