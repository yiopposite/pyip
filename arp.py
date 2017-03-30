# arp.py

import threading
import time
import enum

import logging
log = logging.getLogger('arp')

import net
import eth
from common import *

_cache = {}
_cache_lifespan = 300
_lock = threading.Lock()
_pending_ip_lifespan = 10
_pending_ip = []

Op = enum.IntEnum('Op', 'ARP_REQUEST ARP_REPLY RARP_REQUEST RARP_REPLY')

class Pack:
    kind = 'ARP'
    eth_proto = 0x0806

    def __init__(self, op, sha, spa, tha, tpa):
        if not op in (i.value for i in Op.__members__.values()):
            raise ValueError('not a valid op: %d' % op)
        self.op = op
        self.sha = macaddr(sha)
        self.spa = ip4(spa)
        self.tha = macaddr(tha)
        self.tpa = ip4(tpa)

    def __len__(self):
        return 28

    def __repr__(self):
        op = Op(self.op)
        return ('<%s: sha=%s spa=%s tha=%s tpa=%s>'
                % (op.name,
                   self.sha, self.spa,
                   self.tha, self.tpa))

    def pack(self):
        return (b'\x00\x01\x08\x00\x06\x04'
                + self.op.to_bytes(2, 'big')
                + self.sha
                + self.spa.to_bytes(4, 'big')
                + self.tha
                + self.tpa.to_bytes(4, 'big'))


def decode(bs):
    if isinstance(bs, Pack):
        return bs
    (htype, ptype, hsize, psize,
     op, sha, spa, tha, tpa) = (
         r16be(bs, 0),
         r16be(bs, 2),
         bs[4],
         bs[5],
         r16be(bs, 6),
         bs[8:14],
         r32be(bs, 14),
         bs[18:24],
         r32be(bs, 24))
    if htype != 1:
        raise DecodeError('htype %d != 1' % htype)
    if ptype != 0x0800:
        raise DecodeError('ptype %04x != 0800' % ptype)
    if hsize != 6:
        raise DecodeError('hsize %d != 6' % hsize)
    if psize != 4:
        raise DecodeError('psize %d != 4' % psize)
    return Pack(op, sha, spa, tha, tpa)


class Timer(threading.Thread):
    def __init__(self, seconds, fun):
        threading.Thread.__init__(self, name='arp', daemon=True)
        self.interval = seconds
        self.fun = fun
        self.stopped = threading.Event()

    def stop(self):
        self.stopped.set()

    def run(self):
        while not self.stopped.wait(self.interval):
            self.fun()

def _timeout():
    now = int(time.time())
    failed_ip = []
    with _lock:
        # cache item
        to_remove = []
        for (k, v) in _cache.items():
            if now > v[2]:
                to_remove.append(k)
        for k in to_remove:
            del _cache[k]
        # pending ip
        to_remove = []
        for e in _pending_ip:
            (i, p, t) = e
            if now > t:
                failed_ip.append((i, p))
                _pending_ip.remove(e)

    for (i, p) in failed_ip:
        # TODO: send ICMP route error to the offending agent
        log.info('no route to %s, packet dropped: %r', i, p)

def _update_cache(nic, ip, mac):
    global _pending_ip
    resends = []
    with _lock:
        _cache[ip] = (mac, nic, int(time.time()) + _cache_lifespan)
        for p in _pending_ip:
            if _cache.get(p[0]):
                resends.append(p[1])
                _pending_ip.remove(p)
    for p in resends:
        net.send(p)

def lookup(ip, pkt=None, nic=None):
    global _pending_ip
    with _lock:
        info = _cache.get(ip)
        if info is not None:
            return info[0]
        if pkt:
            _pending_ip.append((ip, pkt, int(time.time()) + _pending_ip_lifespan))
    # send an ARP request
    if nic:
        pac = Pack(1, nic.mac, nic.ip, b'\x00' * 6, ip)
        _send(eth.BROADCASTADDR, nic.mac, pac)
    return None

def recv(nic, bs):
    try:
        pkt = decode(bs)
    except DecodeError as e:
        log.warn('dropping bad packet: %s', e)
        return

    if pkt.sha == nic.mac:
        log.debug('packet from me, ignored')
        return
    if pkt.sha == eth.BROADCASTADDR:
        log.warning('source ether address is broadcast')
        return
    if pkt.spa == nic.ip:
        log.error('duplicate IP %s, sent from ether address %s',
                  spa, mac2str(sha))
        # TODO
        return

    if pkt.tpa == nic.ip:
        log.info('RECV %s', pkt)
    else:
        log.debug('RECV %s', pkt)

    _update_cache(nic, pkt.spa, pkt.sha)

    # send reply
    if pkt.op == Op.ARP_REQUEST and pkt.tpa == nic.ip:
        pac = Pack(2, nic.mac, nic.ip, pkt.sha, pkt.spa)
        _send(pkt.sha, nic.mac,pac)

def _send(dst, src, pac):
    log.debug('SEND %s', pac)
    net.send(eth.Pack(dst, src, pac))

def info():
    if _cache:
        print('IP\t\tMAC\t\t\tIface\t\tTimeout (sec)')
        for (ip, (mac, net, timeo)) in _cache.items():
            print('%s\t%s\t%s\t\t%d'
                  % (ip, mac, net.name, timeo - int(time.time())))
    if _pending_ip:
        print('Pending IP:\tto\tIP\tTimeout')
        for (ip, pkt, t) in _pending_ip:
            print('%s\t%s -> %s\t%d'
                  % (ip, pkt.src, pkt.dst,
                     int(time.time()) - t))

def ping(ip):
    nic = net.get_default_nic()
    if nic:
        _send(eth.BROADCASTADDR, nic.mac,
              Pack(1, nic.mac, nic.ip, b'\x00' * 6, ip))

_timer = Timer(5, _timeout)

def start():
    _timer.start()

def shutdown():
    _timer.stop()
