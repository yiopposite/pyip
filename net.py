# net.py

import queue
import threading

import logging
tx = logging.getLogger('tx')
rx = logging.getLogger('rx')

import eth
import arp
import ipv4
import tcp
import dhcp
from common import *

_netifs = []
_routetbl = []

_rx_queue = queue.Queue()
_tx_queue = queue.Queue()

def _rx_loop(rxq):
    try:
        while 1:
            item = rxq.get()
            if item is None:
                break

            nic, pkt = item
            rx.debug('from %s: %s', nic, pkt)

            if isinstance(pkt, ipv4.Pack):
                # loopback
                assert nic is None
                ipv4.recv(_netifs[0], pkt)
                continue

            assert isinstance(pkt, eth.Pack)

            if pkt.type == 0x0800:
                try:
                    pkt = ipv4.decode(pkt.pdu)
                except DecodeError as e:
                    rx.error('dropping malformed IPv4 packet: %s', e)
                    ipv4._stat.rx_dropped += 1
                    continue
                # strong host model for Rx
                dst = pkt.dst
                if not (dst == nic.ip
                        or nic.ip == 0
                        or dst == nic.broadcast_ip
                        or dst.is_multicast()):
                    rx.info('dropping unmatched IPv4 packet: %s:', pkt)
                    ipv4._stat.rx_dropped += 1
                    continue
                ipv4.recv(nic, pkt)
            elif pkt.type == 0x0806:
                arp.recv(nic, pkt.pdu)
            else:
                rx.warning('dropping unsupported Eth frame: %s', pkt)
                eth._stat.tx_dropped += 1
    finally:
        rx.info('THREAD STOPPED')

_rx_thread = threading.Thread(name='rx', target=_rx_loop, args=(_rx_queue,), daemon=True)

def _tx_loop(txq):
    try:
        while 1:
            item = txq.get()
            if item is None:
                break
            nic, pac = item

            assert nic
            assert isinstance(pac, eth.Pack)

            nic.send(pac)
    finally:
        rx.info('THREAD STOPPED')

_tx_thread = threading.Thread(name='tx', target=_tx_loop, args=(_tx_queue,), daemon=True)

def ip_hint(ip):
    '''Select source IP from a target IP'''
    if not ip:
        if _netifs:
            return _netifs[0].ip
        return (127 << 24) | 1
    for (mask, dest, gw, nic) in _routetbl:
        if (mask & ip) == dest:
            return nic.ip
    return 0

def get_default_nic():
    if _netifs:
        return _netifs[0]
    return None

def is_local_ip(ip):
    return ip.is_loopback() or any(n.ip == ip for n in _netifs)

def _route(ip):
    for (mask, dest, gw, nic) in _routetbl:
        if (mask & ip) == dest:
            return (gw or ip, nic)
    return None

def send(pac):
    tx.debug('SEND %s', pac)
    if pac.kind == 'IPv4':
        if is_local_ip(pac.dst):
            # loopback
            _rx_queue.put((None, pac))
            return
        if not _netifs:
            tx.error('no interface found!')
            ipv4._stat.tx_dropped += 1
            return
        if pac.dst.is_broadcast():
            for nic in _netifs:
                _tx_queue.put((nic, eth.Pack(eth.BROADCASTADDR, nic.mac, pac)))
            return
        # TODO: multicast
        route = _route(pac.dst)
        if route is None:
            tx.error('no route for %s', pac)
            ipv4._stat.tx_dropped += 1
            return
        (ip, nic) = route
        dstmac = arp.lookup(ip, pac, nic)
        if dstmac is None:
            tx.debug('ARP lookup failed while sending packet %s', pac)
            return
        _tx_queue.put((nic, eth.Pack(dstmac, nic.mac, pac)))
    elif pac.kind == 'eth':
        if not _netifs:
            tx.error('no interface found!')
            eth._stat.tx_dropped += 1
            return
        for nic in _netifs:
            if nic.mac == pac.src:
                break
        else:
            tx.warning('sending frame via default interface')
            nic = _netifs[0]
        _tx_queue.put((nic, pac))
    else:
        tx.error('dropping strange packet %s', pac)

def _start():
    tcp.start()
    ipv4.start()
    arp.start()
    _tx_thread.start()
    _rx_thread.start()
    for i in _netifs:
        i.start()

def shutdown():
    for i in _netifs:
        i.shutdown()
    if _tx_thread.is_alive():
        _tx_queue.put(None)
        _tx_thread.join()
    if _rx_thread.is_alive():
        _rx_queue.put(None)
        _rx_thread.join()
    arp.shutdown()
    ipv4.shutdown()
    tcp.shutdown()

def add_nic(tapname, mac):
    global _netifs
    index = len(_netifs)
    nic = eth.Nic(index, _rx_queue, tapname, mac)
    _netifs.append(nic)
    return nic

def add_route(dest, gateway, mask, nic):
    _routetbl.append((ip4(mask), ip4(dest), ip4(gateway), nic))
    _routetbl.sort()
    _routetbl.reverse()

def start(tapname, cidr, mac=None, gateway=None):
    nic = add_nic(tapname, mac)

    ip, prefix = cidr.split('/')
    netmask = ~((1 << (32 - int(prefix))) - 1) & 0xffffffff
    nic.config(ip4(ip), ip4(netmask))

    add_route(nic.ip & netmask, 0, netmask, nic)
    if gateway:
        add_route(0, gateway, 0, nic)

    _start()

def start_dhcp(tapname, mac=None):
    nic = add_nic(tapname, mac)
    _start()
    dhcp.boot()
