# -*- coding: utf-8 -*-

'''Various small TCP/IP client programs
 - ping (ICMP)
 - traceroute (UDP/ICMP)
 - wget (TCP)
 - rlogin (TCP)
'''

import os, sys, time
import threading
import select
import marshal
import tty, pwd, termios

import ipv4, udp, tcp, icmp, raw
from common import *

import logging
tcp.log.setLevel(logging.INFO)

def ping(host, n=3, interval=1, timeout=10):
    '''ICMP ping'''
    ip = ip4(host)
    id = os.getpid()

    sock = raw.socket(ipv4.IPPROT.ICMP)

    def send(s, ip, id, n, interval):
        print('PING %s 56 bytes of data.' % ip)
        for i in range(1, n+1):
            data = marshal.dumps(time.time()).ljust(56, b'\x00')
            s.sendto(ip, icmp.Pack.Echo(id, i, data))
            if i == n:
                break
            time.sleep(interval)

    t = threading.Thread(target=send, name='ping',
                         args=(sock, ip, id, n, interval))
    t.start()

    r = n
    acc = 0
    try:
        while r > 0:
            ret = sock.recvfrom(timeout=timeout)
            if not ret:
                break
            sip, ippkt = ret
            icmppkt = icmp.decode(ippkt.pdu)
            if not (icmppkt.type == icmp.ICMP_ECHOREPLY
                    and icmppkt.code == 0):
                continue
            if icmppkt.id != id:
                continue
            r -= 1
            rtt = (time.time() - marshal.loads(icmppkt.data)) * 1000
            acc += rtt
            print('%d bytes from %s: seq=%d ttl=%d time=%.2fms'
                  % (len(icmppkt), sip, icmppkt.seq, ippkt.ttl, rtt))
    finally:
        print('\n--- %s ping statistics ---' % ip)
        print('%d packets transmitted, %d received, average time %s'
              % (n, n-r, 'N/A' if n==r else ('%.2fms' % (acc/(n-r)))))
        sock.close()

    t.join()
    return r == 0

def traceroute(host, *, sport=None, nhop=20, nprobes=3, timeout=5):
    '''Trace route using UDP'''
    dip = ip4(host)
    dport = 33333
    if sport is None:
        sport = (os.getpid() & 0xffff) | 0x8000

    pktlen = 60
    datalen = pktlen - 20 - 8
    assert datalen >= len(marshal.dumps((int(), float())))

    sendsock = udp.socket().bind((0, sport))
    recvsock = raw.socket(ipv4.IPPROT.ICMP)

    print('traceroute to %s, %d hops max, %d bytes packets'
          % (dip, nhop, pktlen), flush=True)

    try:
        seq = 0
        for ttl in range(1, nhop+1):
            sendsock.setsockopt(DF=1, ttl=ttl)
            print('%2d' % ttl, end='', flush=True)
            done = 0
            lastsip = None
            for probe in range(1, nprobes+1):
                sendtime = time.time()
                seq += 1
                sendsock.sendto((dip, dport+seq),
                                marshal.dumps((ttl, sendtime)).ljust(datalen, b'\x00'))
                ret = None
                while True:
                    now = time.time()
                    wait = timeout - (now - sendtime)
                    if wait <= 0:
                        ret = None
                        break
                    ret = recvsock.recvfrom(timeout=wait)
                    if not ret:
                        break
                    (sip, ippkt) = ret
                    icmppkt = icmp.decode(ippkt.pdu)
                    if ((icmppkt.type == icmp.ICMP_TIMXCEED
                         and icmppkt.code == icmp.TIMXCEED_INTRANS)
                        or icmppkt.type == icmp.ICMP_UNREACH):
                        try:
                            ippkt2 = ipv4.decode(icmppkt.data)
                        except DecodeError as e:
                            print(e, file=sys.stderr, flush=True)
                            continue
                        if ippkt2.proto != ipv4.IPPROT.UDP:
                            continue
                        udppkt = udp.decode(ippkt2.pdu)
                        if (udppkt.sport == sport
                            and udppkt.dport == dport + seq):
                            ret = (sip, icmppkt)
                            break
                if not ret:
                    print('\t*', end='', flush=True)
                    continue
                rtt = (time.time() - sendtime) * 1000
                sip, icmppkt = ret
                if sip != lastsip:
                    print('\t%s %7.3f ms' % (sip, rtt), end='', flush=True)
                    lastsip = sip
                else:
                    print('\t%7.3f ms' % rtt, end='', flush=True)
                if sip == dip:
                    done += 1
            print(flush=True)
            if done:
                break
    finally:
        sendsock.close()
        recvsock.close()

    return True


def wget(host, port=80, file='/'):
    cli = tcp.socket()
    cli.connect((ip4(host), port))
    cli.send('GET %s HTTP/1.1\r\n\r\n' % file)
    doc = cli.recv()
    cli.close()
    return doc and doc.decode()


def rlogin(host, rport=None, lport=None, uname=None,
           *, _testing=False):
    ''' Remote login client '''
    if not sys.stdin.isatty():
        sys.stderr.write('stdin is not a terminal\n')
        return False

    if not uname:
        uname = pwd.getpwuid(os.getuid())[0]
    if not rport:
        #rport = socket.getservbyname("login", "tcp")
        rport = 513
    if lport is None:
        lport = 1023

    STDIN = 0
    STDOUT = 1
    STDERR = 2

    def login(host, rport, lport, uname):
        term = '/'.join((os.getenv('TERM'),
                         ("0", "50", "75", "110", "134", "150",
                          "200", "300", "600", "1200", "1800",
                          "2400", "4800", "9600", "19200",
                          "38400")[termios.tcgetattr(STDIN)[5]]))
        sock = tcp.socket()
        try:
            sock.bind(('', lport))
            sock.connect((host, rport))
            sock.send(b'\x00')
            sock.send(uname.encode() + b'\x00')
            sock.send(uname.encode() + b'\x00')
            sock.send(term.encode() + b'\x00')
            s = sock.recv()
            if s[0] != 0:
                os.write(STDERR, s[1:].decode())
                sock.close()
                return None
        except Exception:
            sock.close()
            raise
        return sock

    def writer(sock, pipe):
        '''Copy standard input to network.'''
        while 1:
            (ready, _, _) = select.select((STDIN, pipe), (), ())
            if STDIN in ready:
                c = os.read(STDIN, 1)
                if not c:
                    break
                sock.send(c)
            if pipe in ready:
                break

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        # cbreak, not raw, so that we can Ctrl-C when stuck
        tty.setcbreak(fd)
        sock = login(host, rport, lport, uname)
        if sock is None:
            return False
        pipe = os.pipe()
        writer_thr = threading.Thread(name='rlogin',
                                      target=writer,
                                      args=(sock, pipe[0]))
        writer_thr.start()
        s = b''
        try:
            # copy input from network to standard output
            while 1:
                s = sock.recv()
                if not s:
                    sys.stderr.write('Connection closed\n')
                    break
                os.write(STDOUT, s)
                if _testing and s.endswith(b'\n'):
                    sock.send(b'logout\r\n\x00')
                    break
        finally:
            if writer_thr.is_alive():
                os.write(pipe[1], b'\n')
                writer_thr.join()
            os.close(pipe[0])
            os.close(pipe[1])
            sock.close()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    return bool(s)
