# -*- coding: utf-8 -*-

import threading
import time
import queue
import collections
import enum
import random
import io
import warnings

import logging
log = logging.getLogger(__name__)

import ipv4
import icmp
import net
from common import *
from _common import _memcopy

class _stat:
    rx_total = 0
    rx_bad_checksum = 0
    rx_bad_doff = 0

DefSynBacklog = 16
MaxSynBacklog = 128

DefWindowSize = 4096
MaxSynRetries = 3
MaxSynAckRetries = 3
SynInterval = 2
RetransmissionN = 3
RetransmissionT = 2
FinRetries = 3
FinInterval = 1
MSL = 5

class Pack:
    kind = 'TCP'
    ip_proto = 6

    def __init__(self, sp=0, dp=0,
                 seq=0, ack=0,
                 CWR=0, ECE=0, URG=0, ACK=0, PSH=0, RST=0, SYN=0, FIN=0,
                 wnd=4096, urg=0,
                 mss=None, ws=None, sack=None, timestamp=None, data=None,
                 _raw=None):
        if _raw is not None:
            doff = _raw[12] >> 2
            self.hdr = memoryview(_raw)[:doff]
            self.data = memoryview(_raw)[doff:]
            return

        if wnd < 2 or wnd > 65535:
            raise ValueError('`wnd` must be between 2 and 65535')

        if ws is not None and not 0 <= ws <= 14:
            raise ValueError('`ms` must be between 0 and 14')

        hbytes = 20
        if mss:
            hbytes += 4
        if sack:
            hbytes += 2
        if timestamp:
            hbytes += 10
        if ws is not None:
            hbytes += 3
        hbytes = (hbytes + 3) >> 2 << 2
        hdr = bytearray(hbytes)

        # options
        opt = 20
        if mss:
            w16be(hdr, opt, 0x0204)
            w16be(hdr, opt+2, mss & 0xffff)
            opt += 4
        if sack:
            w16be(hdr, opt, 0x0402)
            opt += 2
        if timestamp:
            w16be(hdr, opt, 0x080a)
            w32be(hdr, opt+2, timestamp[0])
            w32be(hdr, opt+6, timestamp[1])
            opt += 10
        if ws:
            w16be(hdr, opt, 0x0103)
            hdr[opt+2] = 0x03
            hdr[opt+3] = ws
            opt += 4

        self.hdr = hdr
        self.data = bytearray()
        if data is not None:
            self.data[:] = data

        self.sp = sp
        self.dp = dp
        self.seq = seq
        self.ack = ack
        self.doff = hbytes >> 2
        self.wnd = wnd
        self.urg = urg
        self.CWR=CWR
        self.ECE=ECE
        self.URG=URG
        self.ACK=ACK
        self.PSH=PSH
        self.RST=RST
        self.SYN=SYN
        self.FIN=FIN

    def __repr__(self):
        return ('<TCP: %d:%d %s>'
                % (self.sp, self.dp,
                   ' '.join(s
                       for s in (self.flagstr(),
                                 self.seqackstr(),
                                 self.wndstr(),
                                 self.optstr(),
                                 self.lenstr())
                       if s)))

    def __len__(self):
        return len(self.hdr) + len(self.data)

    def flagstr(self):
        s = []
        if self.CWR: s.append('C')
        if self.ECE: s.append('E')
        if self.URG: s.append('U')
        if self.PSH: s.append('P')
        if self.RST: s.append('R')
        if self.SYN: s.append('S')
        if self.FIN: s.append('F')
        return ''.join(s)

    def seqackstr(self):
        s = 'seq=%s' % self.seq
        if self.ACK:
            return s + (' ack=%d' % self.ack)
        return s

    def wndstr(self):
        return 'wnd=%d' % self.wnd

    def lenstr(self):
        if self.data:
            return 'len=%d' % len(self.data)

    def optstr(self):
        res = []
        for (t, _, v) in self.options:
            if t == 1:
                res.append('NOP')
            if t == 2:
                res.append('MSS=%d' % v)
            elif t == 3:
                res.append('WS=%d' % v)
            elif t == 4:
                res.append('SACK_PERM')
            elif t == 8:
                res.append('TS=(%d, %d)' % (v>>32, v & 0xffffffff))
            else:
                res.append('%d=%s' % (t, v))
        if res:
            return '[' + ' '.join(res) + ']'

    @property
    def sp(self):
        return r16be(self.hdr, 0)

    @sp.setter
    def sp(self, val):
        w16be(self.hdr, 0, val)

    @property
    def dp(self):
        return r16be(self.hdr, 2)

    @dp.setter
    def dp(self, val):
        w16be(self.hdr, 2, val)

    @property
    def seq(self):
        return seq32(r32be(self.hdr, 4))

    @seq.setter
    def seq(self, val):
        w32be(self.hdr, 4, int(val))

    @property
    def ack(self):
        return seq32(r32be(self.hdr, 8))

    @ack.setter
    def ack(self, val):
        w32be(self.hdr, 8, int(val))

    @property
    def doff(self):
        return self.hdr[12] >> 4

    @doff.setter
    def doff(self, v):
        self.hdr[12] = (self.hdr[12] & 0x0f) | ((v & 0xf) << 4)

    @property
    def CWR(self):
        return self.hdr[13] >> 7

    @CWR.setter
    def CWR(self, v):
        self.hdr[13] = (self.hdr[13] & 0xef) | ((v & 1) << 7)

    @property
    def ECE(self):
        return (self.hdr[13] >> 6) & 1

    @ECE.setter
    def ECE(self, v):
        self.hdr[13] = (self.hdr[13] & 0xbf) | ((v & 1) << 6)

    @property
    def URG(self):
        return (self.hdr[13] >> 5) & 1

    @URG.setter
    def URG(self, v):
        self.hdr[13] = (self.hdr[13] & 0xdf) | ((v & 1) << 5)

    @property
    def ACK(self):
        return (self.hdr[13] >> 4) & 1

    @ACK.setter
    def ACK(self, v):
        self.hdr[13] = (self.hdr[13] & 0xef) | ((v & 1) << 4)

    @property
    def PSH(self):
        return (self.hdr[13] >> 3) & 1

    @PSH.setter
    def PSH(self, v):
        self.hdr[13] = (self.hdr[13] & 0xf7) | ((v & 1) << 3)

    @property
    def RST(self):
        return (self.hdr[13] >> 2) & 1

    @RST.setter
    def RST(self, v):
        self.hdr[13] = (self.hdr[13] & 0xfb) | ((v & 1) << 2)

    @property
    def SYN(self):
        return (self.hdr[13] >> 1) & 1

    @SYN.setter
    def SYN(self, v):
        self.hdr[13] = (self.hdr[13] & 0xfd) | ((v & 1) << 1)

    @property
    def FIN(self):
        return self.hdr[13] & 1

    @FIN.setter
    def FIN(self, v):
        self.hdr[13] = (self.hdr[13] & 0xfe) | (v & 1)

    @property
    def wnd(self):
        return r16be(self.hdr, 14)

    @wnd.setter
    def wnd(self, v):
        w16be(self.hdr, 14, v & 0xffff)

    @property
    def checksum(self):
        return r16be(self.hdr, 16)

    @checksum.setter
    def checksum(self, v):
        w16be(self.hdr, 16, v & 0xffff)

    @property
    def urg(self):
        return r16be(self.hdr, 18)

    @urg.setter
    def urg(self, v):
        w16be(self.hdr, 18, v & 0xffff)

    @property
    def options(self):
        res = []
        hdr = self.hdr
        sz = len(hdr)
        i = 20
        while i < sz:
            t = hdr[i]
            if t == 0:
                break
            elif t == 1:
                i += 1
                continue
            n = hdr[i+1]
            if n > 2:
                v = 0
                k = 0
                j = n - 2
                while k < j:
                    v = (v << 8) + hdr[i+2+k]
                    k += 1
                res.append((t, n, v))
            i += n
        return res

    @property
    def mss(self):
        for (t, n, v) in self.options:
            if t == 2 and n == 4:
                return v

    @property
    def ws(self):
        for (t, n, v) in self.options:
            if t == 3 and n == 3:
                return v

    @property
    def sack(self):
        for (t, n, _) in self.options:
            if t == 4 and n == 2:
                return True

    @property
    def timestamp(self):
        for (t, n, v) in self.options:
            if t == 8 and n == 10:
                return (v >> 32, v & 0xffffffff)

    @property
    def len(self):
        return len(self.data) + self.SYN + self.FIN

    def pack(self, iphdr):
        self.checksum = 0
        if iphdr:
            self.checksum = chksum_iphdr3(6, iphdr, self.hdr, self.data)
        return self.hdr + self.data


def decode(bs, iphdr=None):
    if isinstance(bs, Pack):
        return bs
    if len(bs) < 20:
        raise DecodeError('segment too small %s' % bs)
    if iphdr:
        if chksum_iphdr2(6, iphdr, bs) != 0:
            raise DecodeError('checksum error %s' % bs)

    hsz = bs[12] >> 2
    if hsz < 20 or hsz > 60:
        raise DecodeError('bad data offset field %d' % hsz)

    return Pack(_raw=bs)


# Simple ISS generator that bumps 64000 every 0.5 seconds
# or when a new connection is established.
_genisn = seq32(1)
def gen_isn(la, fa):
    global _genisn
    isn = _genisn
    _genisn += 64000
    return isn

# A simplistic implementation that will overflow
# IANA: 49152 to 65535
_ephemeral_port = 49152

def _alloc_port():
    global _ephemeral_port
    p = _ephemeral_port
    _ephemeral_port += 1
    assert p <= 65535
    return p

class SockError(Exception):
    def __init__(self, typ, msg):
        self.typ = typ
        self.msg = msg
    def __str__(self):
        return '%s: %s' % (self.typ, self.msg)

class SocketIO(io.RawIOBase):
    '''from socket.SocketIO'''
    def __init__(self, sock, mode):
        if mode not in ("r", "w", "rw", "rb", "wb", "rwb"):
            raise ValueError("invalid mode: %r" % mode)
        io.RawIOBase.__init__(self)
        self._sock = sock
        if "b" not in mode:
            mode += "b"
        self._mode = mode
        self._reading = "r" in mode
        self._writing = "w" in mode

    def readinto(self, b):
        return self._sock.recv_into(b)

    def write(self, b):
        return self._sock.send(b)

    def readable(self):
        return not self.closed and self._reading

    def writable(self):
        return not self.closed and self._writing

    def seekable(self):
        return False

    def fileno(self):
        return -1

    @property
    def name(self):
        return -1

    @property
    def mode(self):
        return self._mode

    def close(self):
        if self.closed:
            return
        io.RawIOBase.close(self)

# Retransmission record
RTS = collections.namedtuple('RTS', 'tmo, n, t, seg')

# TCP state
@enum.unique
class TCPS(enum.IntEnum):
    CLOSED = 0
    LISTEN = 1
    SYN_SENT = 2
    SYN_RCVD = 3
    ESTABLISHED = 4
    CLOSE_WAIT = 5
    FIN_WAIT_1 = 6
    CLOSING = 7
    LAST_ACK = 8
    FIN_WAIT_2 = 9
    TIME_WAIT = 10

_slock = threading.Lock()
_binding_socks = []
_listening_socks = []
_active_socks = []

# TCP timer
class _Timer(threading.Thread):
    def __init__(self, name, interval):
        threading.Thread.__init__(self, name=name, daemon=True)
        self.interval = interval
        self.stopped = threading.Event()

    def stop(self):
        self.stopped.set()

    def run(self):
        while not self.stopped.wait(self.interval):
            global _genisn
            _genisn += 64000
            now = time.time()
            with _slock:
                for s in _active_socks:
                    s._timeout(now)
        log.info('TIMER STOPPED')

class _Socket:
    def __init__(self, blocking=True, timeout=None):
        #self._lock = threading.RLock()
        self.blocking = blocking
        self.timeout = timeout
        self.la = None
        self.fa = None
        self._opt = {}
        self._st = self._st_p = TCPS.CLOSED
        self._reason = None
        self._eoi = None

    def __repr__(self):
        if self._st == TCPS.ESTABLISHED:
            return '[%s:%s]' % (self.la, self.fa)
        else:
            return ('[%s:%s %s]'
                    % (self.la, self.fa, self._st.name))

    def log(self, fmt, *args):
        log.info('%s: ' + fmt, self, *args)

    def dbg(self, fmt, *args):
        log.debug('%s: ' + fmt, self, *args)

    def warn(self, fmt, *args):
        log.warning('%s: ' + fmt, self, *args)

    def error(self, fmt, *args):
        log.error('%s: ' + fmt, self, *args)

    def bind(self, laddr):
        if self.la is not None:
            raise SockError('bind', 'already bound')
        ip, port = laddr
        ip = ip4(ip)
        if port == 0:
            port = _alloc_port()
        if not 0 < port < 65535:
            raise SockError('bind', 'invalid port number %d' % port)
        with _slock:
            if any(s.la.port == port and s.la.ip == ip
                   for s in (_active_socks
                             + _listening_socks
                             + _binding_socks)):
                raise SockError('bind', 'address %s:%s already in use'
                                % (ip, port))
            self.la = sockaddr(ip, port)
            _binding_socks.append(self)
        return self

    def setsockopt(self, **opt):
        self._opt = opt

    def getsockopt(self):
        return self._opt

    def getsockname(self):
        return self.la

    def settimeout(self, val):
        if val is None:
            self.blocking = True
            self.timeout = None
        elif val == 0:
            self.blocking = False
            self.timeout = None
        elif val > 0:
            self.blocking = True
            self.timeout = val

    def setblocking(self, val):
        if val:
            self.settimeout(None)
        else:
            self.settimeout(0)
    
    def connect(self, addr):
        if self in _active_socks:
            raise SockError('connect', 'connection alreay exists')
        if self in _listening_socks:
            raise SockError('connect', 'listening socket')
            
        ip, port = addr
        ip = ip4(ip)
        if ip == 0:
            raise SockError('connect', 'ip address not specified')
        if port == 0:
            raise SockError('connect', 'port not specified')
        if not 0 < port < 65535:
            raise SockError('connect', 'invalid port number %d' % port)

        with _slock:
            if self in _binding_socks:
                if self.la.ip == 0:
                    lip = net.ip_hint(ip)
                    if not lip:
                        raise SockError('connect', 'no route to %s' % ip)
                    assert(self.la.port)
                    self.la = sockaddr(lip, self.la.port)
                _binding_socks.remove(self)
            else:
                assert self.la is None
                lip = net.ip_hint(ip)
                if not lip:
                    raise SockError('connect', 'no route to %s' % ip)
                self.la = sockaddr(lip, _alloc_port())

            self.fa = sockaddr(ip, port)
            assert all(s.la != self.la or s.fa !=  self.fa
                       for s in _active_socks)
            self._inq = queue.Queue()
            self._txbuf = b''
            self._rtq = []
            _active_socks.append(self)

            self.iss = gen_isn(self.la, self.fa)
            self.snd_una = self.iss
            self.snd_nxt = self.iss + 1
            self._send(None, self.iss, None,
                       (MaxSynRetries, SynInterval),
                       SYN=1, wnd=DefWindowSize, mss=1460)
            self._trans(TCPS.SYN_SENT)

        # block
        self._connect_evt = threading.Event()
        self._connect_status = None
        self._connect_evt.wait()
        if self._connect_status is not None:
            raise SockError('Connect', self._connect_status)

    def listen(self, backlog=DefSynBacklog):
        if self._st != TCPS.CLOSED:
            raise SockError('Listen', 'bad socket/state')

        with _slock:
            if not self in _binding_socks:
                assert self.la is None
                # this is rare but permitted
                self.la = sockaddr(ip4(0), _alloc_port())
            else:
                _binding_socks.remove(self)
            assert all(s.la.port != self.la.port
                       or (s.la.ip and self.la.ip and s.la.ip != self.la.ip)
                       for s in _listening_socks)
            self._trans(TCPS.LISTEN)
            self._pending_conns = queue.Queue()
            _listening_socks.append(self)

    def accept(self, block=True, timeout=None):
        if not hasattr(self, '_pending_conns'):
            raise SockError('accept', 'bad socket')

        assert self in _listening_socks

        try:
            so = self._pending_conns.get(block=block, timeout=timeout)
        except queue.Empty:
            return None

        return (so, so.fa)

    def send(self, data, *, blocking=True):
        if self._st in (TCPS.FIN_WAIT_1, TCPS.FIN_WAIT_2, TCPS.CLOSING,
                        TCPS.TIME_WAIT, TCPS.LAST_ACK):
            raise SockError('send', 'connection is closing')

        # TODO: what if LISTEN, SYN_SENT, SYN_RCVD?
        if self._st not in (TCPS.ESTABLISHED, TCPS.CLOSE_WAIT):
            raise SockError('send', 'no connection')

        if not data:
            return 0

        if isinstance(data, str):
            data = data.encode()

        buf = b''.join((self._txbuf, data))
        mss = self.peer_mss
        limit = self.snd_una + self.snd_wnd - self.snd_nxt
        nbytes = min(len(buf), limit)
        n = 0
        while 1:
            m = min(mss, nbytes)
            if m > 0:
                self._send(buf[n:n+m], self.snd_nxt + n, self.rcv_nxt,
                           (RetransmissionN, RetransmissionT))
                n += m
                nbytes -= m
            else:
                break

        self.snd_nxt += + n
        self._txbuf = buf[n:]

        if nbytes > 0:
            log.info('sending window closed: %d %d %d',
                     self.snd_una, self.snd_nxt, self.snd_wnd)

        return n

    def recv(self, blocking=None, timeout=None):
        if self._st == TCPS.CLOSED:
            raise SockError('recv', 'no connection')
        if self._st in (TCPS.CLOSING, TCPS.TIME_WAIT, TCPS.LAST_ACK):
            raise SockError('send', 'connection is closing')
        if self._st == TCPS.CLOSE_WAIT:
            # TODO: check if there is data
            #raise SockError('recv', 'connection is closing')
            return None

        if blocking is None:
            blocking = self.blocking
        if timeout is None:
            timeout = self.timeout

        try:
            data = self._inq.get(block=blocking, timeout=timeout)
        except queue.Empty:
            return None
        return data

    def recv_into(self, buffer, nbytes=0, flags=0):
        if nbytes < 0:
            raise SockError('recv_into', 'negative buffer size')
        data = self.recv()
        n = _memcopy(buffer, nbytes, data)
        if n < len(data):
            # TODO
            warning.warn('received data truncated', RuntimeWarning)
        return n

    def makefile(self, mode="r", buffering=None, *,
                 encoding=None, errors=None, newline=None):
        '''from socket.makefile'''
        if not set(mode) <= {"r", "w", "b"}:
            raise ValueError("invalid mode %r (only r, w, b allowed)" % (mode,))
        writing = "w" in mode
        reading = "r" in mode or not writing
        assert reading or writing
        binary = "b" in mode
        rawmode = ""
        if reading:
            rawmode += "r"
        if writing:
            rawmode += "w"
        raw = SocketIO(self, rawmode)
        if buffering is None:
            buffering = -1
        if buffering < 0:
            buffering = io.DEFAULT_BUFFER_SIZE
        if buffering == 0:
            if not binary:
                raise ValueError("unbuffered streams must be binary")
            return raw
        if reading and writing:
            buffer = io.BufferedRWPair(raw, raw, buffering)
        elif reading:
            buffer = io.BufferedReader(raw, buffering)
        else:
            assert writing
            buffer = io.BufferedWriter(raw, buffering)
        if binary:
            return buffer
        text = io.TextIOWrapper(buffer, encoding, errors, newline)
        text.mode = mode
        return text

    def abort(self):
        with _slock:
            if self in _binding_socks:
                _binding_socks.remove(self)
            elif self in _listening_socks:
                self._close('close()')
            elif self in _active_socks:
                if self._st == TCPS.LISTEN:
                    self._close('abort()')
                elif self._st == TCPS.SYN_SENT:
                    self._close('abort()')
                elif self._st == TCPS.SYN_RCVD:
                    self._send(None, self.snd_nxt, None, None, RST=1)
                    self._close('abort()')
                elif self._st == TCPS.ESTABLISHED:
                    self._send(None, self.snd_nxt, None, None, RST=1)
                    self._close('abort()')
                elif self._st in (TCPS.FIN_WAIT_1, TCPS.FIN_WAIT_2):
                    self._send(None, self.snd_nxt, None, None, RST=1)
                    self._close('abort()')
                elif self._st in (TCPS.CLOSING, TCPS.TIME_WAIT):
                    self._close('abort()')
                elif self._st == TCPS.CLOSE_WAIT:
                    self._send(None, self.snd_nxt, None, None, RST=1)
                    self._close('abort()')
                elif self._st == TCPS.LAST_ACK:
                    self._close('abort()')
                else:
                    assert 0
            else:
                pass

    def close(self):
        with _slock:
            if self in _binding_socks:
                _binding_socks.remove(self)
            elif self in _listening_socks:
                self._close('close()')
            elif self in _active_socks:
                if self._st in (TCPS.FIN_WAIT_1, TCPS.FIN_WAIT_2, TCPS.CLOSING,
                                TCPS.TIME_WAIT, TCPS.LAST_ACK):
                    raise SockError('close', 'connection is closing')
                if self._st == TCPS.LISTEN:
                    self._close('close()')
                elif self._st == TCPS.SYN_SENT:
                    self._close('close()')
                elif self._st == TCPS.SYN_RCVD:
                    self._send(None, self.snd_nxt, None, None, FIN=1)
                    self._trans(TCPS.FIN_WAIT_1)
                elif self._st == TCPS.ESTABLISHED:
                    self._send(None, self.snd_nxt, self.rcv_nxt, None, FIN=1)
                    self.snd_nxt += 1
                    self._trans(TCPS.FIN_WAIT_1)
                elif self._st == TCPS.CLOSE_WAIT:
                    self._send(None, self.snd_nxt, self.rcv_nxt, None, FIN=1)
                    self.snd_nxt += 1
                    self._trans(TCPS.LAST_ACK)
                else:
                    assert 0
            else:
                pass

    def _trans(self, st):
        #self.dbg('%s -> %s', self._st_p, st)
        self._st_p, self._st = self._st, st

    def __send(self, seg):
        self.dbg('%r', seg)
        send_ip(self.la.ip, self.fa.ip, seg)

    def _send(self, data, seq, ack, tmo, **args):
        seg = Pack(sp=self.la.port, dp=self.fa.port,
                   seq=seq,
                   ack=0 if ack is None else ack,
                   data=data, ACK=ack is not None,
                   **args)
        if tmo:
            assert tmo[0]
            assert tmo[1]
            self._rtq.append(RTS(time.time() + tmo[1], tmo[0], tmo[1], seg))
        self.__send(seg)

    def _abort(self):
        self._send(None, self.twl, None, None, RST=1)
        self._trans(TCPS.CLOSED)

    def _close(self, reason):
        self.log('_close: %s', reason)
        if self in _listening_socks:
            if self._pending_conns.qsize():
                log.warn('closing listening socket while there'
                         ' are pending connections')
            self._pending_conns.put(None)
            _listening_socks.remove(self)
        else:
            assert self in _active_socks
            self._rtq.clear()
            self._inq.put(None)
            if hasattr(self, '_connect_evt'):
                if self._connect_status is None:
                    self._connect_status = 'Timeout'
                self._connect_evt.set()
            _active_socks.remove(self)

    def _timeout(self, now):
        if self._st == TCPS.TIME_WAIT and now > self._tw_tmo:
            assert not self._rtq
            self._close('TIME_WAIT timeout')
        else:
            rtq = []
            for e in self._rtq:
                if e.tmo > now:
                    rtq.append(e)
                    continue
                n = e.n - 1
                if n == 0:
                    self.error('***transmission timeout,'
                               ' failed segment: %s', e.seg)
                    self._close('transmission timeout')
                    return
                assert e.t
                rtq.append(RTS(now + e.t * 1.9, n, e.t, e.seg))
                self.log('Retransmitting %s', e.seg)
                self.__send(e.seg)
            self._rtq = rtq

    def _ack_received(self, seg):
        self.pending_segment = None
        while self._rtq:
            if seg.ack >= self._rtq[0].seg.seq + self._rtq[0].seg.len:
                self._rtq.pop(0)
            else:
                break
        self.snd_una = seg.ack
        self.snd_wnd = seg.wnd * self.peer_ws

    def _check_seq(self, seg):
        # Simplifications: unlimited recv window; doesn't accept OO segments
        if seg.seq < self.rcv_nxt:
            self.warn('duplicated segment: seg.seq=%d rcv_nxt=%d', seg.seq, self.rcv_nxt)
        elif seg.seq > self.rcv_nxt:
            self.warn('out of order segment: seg.seq=%d rcv_nxt=%d', seg.seq, self.rcv_nxt)
        return seg.seq != self.rcv_nxt

    def _recv(self, from_ip, seg):
        faddr = sockaddr(from_ip, seg.sp)
        self.dbg('RECV from %s: %s', faddr, seg)

        if self._st == TCPS.CLOSED:
            # TODO: check ACK?
            self._send(None, seg.ack, seg.seq + seg.len, None, RST=1)
            return

        if self._st == TCPS.LISTEN:
            if seg.RST:
                self.warn('RST from %s', faddr)
            elif seg.ACK:
                self.warn('ACK from %s', faddr)
                if self in _active_socks:
                    self._send(None, seg.ack, None, None, RST=1)
            elif seg.FIN:
                self.warn('FIN from %s', faddr)
                if self in _active_socks:
                    self._send(None, seg.ack, None, None, RST=1)
                return
            elif seg.SYN:
                if seg.data:
                    # TODO
                    self.error('SYN with data')
                    return
                if hasattr(self, '_pending_conns'):
                    # this is a listening socket
                    if self._pending_conns.qsize() > MaxSynBacklog:
                        self.warn('backlog queue overflow!')
                        return
                    newso = _Socket(self.blocking, self.timeout)
                    newso.la = self.la
                    newso._st = TCPS.LISTEN
                    newso._listenq = self._pending_conns
                    newso._inq = queue.Queue()
                    newso._txbuf = b''
                    newso._rtq = []
                    newso.fa = faddr
                    # _slock should be hold
                    _active_socks.append(newso)
                    newso._recv(from_ip, seg)
                    return
                self.irs = seg.seq
                self.rcv_nxt = seg.seq + 1
                if seg.ws:
                    self.peer_ws = 1 << seg.ws
                else:
                    self.peer_ws = 1
                self.snd_wnd = seg.wnd * self.peer_ws
                if seg.mss:
                    self.peer_mss = seg.mss
                else:
                    self.peer_mss = 576
                if self.la.ip == 0:
                    # update local
                    self.la = sockaddr(net.ip_hint(from_ip), self.la.port)
                    assert self.la.ip
                self.iss = gen_isn(self.la, self.fa)
                self.snd_nxt = self.iss + 1
                self.snd_una = self.iss
                self._send(None, self.iss, self.rcv_nxt,
                           (MaxSynAckRetries, SynInterval),
                           SYN=1, wnd=DefWindowSize, mss=1460)
                self._trans(TCPS.SYN_RCVD)
            else:
                self.warn('bad segment from %s', faddr)
                self._send(None, seg.ack, None, None, RST=1)
            return

        if self._st == TCPS.SYN_SENT:
            if seg.ACK:
                if seg.ack != self.iss + 1:
                    self.warn('bad ACK, expecting %d, got %d', self.iss+1, seg.ack)
                    self._send(None, seg.ack, None, None, RST=1)
                elif seg.RST:
                    self.warn('Connection refused by %s', faddr)
                    # unblock connect()
                    self._connect_evt.set()
                    self._connect_status = 'Connection refused'
                    self._close('Connection refused')
                elif seg.SYN:
                    self.irs = seg.seq
                    self.rcv_nxt = seg.seq + 1
                    if seg.ws:
                        self.peer_ws = 1 << seg.ws
                    else:
                        self.peer_ws = 1
                    self.snd_wnd = seg.wnd * self.peer_ws
                    if seg.mss:
                        self.peer_mss = seg.mss
                    else:
                        self.peer_mss = 576
                    self._ack_received(seg)
                    self.log('connected with %s', faddr)
                    # unblock connect()
                    self._send(None, self.snd_nxt, self.rcv_nxt, None)
                    self._trans(TCPS.ESTABLISHED)
                    self._connect_evt.set()
                else:
                    # keep waiting
                    self.warn('ACK w/o SYN from %s', faddr)
            elif seg.RST:
                self.warn('receiving RST in SYN_SENT')
                return
            elif seg.SYN:
                # TODO
                self.warn('Simultaneous SYN')
            else:
                # TODO: send a RST?
                self.warn('bad segment from %s', faddr)
            return

        if self._st == TCPS.SYN_RCVD:
            if self._check_seq(seg):
                # keep waiting, will retransmit or timeout
                pass
            elif seg.RST:
                self._rtq.clear()
                if self._st_p == TCPS.LISTEN:
                    self.warn('RST segment, back to LISTEN')
                    self._trans(TCPS.LISTEN)
                else:
                    # connection was initiated with an active open
                    self.warn('RST segment, closing')
                    self._close('RST from peer in SYN_RCVD')
            elif seg.SYN:
                self.error('bad SYN, closing')
                self._rtq.clear()
                self._send(None, self.snd_nxt, None, None, RST=1)
                self._close('bad SYN from peer in SYN_RCVD')
            elif seg.FIN:
                self.warn('FIN in SYN_RCVD')
                self._rtq.clear()
                self.rcv_nxt = seg.seq + 1
                self._send(None, self.snd_nxt, self.rcv_nxt, None)
                self._trans(TCPS.CLOSE_WAIT)
            elif not seg.ACK:
                # keep waiting
                self.warn('expecting ACK')
            elif seg.ack != self.iss + 1:
                self.error('bad ACK, closing')
                self._send(None, self.snd_nxt, None, None, RST=1)
                self._close('bad ACK from peer in SYN_RCVD')
            else:
                self._ack_received(seg)
                if seg.data:
                    self.warn('ACK with data')
                    self._inq.put(bytes(seg.data))
                    self.rcv_nxt = seg.seq + len(seg.data)
                self.log('Connected with %s', faddr)
                self._trans(TCPS.ESTABLISHED)
                # ready to be accept()
                self._listenq.put(self)
                del self._listenq
            return

        # check incoming segment

        if self._check_seq(seg):
            if not seg.RST:
                self._send(None, self.snd_nxt, self.rcv_nxt, None)
                return

        if seg.RST:
            self.warn('RST segment, closing')
            self._close('RST from peer')
            return

        if seg.SYN:
            self.error('SYN segment, closing')
            self._send(None, self.snd_nxt, None, None, RST=1)
            self._close('bad SYN from peer')
            return

        if seg.ACK:
            if seg.ack > self.snd_nxt:
                self.warn('invalid ACK, ack (%d) > %d', seg.ack, self.snd_nxt)
                return
            elif seg.ack < self.snd_una:
                self.warn('obsolete ACK')
                return
            else:
                self._ack_received(seg)
        elif self._st not in (TCPS.FIN_WAIT_1, TCPS.FIN_WAIT_2):
            self.warn('ACK is off')
            return

        # data transfer

        if self._st == TCPS.ESTABLISHED:
            if seg.seq == self.rcv_nxt:
                if seg.data:
                    self._inq.put(bytes(seg.data))
                self.rcv_nxt = seg.seq + seg.len
                # TODO: delayed ACK instead of immediate ACK
                self._send(None, self.snd_nxt, self.rcv_nxt, None)
                if seg.FIN:
                    # passive close
                    self._inq.put(None)
                    self._trans(TCPS.CLOSE_WAIT)
            else:
                self.warn('OO segment')
            return

        # passive close

        if self._st == TCPS.CLOSE_WAIT:
            if seg.FIN:
                log.warn('FIN_ACK lost, resent')
                self._send(None, self.snd_nxt, self.rcv_nxt, None)
            return

        if self._st == TCPS.LAST_ACK:
            self.log('Connection closed (passive)')
            self._close('Connection closed (passive)')
            return

        # active close

        if self._st == TCPS.FIN_WAIT_1:
            if seg.seq == self.rcv_nxt:
                if seg.data:
                    self.warn('RECV data in FIN_WAIT_1')
                    self._inq.put(bytes(seg.data))
                self.rcv_nxt = seg.seq + seg.len
                if seg.ACK:
                    if seg.FIN:
                        self._send(None, self.snd_nxt, self.rcv_nxt, None)
                        self._tw_tmo = time.time() + MSL * 2
                        self._trans(TCPS.TIME_WAIT)
                    else:
                        self._trans(TCPS.FIN_WAIT_2)
                elif seg.FIN:
                    self.warn('simultaneous FIN')
                    self._send(None, self.snd_nxt, self.rcv_nxt, None)
                    self._trans(TCPS.CLOSING)
            else:
                self.warn('OO segment')
            return

        if self._st == TCPS.FIN_WAIT_2:
            if seg.seq == self.rcv_nxt:
                if seg.data:
                    self.warn('RECV data in FIN_WAIT_2')
                    self._inq.put(bytes(seg.data))
                self.rcv_nxt = seg.seq + seg.len
                if seg.FIN:
                    self._send(None, self.snd_nxt, self.rcv_nxt, None)
                    self._tw_tmo = time.time() + MSL * 2
                    self._trans(TCPS.TIME_WAIT)
            else:
                self.warn('OO segment')
            return

        if self._st == TCPS.CLOSING:
            self._tw_tmo = time.time() + MSL * 2
            self._trans(TCPS.TIME_WAIT)
            return

        # time wait

        if self._st == TCPS.TIME_WAIT:
            if seg.FIN:
                self.warn('lost FIN_ACK, resent')
                self._send(None, self.snd_nxt, seg.seq + 1, None)
                self._tw_tmo = time.time() + MSL * 2
            else:
                self.warn('spurious segment in TIME_WAIT')
            return

        # shouldn't reach here
        self.error('***unhandled segment!')
        assert 0

def socket(blocking=True, timeout=None):
    return _Socket(blocking, timeout)

def send_ip(from_ip, to_ip, segment, **ip_opts):
    from_ip = ip4(from_ip)
    to_ip = ip4(to_ip)
    return ipv4.send(from_ip, to_ip, segment, **ip_opts)

def notify(sip, icmppkt, ippkt):
    assert isinstance(icmppkt, icmp.Pack)
    try:
        pac = decode(ippkt.pdu)
    except DecodeError as e:
        log.error('cannot retrive the offending segment from'
                  ' ICMP packet: %s', e)
        return
    # TODO
    log.warning('ICMP from %s: %s, original packet: %s', sip, icmppkt, ippkt)

def recv(iphdr, sip, dip, bs):
    _stat.rx_total += 1
    if isinstance(bs, Pack):
        # loopback
        seg = bs
    else:
        if len(bs) < 20:
            log.error('short segment')
            _stat.rx_short += 1
            return
        if chksum_iphdr2(6, iphdr, bs) != 0:
            log.error('bad checksum')
            _stat.rx_bad_checksum += 1
            return
        doff = bs[12] >> 2
        if doff < 20 or doff > 60:
            log.error('bad data offset %d', doff)
            _stat.rx_bad_doff += 1
            return
        seg = Pack(_raw=bs)

    with _slock:
        for s in _active_socks:
            if (s.la.port == seg.dp
                and (s.la.ip == 0 or s.la.ip == dip)
                and (s.fa.ip == sip and s.fa.port == seg.sp)):
                s._recv(sip, seg)
                return

        for s in _listening_socks:
            if (s.la.port == seg.dp
                and (s.la.ip == 0 or s.la.ip == dip)):
                s._recv(sip, seg)
                return

        log.info('port %d unavailable: %s:%d -> %s:%d',
                 seg.dp, sip, seg.sp, dip, seg.dp)

        for s in _binding_socks:
            if (s.la.port == seg.dp and (s.la.ip == 0 or s.la.ip == dip)):
                # hasn't call connect() or listen() yet
                # simply drop the incoming segment and the
                # sender will timeout and resend.
                return

    if seg.RST or dip.is_multicast():
        return

    # send RST
    send_ip(dip, sip, Pack(sp=seg.dp,
                           dp=seg.sp,
                           RST=1,ACK=1,
                           ack=seg.seq+1),
            DF=1)

_timer_thr = _Timer(name='tcp', interval=0.5)

def shutdown():
    # TODO: close active connections
    _timer_thr.stop()

def start():
    # TODO: quiet time
    _timer_thr.start()
