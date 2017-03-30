# -*- coding: utf-8 -*-

import _common
from _common import *

import os, sys
import enum

__all__ = [
    'DecodeError', 'ip4', 'macaddr', 'sockaddr', 'enum_convert',
]

__all__.extend(os._get_exports_list(_common))


class DecodeError(Exception):
    def __init__(self, msg):
        self.mod = __name__
        self.msg = msg
    def __str__(self):
        return '%s: %s' % (self.mod, self.msg)

class ip4(int):
    def __new__(cls, v=0, off=0):
        if isinstance(v, str):
            if not v:
                return int.__new__(cls, 0)
            v = [int(i) for i in v.split('.')]
            return int.__new__(cls, v[0]<<24 | v[1]<<16 | v[2]<<8 | v[3])
        if isinstance(v, (bytes, bytearray, memoryview)):
            return int.__new__(cls,
                               v[off]<<24
                               | v[off+1]<<16 | v[off+2]<<8 | v[off+3])
        if isinstance(v, ip4):
            return v
        return int.__new__(cls, v & 0xffffffff)

    def __repr__(self):
        return '<IP: %s>' % self

    def __str__(self):
        return '.'.join('%d' % b for b in
                    ((self >> 24) & 0xff,
                     (self >> 16) & 0xff,
                     (self >> 8) & 0xff,
                     self & 0xff))

    def is_broadcast(self):
        return self & 0xffffffff == 0xffffffff

    def is_multicast(self):
        return self & 0xe0000000 == 0xe0000000
     
    def is_loopback(self):
        return (self >> 24) & 0xff == 127
     
    def is_single_host(self):
        return (self != 0
                and not self.is_broadcast()
                and not self.is_multicast()
                and not self.is_loopback())


class macaddr(bytes):
    BROADCASTADDR = b'\xff' * 6

    def __new__(cls, v=None, off=0):
        if v is None:
            return bytes.__new__(cls, 6)
        if isinstance(v, macaddr):
            return v
        if isinstance(v, str):
            v = bytes.fromhex(v.replace(':', '').replace('-', ''))
            if len(v) != 6:
                raise ValueError('malformed MAC address string')
            return bytes.__new__(cls, v)
        if isinstance(v, (bytes, bytearray, memoryview)):
            return bytes.__new__(cls, v[off:off+6])
        raise ValueError('cannot convert %r to a MAC address' % v)

    def __repr__(self):
        return '<MAC: %s>' % self

    def __str__(self):
        return ':'.join('%02x' % b for b in self)

    def is_broadcast(self):
        return self == self.BROADCASTADDR

    def is_multicast(self):
        return bool(self[0] & 0x1)


class sockaddr(tuple):
    def __new__(cls, ip=0, port=0):
        return tuple.__new__(cls, (ip4(ip), port))
    def __repr__(self):
        return '<sockaddr: %s>' % self
    def __str__(self):
        return '%s:%d' % (self[0], self[1])
    @property
    def ip(self):
        return self[0]
    @property
    def port(self):
        return self[1]

# from 3.5
def enum_convert(name, module, filter):
        module_globals = vars(sys.modules[module])
        members = {name: value for name, value in module_globals.items()
                   if filter(name)}
        cls = enum.IntEnum(name, members, module=module)
        module_globals.update(cls.__members__)
        module_globals[name] = cls
        return cls

def _tbt(file=None):
    '''backtrace of all active threads'''
    import traceback, threading
    def id2thread(tid):
        for t in threading.enumerate():
            if t._ident == tid:
                return t
    if file is None:
        file = sys.stderr
    for (tid, frm) in sys._current_frames().items():
        print(id2thread(tid), file=file, flush=True)
        traceback.print_stack(frm, file=file)

