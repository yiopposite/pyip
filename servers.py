# -*- coding: utf-8 -*-

'''Various small TCP/IP server programs
 - echo (7/TCP)
 - daytime (13/UDP)
 - login (513/TCP)
 - http (80/TCP)
'''

import threading
import time
import os, select, pty
import logging
import datetime
import http.server

import tcp, udp
from common import *

log = logging.getLogger(__name__)

class udp_daytime(threading.Thread):
    '''$ nc -u4 192.168.1.3 13'''
    PORT = 13
    def __init__(self):
        threading.Thread.__init__(self, name=self.__class__.__name__, daemon=True)

    def run(self):
        sock = udp.socket()
        sock.bind((0, self.PORT))
        while True:
            cli = sock.recvfrom()
            if not cli:
                break
            sock.sendto(cli[0], ('%s\r\n' % datetime.datetime.today()).encode())
        log.info('[daytime]: server stopped')

class tcp_echo(threading.Thread):
    '''$ nc -t4 192.168.1.3 7'''
    PORT = 7
    def __init__(self):
        threading.Thread.__init__(self, name=self.__class__.__name__, daemon=True)

    @staticmethod
    def cli(conn):
        try:
            while True:
                data = conn.recv()
                if not data:
                    break
                conn.send(data)
        finally:
            conn.close()

    def run(self):
        so = tcp.socket().bind((0, self.PORT))
        so.listen()
        try:
            while True:
                conn = so.accept()
                if not conn:
                    break
                (conn, _) = conn
                threading.Thread(target=self.cli, args=(conn,), name='%s' % conn).start()
        finally:
            so.close()
            log.info('[echo]: server stopped')

class tcp_login(threading.Thread):
    '''$ rlogin -luser 192.168.1.3'''
    PORT = 513
    def __init__(self):
        threading.Thread.__init__(self, name=self.__class__.__name__, daemon=True)

    @staticmethod
    def svr_writer(conn, mfd, pipe):
        try:
            while True:
                (ready, _, _) = select.select((mfd, pipe), (), ())
                if pipe in ready:
                    break
                try:
                    if mfd in ready:
                        data = os.read(mfd, 1024)
                    if not data:
                        break
                    conn.send(data)
                except OSError:
                    break
        finally:
            os.close(mfd)

    @classmethod
    def svr(cls, conn):
        log.info('[login]: connected with %s', conn.fa)
        data = conn.recv()
        if data != b'\x00':
            conn.close()
            return

        data = conn.recv()
        data = [b.decode() for b in data[:-1].split(b'\x00')]
        log.info('[login]: suser %s, cuser %s, term %s', *data)
        conn.send(b'\x00')
        conn.send('Welcome to PyIP @ %s\r\n\x00' % conn.la.ip)

        pid, mfd = pty.fork()
        if pid == 0:
            os.execl('/bin/sh', '/bin/sh')
        else:
            pipe = os.pipe()
            wr = threading.Thread(target=cls.svr_writer, args=(conn, mfd, pipe[0]))
            wr.start()
            try:
                while True:
                    # TODO: this will block in case of an active close from
                    # the server. An extra keystroke is required to properly
                    # end the session.
                    data = conn.recv()
                    if not data:
                        log.info('[login]: client disconnected')
                        break
                    try:
                        os.write(mfd, data)
                    except OSError:
                        break
            finally:
                os.write(pipe[1], b'\n')
                wr.join()
                os.close(pipe[0])
                os.close(pipe[1])
                conn.close()
        log.info('[login]: end session with %s', conn.fa)

    def run(self):
        so = tcp.socket().bind((0, self.PORT))
        so.listen()
        try:
            while True:
                conn = so.accept()
                if not conn:
                    break
                (conn, _) = conn
                threading.Thread(target=self.svr, args=(conn,), name='%s' % conn).start()
        finally:
            so.close()
            log.info('[longin]: server stopped')


class tcp_http(threading.Thread):
    PORT = 80
    def __init__(self):
        threading.Thread.__init__(self, name=self.__class__.__name__, daemon=True)

    def run(self):
        so = tcp.socket().bind((0, self.PORT))
        so.listen()
        try:
            while True:
                conn = so.accept()
                if not conn:
                    break
                (conn, faddr) = conn
                try:
                    http.server.SimpleHTTPRequestHandler(conn, faddr, None)
                finally:
                    conn.close()
        finally:
            so.close()
            log.info('[http]: server stopped')

def start():
    for (n, s) in globals().items():
        if ((n.startswith('udp_') or n.startswith('tcp_'))
            and hasattr(s, 'PORT')):
            log.info('start %s service on %s %d', n[4:], n[:3].upper(), s.PORT)
            s().start()
