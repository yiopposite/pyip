Introduction
============
PyIP is a prototypical implementation of TCP/IP stack in Python
(except ~700 lines of C code that is either too low-level or too
inefficient if written in Python). Functionally, it turns your Python
REPL session into a virtual networking node and is capable of
exchanging packets with either the host (via the "tap" interface) or
the whole internet (via the Ethernet bridge).


Implementation
==============
The implementation includes:
- ARP
- IP/ICMP
- UDP/TCP
- Raw (IPv4) packets
- DHCP client and DNS query

A socket-like API, which to a large degree compatible with the socket
module in the Python standard library, is provided for the TCP, UDP
and Raw protocols. Additionally, some client/server programs, based on
this interface, are also included in separate modules:

- services (servers.py): echo, daytime, login, http
- clients (apps.py): ping, traceroute, wget, rlogin

A perhaps unique feature of PyIP is that it includes an extensible
logging system at the packet level to facilitate tracing and
debugging, achieving, to some degree, what wireshark can do for you.


How to use
==========

1. Initial setup
----------------
1.1 Build the _common.so extension module first:
```
$ ./build_ext.py
```
1.2. Create the tap device owned by you:
```
$ /usr/sbin/tunctl -u `id -un` -t tap0
Set 'tap0' persistent and owned by uid 1000
```
These two steps are only required for the first time use.

2. Host-only connection
-----------------------
The the simplest configuration is the host only connection, in which
PyIP communicates with the host via the tap interface:
```
$ ifconfig tap0 192.168.1.2/24 up && python3 -i pyip.py 192.168.1.3/24
PyIP @ [192.168.1.3]
>>> from apps import ping
>>> ping('192.168.1.2')
PING 192.168.1.2 56 bytes of data.
64 bytes from 192.168.1.2: seq=1 ttl=64 time=1.44ms
64 bytes from 192.168.1.2: seq=2 ttl=64 time=7.78ms
64 bytes from 192.168.1.2: seq=3 ttl=64 time=6.85ms

--- 192.168.1.2 ping statistics ---
3 packets transmitted, 3 received, average time 5.36ms
True
>>> 
```
3. Bridged connection
---------------------
Bridged connection is more involved to setup and requires a separate
Ethernet interface on the host (not a problem if the host is a virtual
machine itself). The script "hostconf" is provided to automate those
steps, but you may need to modify it first to suit your
environment. An example session using DHCP:
```
$ ./hostconf bridge up
Set 'tap0' persistent and owned by uid 1000
$ python3 -i pyip.py -dhcp
PyIP @ [10.0.3.15]
>>> import dns
>>> dns.gethostbyname('github.com')
<IP: 192.30.255.112>
>>> import apps
>>> apps.wget('192.30.255.112')
'HTTP/1.1 301 Moved Permanently\r\nContent-length: 0\r\nLocation: https:///\r\nConnection: close\r\n\r\n'
>>> 
```

Development environment
=======================

> $ uname -a
Linux envy 4.0.4-301.fc22.x86_64 #1 SMP Thu May 21 13:10:33 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

> $ python3 --version
Python 3.4.2