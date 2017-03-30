'''PyIP startup script'''

import sys, os

scriptdir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(scriptdir))

prog = sys.argv.pop(0)

nowin = '-nw' in sys.argv
if nowin:
    sys.argv.remove('-nw')

dhcp = '-dhcp' in sys.argv
if dhcp:
    sys.argv.remove('-dhcp')

cidr = None
if len(sys.argv) > 0:
    cidr = sys.argv.pop(0)

tap = 'tap0'
console = 'xterm'

if sys.argv or (not dhcp and not cidr):
    print('Usage: %s [-nw] [-dhcp | cidr]', file=sys.stderr)
    exit(2)

import common

stream = None
if not nowin:
    stream = common.open_console(console)

import logging
log = logging.getLogger('')
logh = logging.StreamHandler(stream)
logh.setFormatter(logging.Formatter('[%(name)s|%(levelname)s] %(message)s'))
log.addHandler(logh)
log.setLevel(logging.INFO)

import net

try:
    if dhcp:
        net.start_dhcp(tap)
    else:
        net.start(tap, cidr)
except OSError as e:
    print(e, file=sys.stederr)
else:
    print('PyIP @ [%s]' % net._netifs[0].ip)
