#!/usr/bin/env python3

import os, sys, glob
import time
import subprocess

scriptdir = os.path.dirname(os.path.abspath(__file__))
testdir = os.path.join(scriptdir, 'test')

verbose = False
printout = False
timeout = 10

if '-v' in sys.argv:
    verbose = True
    sys.argv.remove('-v')

if '-vv' in sys.argv:
    verbose = True
    printout = True
    sys.argv.remove('-vv')

if len(sys.argv) > 2:
    print('Usage: %s [-v] [pattern]', sys.argv[0], file=sys.stderr)
    exit(2)

if len(sys.argv) == 2:
    pattern = 'test-' + sys.argv[1] + '.py'
else:
    pattern = 'test-*.py'

tested = []
total = ns = nt = nf = 0
t0 = time.time()

def pr(f, *args):
    print(f % args, end='', flush=True)

def pl(f, *args):
    print(f % args, flush=True)

for t in glob.glob(os.path.join(testdir, pattern)):
    n = os.path.basename(t)[:-3]
    total += 1
    if printout:
        pl(n)
    elif verbose:
        pr(n)
    start = time.time()
    p = subprocess.Popen(['python3', '-E', t], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        out, _ = p.communicate(timeout=timeout)
        rc = p.returncode
        tested.append((n, rc, out))
        if printout:
            print(out.decode(errors='ignore'), flush=True)
        if rc:
            nf += 1
            if verbose:
                pl(' FAILED')
            else:
                pr('x')
        else:
            ns += 1
            if verbose:
                pl(' %.2f seconds OK', time.time() - start)
            else:
                pr('.')
    except subprocess.TimeoutExpired as e:
        p.kill()
        nt += 1
        tested.append((n, 'TIMEOUT', e.output))
        if printout:
            print(e.output, flush=True)
        if verbose:
            pl(' TIMEOUT')
        else:
            pr('=')

if total == ns:
    print('%d tests, %.2f seconds' % (total, time.time() - t0))
else:
    print('FAILED: %d tests, %d succeed, %d failed, %d timeout, %.2f seconds'
          % (total, ns, nf, nt, time.time() - t0))

for (n, r, o) in tested:
    if r == 0 or printout or not o:
        continue
    print(n, r);
    print(o.decode(errors='ignore'), flush=True)

sys.exit(nf + nt)
