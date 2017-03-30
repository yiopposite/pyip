#!/usr/bin/env python3

import sys
sys.argv.extend(['build_ext', '--inplace'])

from distutils.core import setup, Extension
setup(name='pyip', ext_modules=[Extension('_common', ['_commonmodule.c'])])
