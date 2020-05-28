#!/usr/bin/env python

from setuptools import setup
from mypyq import __version__ as version

setup(name='mypyq',
      version=version,
      author='Y. Talvet',
      author_email='hurin8888@gmail.com',
      url='http://github.com/Meithal/mypyq/',
      description='A modern Python library for extracting MPQ (MoPaQ) files.',
      py_modules=['mypyq', 'explode'],
      classifiers=[
          'Development Status :: 2 - Pre-Alpha',
          'Environment :: Console',
          'Intended Audience :: End Users/Desktop',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: zlib/libpng License',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: Microsoft :: Windows',
          'Operating System :: POSIX',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Topic :: Games/Entertainment :: Real Time Strategy',
          'Topic :: Software Development :: Libraries',
          'Topic :: System :: Archiving',
      ],
      )
