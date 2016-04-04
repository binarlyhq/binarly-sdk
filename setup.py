#!/usr/bin/env python

from distutils.core import setup

setup(name='BinarlySDK',
      version='1.0',
      description='Binarly API',
      author='Binarly Team',
      author_email='contact@binar.ly',
      url='https://github.com/binarlyhq/binarly-sdk',
      py_modules=['BinarlyAPIv1'],
      install_requires=['requests']
      )
