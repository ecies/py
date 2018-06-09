# eciespy
Elliptic Curve Integrated Encryption Scheme for secp256k1 in Python


[![License](https://img.shields.io/github/license/kigawas/eciespy.svg)](https://github.com/kigawas/eciespy)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/eciespy.svg)](https://pypi.org/project/eciespy/)
[![PyPI](https://img.shields.io/pypi/v/eciespy.svg)](https://pypi.org/project/eciespy/)
[![Travis branch](https://img.shields.io/travis/kigawas/eciespy/master.svg)](https://travis-ci.org/kigawas/eciespy)
[![Codecov](https://img.shields.io/codecov/c/github/kigawas/eciespy.svg)](https://codecov.io/gh/kigawas/eciespy)

# Install
`pip install eciespy`

# Quick Start

```python
>>> from ecies.utils import generate_eth_key
>>> from ecies import encrypt, decrypt
>>> k = generate_eth_key()
>>> prvhex = k.to_hex()
>>> pubhex = k.public_key.to_hex()
>>> data = b'this is a test'
>>> decrypt(prvhex, encrypt(pubhex, data))
b'this is a test'
```

Or just use a builtin command `eciespy -h` in your favorite command line.
