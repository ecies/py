# eciespy
Elliptic Curve Integrated Encryption Scheme for secp256k1 in Python


[![License](https://img.shields.io/github/license/kigawas/eciespy.svg)](LICENSE)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/eciespy.svg)](https://pypi.org/project/eciespy/)
[![PyPI](https://img.shields.io/pypi/v/eciespy.svg)](https://pypi.org/project/eciespy/)

# Install
`pip install eciespy`

# Quickstart

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
