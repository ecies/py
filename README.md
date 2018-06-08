# eciespy
Elliptic Curve Integrated Encryption Scheme in Python

# Install
`pip install ecies`

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
