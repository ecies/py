# eciespy

Elliptic Curve Integrated Encryption Scheme for secp256k1 in Python

[![License](https://img.shields.io/github/license/kigawas/eciespy.svg)](https://github.com/kigawas/eciespy)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/eciespy.svg)](https://pypi.org/project/eciespy/)
[![PyPI](https://img.shields.io/pypi/v/eciespy.svg)](https://pypi.org/project/eciespy/)
[![Travis branch](https://img.shields.io/travis/kigawas/eciespy/master.svg)](https://travis-ci.org/kigawas/eciespy)
[![Codecov](https://img.shields.io/codecov/c/github/kigawas/eciespy.svg)](https://codecov.io/gh/kigawas/eciespy)

## Install

Install with `pip install eciespy` under Python version >= 3.5.

## Quick Start

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

Or just use a builtin command `eciespy` in your favorite command line.

## API

### `ecies.encrypt(receiver_pubhex: str, msg: bytes) -> bytes`

Parameters:

- **receiver_pubhex** - Receiver's ethereum public key hex string

- **msg** - Data to encrypt

Returns:  **bytes**

### `ecies.decrypt(receiver_prvhex: str, msg: bytes) -> bytes`

Parameters:

- **receiver_prvhex** - Receiver's ethereum private key hex string

- **msg** - Data to decrypt

Returns:  **bytes**

## Command Line Interface

### Show help

```bash
$ eciespy -h
usage: eciespy [-h] [-e] [-d] [-g] [-k KEY] [-D [DATA]] [-O [OUT]]

Elliptic Curve Integrated Encryption Scheme for secp256k1 in Python

optional arguments:
  -h, --help            show this help message and exit
  -e, --encrypt         encrypt with public key, not compatible with -d
  -d, --decrypt         decrypt with private key, not compatible with -e
  -g, --generate        generate ethereum key pair
  -k KEY, --key KEY     public or private key file
  -D [DATA], --data [DATA]
                        file to encrypt or decrypt, if not specified, it will
                        read from stdin
  -O [OUT], --out [OUT]
                        encrypted or decrypted file, if not specified, it will
                        write to stdout
```

### Generate eth key

```bash
$ eciespy -g
Private: 0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d
Public: 0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b
Address: 0x47e801184B3a8ea8E6A4A7A4CFEfEcC76809Da72
```

### Encrypt with public key and decrypt with private key

```bash
$ echo '0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d' > prv
$ echo '0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b' > pub
$ echo 'helloworld' | eciespy -e -k pub | eciespy -d -k prv
helloworld
$ echo 'data to encrypt' > data
$ eciespy -e -k pub -D data -O enc_data
$ eciespy -d -k prv -D enc_data
data to encrypt
$ rm data enc_data
```

## Mechanism

This library combines `secp256k1` and `AES-256-GCM` (powered by [`coincurve`](https://github.com/ofek/coincurve) and [`pycryptodome`](https://github.com/Legrandin/pycryptodome)) to provide an API of encrypting with `secp256k1` public key and decrypting with `secp256k1`'s private key. It has two steps:

1. Use [ECDH](https://www.wikiwand.com/en/Elliptic-curve_Diffie%E2%80%93Hellman) to calculate an AES session key;

    > Notice that the server public key is generated every time when `ecies.encrypt` is invoked, thus, the calculated AES session key varies.

2. Use this AES session key to encrypt/decrypt the data under `AES-256-GCM`.

Basically the encrypted data will be like this:

```plaintext
+-------------------------------+----------+----------+-----------------+
| 65 Bytes                      | 16 Bytes | 16 Bytes | == data size    |
+-------------------------------+----------+----------+-----------------+
| Server Public Key(Disposable) | Nonce/IV | Tag/MAC  | Encrypted data  |
+-------------------------------+----------+----------+-----------------+
| server_pub                    | nonce    | tag      | encrypted_data  |
+-------------------------------+----------+----------+-----------------+
|           Secp256k1           |              AES-256-GCM              |
+-------------------------------+---------------------------------------+
```

### Secp256k1

So, **how** do we calculate the ECDH key under `secp256k1`? If you use library like [`coincurve`](https://github.com/ofek/coincurve), you just simply call `k1.ecdh(k2.public_key.format())`, then uh-huh, you got it! Let's see how to do it in simple Python snippets:

```python
>>> from coincurve import PrivateKey
>>> k1 = PrivateKey(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
>>> k2 = PrivateKey(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
>>> k1.public_key.format(False).hex() # 65 bytes, False means uncompressed key
'0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
>>> k2.public_key.format(False).hex() # 65 bytes
'04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
>>> k1.ecdh(k2.public_key.format()).hex()
'b1c9938f01121e159887ac2c8d393a22e4476ff8212de13fe1939de2a236f0a7'
>>> k2.ecdh(k1.public_key.format()).hex()
'b1c9938f01121e159887ac2c8d393a22e4476ff8212de13fe1939de2a236f0a7'
```

However, as a hacker like you with strong desire to learn something, you must be curious about the magic under the ground.

In one sentence, the `secp256k1`'s ECDH key of `k1` and `k2` is nothing but `sha256(k2.public_key.multiply(k1)`.

```python
>>> k1.to_int()
1
>>> shared_pub = k2.public_key.multiply(bytes.fromhex(k1.to_hex()))
>>> shared_pub.point()
(89565891926547004231252920425935692360644145829622209833684329913297188986597,
 12158399299693830322967808612713398636155367887041628176798871954788371653930)
>>> import hashlib
>>> h = hashlib.sha256()
>>> h.update(shared_pub.format())
>>> h.hexdigest()  # here you got the ecdh key same as above!
'b1c9938f01121e159887ac2c8d393a22e4476ff8212de13fe1939de2a236f0a7'
```

Let's discuss in details. The word *multiply* here means multiplying a **point** of a public key on elliptic curve (like `(x, y)`) with a scalar (like `k`). Here `k` is the integer format of a private key, for instance, a simple `1` as `k1`, and `(x, y)` here is an extremely large number pair like `(89565891926547004231252920425935692360644145829622209833684329913297188986597, 12158399299693830322967808612713398636155367887041628176798871954788371653930)`.

Mathematically, the elliptic curve cryptography is based on the fact that you can easily multiply point `A` (aka [base point](https://www.wikiwand.com/en/Elliptic_Curve_Digital_Signature_Algorithm#/Signature_generation_algorithm), or public key in ECDH) and scalar `k` (aka private key) to get another point `B` (aka public key), but it's almost impossible to calculate `A` from `B` reversely.

A point multiplying a scalar can be regarded that this point adds itself multiple times, and the point `B` can be converted to a readable public key (compressed or uncompressed format).

- Compressed format (only use `x` coordinate)

```python
>>> point = (89565891926547004231252920425935692360644145829622209833684329913297188986597, 12158399299693830322967808612713398636155367887041628176798871954788371653930)
>>> prefix = '02' if point[1] % 2 == 0 else '03'
>>> compressed_key_hex = prefix + hex(point[0])[2:]
>>> compressed_key = bytes.fromhex(compressed_key_hex)
>>> compressed_key.hex()
'02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
```

- Uncompressed format (use `(x, y)` coordinate)

```python
>>> uncompressed_key_hex = '04' + hex(point[0])[2:] + hex(point[1])[2:]
>>> uncompressed_key = bytes.fromhex(uncompressed_key_hex)
>>> uncompressed_key.hex()
'04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
```

> If you want to convert the compressed format to uncompressed, basically, you need to calculate `y` from `x` by solving the equation using [Cipolla's Algorithm](https://www.wikiwand.com/en/Cipolla%27s_algorithm):
> $$
> y^2=(x^3 + 7) \bmod p,\ where\ p=2^{256}-2^{32}-2^{9}-2^{8}-2^{7}-2^{6}-2^{4}-1
> $$
> You can check the [bitcoin wiki](https://en.bitcoin.it/wiki/Secp256k1) and this thread on [bitcointalk.org](https://bitcointalk.org/index.php?topic=644919.msg7205689#msg7205689) for more details.

Then, the shared key between `k1` and `k2` is the `sha256` hash of the **compressed** key.

```python
>>> h = hashlib.sha256()
>>> h.update(compressed_key)
>>> h.hexdigest()
'b1c9938f01121e159887ac2c8d393a22e4476ff8212de13fe1939de2a236f0a7'
```

> You may want to ask, what if no hash? Briefly, hash can make it safer since hash function can remove "weak bits" in the original computed key. Check the introduction section of this [paper](http://cacr.uwaterloo.ca/techreports/1998/corr98-05.pdf) for more details.

### AES

Now we have the shared key, and we can use the `nonce` and `tag` to decrypt. This is quite straight, and the example derives from `pycryptodome`'s [documentation](https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes).

```python
>>> from Cryptodome.Cipher import AES
>>> key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
>>> nonce = b'\xf3\xe1\xba\x81\r,\x89\x00\xb1\x13\x12\xb7\xc7%V_'
>>> tag = b'\xec;q\xe1|\x11\xdb\xe3\x14\x84\xda\x94P\xed\xcfl'
>>> data = b'\x02\xd2\xff\xed\x93\xb8V\xf1H\xb9'
>>> decipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
>>> decipher.decrypt_and_verify(data, tag)
b'helloworld'
```

## Release Notes

### 0.1.3

- Bump dependency versions

### 0.1.2

- Support Python 3.7 build
- Minor fix on documentation

### 0.1.1

- Update documentation

### 0.1.0

- First beta version release
