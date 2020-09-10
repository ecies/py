# eciespy

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/2a11aeb9939244019d2c64bce3ff3c4e)](https://www.codacy.com/app/ecies/py)
[![CI](https://img.shields.io/circleci/project/github/ecies/py.svg)](https://circleci.com/gh/ecies/py)
[![Codecov](https://img.shields.io/codecov/c/github/ecies/py.svg)](https://codecov.io/gh/ecies/py)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/eciespy.svg)](https://pypi.org/project/eciespy/)
[![PyPI](https://img.shields.io/pypi/v/eciespy.svg)](https://pypi.org/project/eciespy/)
[![License](https://img.shields.io/github/license/ecies/py.svg)](https://github.com/ecies/py)

Elliptic Curve Integrated Encryption Scheme for secp256k1 in Python.

Other language versions:

- [Rust](https://github.com/ecies/rs)
- [TypeScript](https://github.com/ecies/js)
- [Golang](https://github.com/ecies/go)

You can also check a flask web backend demo [here](https://github.com/kigawas/eciespy-demo).

## Install

Install with `pip install eciespy` under [Python 3.5.3+](https://github.com/ecies/py/blob/master/pyproject.toml#L32).

## Quick Start

```python
>>> from ecies.utils import generate_eth_key, generate_key
>>> from ecies import encrypt, decrypt
>>> eth_k = generate_eth_key()
>>> sk_hex = eth_k.to_hex()  # hex string
>>> pk_hex = eth_k.public_key.to_hex()  # hex string
>>> data = b'this is a test'
>>> decrypt(sk_hex, encrypt(pk_hex, data))
b'this is a test'
>>> secp_k = generate_key()
>>> sk_bytes = secp_k.secret  # bytes
>>> pk_bytes = secp_k.public_key.format(True)  # bytes
>>> decrypt(sk_bytes, encrypt(pk_bytes, data))
b'this is a test'
```

Or just use a builtin command `eciespy` in your favorite [command line](#command-line-interface).

## API

### `ecies.encrypt(receiver_pk: Union[str, bytes], msg: bytes) -> bytes`

Parameters:

- **receiver_pk** - Receiver's public key (hex str or bytes)
- **msg** - Data to encrypt

Returns: **bytes**

### `ecies.decrypt(receiver_sk: Union[str, bytes], msg: bytes) -> bytes`

Parameters:

- **receiver_sk** - Receiver's private key (hex str or bytes)
- **msg** - Data to decrypt

Returns: **bytes**

## Command Line Interface

### Show help

```console
$ eciespy -h
usage: eciespy [-h] [-e] [-d] [-g] [-k KEY] [-D [DATA]] [-O [OUT]]

Elliptic Curve Integrated Encryption Scheme for secp256k1 in Python

optional arguments:
  -h, --help            show this help message and exit
  -e, --encrypt         encrypt with public key, exclusive with -d
  -d, --decrypt         decrypt with private key, exclusive with -e
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

```console
$ eciespy -g
Private: 0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d
Public: 0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b
Address: 0x47e801184B3a8ea8E6A4A7A4CFEfEcC76809Da72
```

### Encrypt with public key and decrypt with private key

```console
$ echo '0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d' > prv
$ echo '0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b' > pub
$ echo 'helloworld' | eciespy -e -k pub | eciespy -d -k prv
helloworld
$ echo 'data to encrypt' > data
$ eciespy -e -k pub -D data -O enc_data
$ eciespy -d -k prv -D enc_data
data to encrypt
$ rm prv pub data enc_data
```

## Mechanism and implementation details

This library combines `secp256k1` and `AES-256-GCM` (powered by [`coincurve`](https://github.com/ofek/coincurve) and [`pycryptodome`](https://github.com/Legrandin/pycryptodome)) to provide an API of encrypting with `secp256k1` public key and decrypting with `secp256k1`'s private key. It has two parts generally:

1. Use [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie–Hellman) to exchange an AES session key;

    > Notice that the sender public key is generated every time when `ecies.encrypt` is invoked, thus, the AES session key varies.

2. Use this AES session key to encrypt/decrypt the data under `AES-256-GCM`.

Basically the encrypted data will be like this:

```plaintext
+-------------------------------+----------+----------+-----------------+
| 65 Bytes                      | 16 Bytes | 16 Bytes | == data size    |
+-------------------------------+----------+----------+-----------------+
| Sender Public Key (ephemeral) | Nonce/IV | Tag/MAC  | Encrypted data  |
+-------------------------------+----------+----------+-----------------+
| sender_pk                     | nonce    | tag      | encrypted_data  |
+-------------------------------+----------+----------+-----------------+
|           Secp256k1           |              AES-256-GCM              |
+-------------------------------+---------------------------------------+
```

### Secp256k1

#### Glance at ecdh

So, **how** do we calculate the ECDH key under `secp256k1`? If you use a library like [`coincurve`](https://github.com/ofek/coincurve), you might just simply call `k1.ecdh(k2.public_key.format())`, then uh-huh, you got it! Let's see how to do it in simple Python snippets:

```python
>>> from coincurve import PrivateKey
>>> k1 = PrivateKey.from_int(3)
>>> k2 = PrivateKey.from_int(2)
>>> k1.public_key.format(False).hex() # 65 bytes, False means uncompressed key
'04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672'
>>> k2.public_key.format(False).hex() # 65 bytes
'04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
>>> k1.ecdh(k2.public_key.format()).hex()
'c7d9ba2fa1496c81be20038e5c608f2fd5d0246d8643783730df6c2bbb855cb2'
>>> k2.ecdh(k1.public_key.format()).hex()
'c7d9ba2fa1496c81be20038e5c608f2fd5d0246d8643783730df6c2bbb855cb2'
```

#### Calculate your ecdh key manually

However, as a hacker like you with strong desire to learn something, you must be curious about the magic under the ground.

In one sentence, the `secp256k1`'s ECDH key of `k1` and `k2` is nothing but `sha256(k2.public_key.multiply(k1))`.

```python
>>> k1.to_int()
3
>>> shared_pub = k2.public_key.multiply(k1.secret)
>>> shared_pub.point()
(115780575977492633039504758427830329241728645270042306223540962614150928364886,
 78735063515800386211891312544505775871260717697865196436804966483607426560663)
>>> import hashlib
>>> h = hashlib.sha256()
>>> h.update(shared_pub.format())
>>> h.hexdigest()  # here you got the ecdh key same as above!
'c7d9ba2fa1496c81be20038e5c608f2fd5d0246d8643783730df6c2bbb855cb2'
```

> Warning: **NEVER** use small integers as private keys on any production systems or storing any valuable assets.
>
> Warning: **ALWAYS** use safe methods like [`os.urandom`](https://docs.python.org/3/library/os.html#os.urandom) to generate private keys.

#### Math on ecdh

Let's discuss in details. The word _multiply_ here means multiplying a **point** of a public key on elliptic curve (like `(x, y)`) with a **scalar** (like `k`). Here `k` is the integer format of a private key, for instance, it can be `3` for `k1` here, and `(x, y)` here is an extremely large number pair like `(115780575977492633039504758427830329241728645270042306223540962614150928364886, 78735063515800386211891312544505775871260717697865196436804966483607426560663)`.

> Warning: 1 \* (x, y) == (x, y) is always true, since 1 is the **identity element** for multiplication. If you take integer 1 as a private key, the public key will be the [base point](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_generation_algorithm).

Mathematically, the elliptic curve cryptography is based on the fact that you can easily multiply point `A` (aka base point, or public key in ECDH) and scalar `k` (aka private key) to get another point `B` (aka public key), but it's almost impossible to calculate `A` from `B` reversely (which means it's a "one-way function").

#### Compressed and uncompressed keys

A point multiplying a scalar can be regarded that this point adds itself multiple times, and the point `B` can be converted to a readable public key in a compressed or uncompressed format.

- Compressed format (`x` coordinate only)

```python
>>> point = (89565891926547004231252920425935692360644145829622209833684329913297188986597, 12158399299693830322967808612713398636155367887041628176798871954788371653930)
>>> point == k2.public_key.point()
True
>>> prefix = '02' if point[1] % 2 == 0 else '03'
>>> compressed_key_hex = prefix + hex(point[0])[2:]
>>> compressed_key = bytes.fromhex(compressed_key_hex)
>>> compressed_key.hex()
'02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
```

- Uncompressed format (`(x, y)` coordinate)

```python
>>> uncompressed_key_hex = '04' + hex(point[0])[2:] + hex(point[1])[2:]
>>> uncompressed_key = bytes.fromhex(uncompressed_key_hex)
>>> uncompressed_key.hex()
'04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
```

The format is depicted by the image below from the [bitcoin book](https://github.com/bitcoinbook/bitcoinbook).

![EC public key format](https://raw.githubusercontent.com/bitcoinbook/bitcoinbook/develop/images/mbc2_0407.png)

> If you want to convert the compressed format to uncompressed, basically, you need to calculate `y` from `x` by solving the equation using [Cipolla's Algorithm](https://en.wikipedia.org/wiki/Cipolla's_algorithm):
>
> ![y^2=(x^3 + 7) mod p, where p=2^{256}-2^{32}-2^{9}-2^{8}-2^{7}-2^{6}-2^{4}-1](<https://tex.s2cms.ru/svg/%20y%5E2%3D(x%5E3%20%2B%207)%20%5Cbmod%20p%2C%5C%20where%5C%20p%3D2%5E%7B256%7D-2%5E%7B32%7D-2%5E%7B9%7D-2%5E%7B8%7D-2%5E%7B7%7D-2%5E%7B6%7D-2%5E%7B4%7D-1%20>)
>
> You can check the [bitcoin wiki](https://en.bitcoin.it/wiki/Secp256k1) and this thread on [bitcointalk.org](https://bitcointalk.org/index.php?topic=644919.msg7205689#msg7205689) for more details.

Then, the shared key between `k1` and `k2` is the `sha256` hash of the **compressed** ECDH public key. It's better to use the compressed format, since you can always get `x` from `x` or `(x, y)` without any calculation.

You may want to ask, what if we don't hash it? Briefly, hash can:

1. Make the shared key's length fixed;
2. Make it safer since hash functions can remove "weak bits" in the original computed key. Check the introduction section of this [paper](http://cacr.uwaterloo.ca/techreports/1998/corr98-05.pdf) for more details.

> Warning: According to some recent research, although widely used, the `sha256` key derivation function is [not secure enough](https://github.com/ecies/py/issues/82).

### AES

Now we have the shared key, and we can use the `nonce` and `tag` to decrypt. This is quite straight, and the example derives from `pycryptodome`'s [documentation](https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes).

```python
>>> from Crypto.Cipher import AES
>>> key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
>>> iv = b'\xf3\xe1\xba\x81\r,\x89\x00\xb1\x13\x12\xb7\xc7%V_'
>>> tag = b'\xec;q\xe1|\x11\xdb\xe3\x14\x84\xda\x94P\xed\xcfl'
>>> data = b'\x02\xd2\xff\xed\x93\xb8V\xf1H\xb9'
>>> decipher = AES.new(key, AES.MODE_GCM, nonce=iv)
>>> decipher.decrypt_and_verify(data, tag)
b'helloworld'
```

> Strictly speaking, `nonce` != `iv`, but this is a little bit off topic, if you are curious, you can check [the comment in `utils.py`](https://github.com/ecies/py/blob/master/ecies/utils.py#L213).

## Release Notes

### 0.3.1 ~ 0.3.7

- Support Python 3.8, 3.9
- Bump dependencies
- Update documentation
- Poetry

### 0.3.0

- API change: use `HKDF-sha256` to derive shared keys instead of `sha256`

### 0.2.0

- API change: `ecies.encrypt` and `ecies.decrypt` now can take both hex str and raw bytes
- Bump dependencies
- Update documentation

### 0.1.1 ~ 0.1.9

- Bump dependencies
- Update documentation
- Switch to Circle CI
- Change license to MIT

### 0.1.0

- First beta version release
