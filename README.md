# eciespy

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/2a11aeb9939244019d2c64bce3ff3c4e)](https://app.codacy.com/gh/ecies/py/dashboard)
[![CI](https://img.shields.io/github/actions/workflow/status/ecies/py/ci.yml?branch=master)](https://github.com/ecies/py/actions)
[![Codecov](https://img.shields.io/codecov/c/github/ecies/py.svg)](https://codecov.io/gh/ecies/py)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/eciespy.svg)](https://pypi.org/project/eciespy/)
[![PyPI](https://img.shields.io/pypi/v/eciespy.svg)](https://pypi.org/project/eciespy/)
[![License](https://img.shields.io/github/license/ecies/py.svg)](https://github.com/ecies/py)

Elliptic Curve Integrated Encryption Scheme for secp256k1 in Python.

Other language versions:

- [Rust](https://github.com/ecies/rs)
- [TypeScript](https://github.com/ecies/js)
- [Golang](https://github.com/ecies/go)
- [WASM](https://github.com/ecies/rs-wasm)

You can also check a FastAPI web backend demo [here](https://github.com/kigawas/eciespy-demo).

## Install

`pip install eciespy`

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
$ echo '0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d' > sk
$ echo '0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b' > pk
$ echo 'hello ecies' | eciespy -e -k pk | eciespy -d -k sk
hello ecies
$ echo 'data to encrypt' > data
$ eciespy -e -k pk -D data -O enc_data
$ eciespy -d -k sk -D enc_data
data to encrypt
$ rm sk pk data enc_data
```

## Configuration

Ephemeral key format in the payload and shared key in the key derivation can be configured as compressed or uncompressed format.

```py
SymmetricAlgorithm = Literal["aes-256-gcm", "xchacha20"]
NonceLength = Literal[12, 16]  # only for aes-256-gcm, xchacha20 will always be 24

COMPRESSED_PUBLIC_KEY_SIZE = 33
UNCOMPRESSED_PUBLIC_KEY_SIZE = 65


@dataclass()
class Config:
    is_ephemeral_key_compressed: bool = False
    is_hkdf_key_compressed: bool = False
    symmetric_algorithm: SymmetricAlgorithm = "aes-256-gcm"
    symmetric_nonce_length: NonceLength = 16

    @property
    def ephemeral_key_size(self):
        return (
            COMPRESSED_PUBLIC_KEY_SIZE
            if self.is_ephemeral_key_compressed
            else UNCOMPRESSED_PUBLIC_KEY_SIZE
        )


ECIES_CONFIG = Config()
```

For example, if you set `is_ephemeral_key_compressed = true`, the payload would be like: `33 Bytes + AES` instead of `65 Bytes + AES`.

If you set `is_hkdf_key_compressed = true`, the hkdf key would be derived from `ephemeral public key (compressed) + shared public key (compressed)` instead of `ephemeral public key (uncompressed) + shared public key (uncompressed)`.

If you set `symmetric_algorithm = "xchacha20"`, plaintext data will encrypted with XChaCha20-Poly1305.

If you set `symmetric_nonce_length = 12`, then the nonce of aes-256-gcm would be 12 bytes. XChaCha20-Poly1305's nonce is always 24 bytes.

For compatibility, make sure different applications share the same configuration.

## Technical details

They are moved to [DETAILS.md](./DETAILS.md).

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).
