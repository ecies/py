import hashlib

from Crypto.Hash import SHA256, keccak
from Crypto.Protocol.KDF import HKDF


def sha256(data: bytes) -> bytes:
    """
    Calculate sha256 hash.

    Parameters
    ----------
    data: bytes
        data to hash

    Returns
    -------
    bytes
        sha256 hash in bytes

    >>> sha256(b'0'*16).hex()[:8] == 'fcdb4b42'
    True
    """
    return hashlib.sha256(data).digest()


def derive_key(master: bytes, salt: bytes = b"") -> bytes:
    # for aes256 and xchacha20
    derived = HKDF(master, 32, salt, SHA256, num_keys=1)
    return derived  # type: ignore


# private below
def keccak256(b: bytes) -> bytes:
    h = keccak.new(data=b, digest_bits=256)
    return h.digest()
