import hashlib

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from typing_extensions import deprecated


@deprecated("Use `hashlib.sha256(data).digest()` instead")
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def derive_key(master: bytes, salt: bytes = b"") -> bytes:
    # 32 bytes for aes256 and xchacha20
    derived = HKDF(master, 32, salt, SHA256, num_keys=1)
    return derived  # type: ignore
