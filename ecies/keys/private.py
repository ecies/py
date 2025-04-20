from __future__ import annotations

from typing import Optional

from ..config import EllipticCurve
from ..utils import decode_hex, derive_key
from .helper import (
    bytes_to_int,
    get_public_key,
    get_shared_point,
    get_valid_secret,
    is_valid_secret,
)
from .public import PublicKey


class PrivateKey:
    def __init__(self, curve: EllipticCurve, secret: Optional[bytes] = None):
        self._curve = curve
        if not secret:
            self._secret = get_valid_secret(curve)
        elif is_valid_secret(curve, secret):
            self._secret = secret
        else:
            raise ValueError(f"Invalid {curve} secret key")
        self._public_key = PublicKey(curve, get_public_key(curve, self._secret))

    def __eq__(self, value):
        return self._secret == value._secret if isinstance(value, PrivateKey) else False

    @classmethod
    def from_hex(cls, curve: EllipticCurve, sk_hex: str) -> PrivateKey:
        """
        For secp256k1, `sk_hex` can only be 32 bytes. `0x` prefix is optional.
        """
        return cls(curve, decode_hex(sk_hex))

    def to_hex(self) -> str:
        return self._secret.hex()

    @property
    def secret(self) -> bytes:
        return self._secret

    @property
    def public_key(self) -> PublicKey:
        return self._public_key

    def to_int(self) -> int:
        return bytes_to_int(self._secret)

    def multiply(self, pk: PublicKey, compressed: bool = False) -> bytes:
        return get_shared_point(self._curve, self._secret, pk.to_bytes(), compressed)

    def encapsulate(self, pk: PublicKey, compressed: bool = False) -> bytes:
        sender_point = self.public_key.to_bytes(compressed)
        shared_point = self.multiply(pk, compressed)
        return derive_key(sender_point + shared_point)
