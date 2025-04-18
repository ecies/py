from __future__ import annotations

from typing import TYPE_CHECKING

from ..config import EllipticCurve
from ..utils import decode_hex, derive_key
from .helper import convert_public_key

if TYPE_CHECKING:
    from .private import PrivateKey


class PublicKey:
    def __init__(self, curve: EllipticCurve, data: bytes):
        self._curve = curve
        compressed = convert_public_key(curve, data, True)
        uncompressed = convert_public_key(curve, data, False)
        self._data = compressed
        self._data_uncompressed = (
            uncompressed if len(compressed) != len(uncompressed) else b""
        )

    def __eq__(self, value):
        return self._data == value._data if isinstance(value, PublicKey) else False

    @classmethod
    def from_hex(cls, curve: EllipticCurve, pk_hex: str) -> PublicKey:
        """
        For secp256k1, `pk_hex` can be 33(compressed)/65(uncompressed)/64(ethereum) bytes
        """
        return cls(curve, decode_hex(pk_hex))

    def to_hex(self, compressed: bool = False) -> str:
        """
        For secp256k1, `pk_hex` can be 33(compressed)/65(uncompressed) bytes
        """
        return self.to_bytes(compressed).hex()

    def to_bytes(self, compressed: bool = False) -> bytes:
        """
        For secp256k1, return uncompressed public key (65 bytes) by default
        """
        return self._data if compressed else self._data_uncompressed

    def decapsulate(self, sk: PrivateKey, compressed: bool = False) -> bytes:
        sender_point = self.to_bytes(compressed)
        shared_point = sk.multiply(self, compressed)
        return derive_key(sender_point + shared_point)
