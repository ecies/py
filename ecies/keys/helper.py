from coincurve import PublicKey
from coincurve.utils import GROUP_ORDER_INT
from Crypto.Random import get_random_bytes

from ..config import EllipticCurve
from ..consts import ETH_PUBLIC_KEY_LENGTH


def is_valid_secret(curve: EllipticCurve, secret: bytes) -> bool:
    if curve == "secp256k1":
        return 0 < bytes_to_int(secret) < GROUP_ORDER_INT
    raise NotImplementedError


def get_valid_secret(curve: EllipticCurve) -> bytes:
    while True:
        key = get_random_bytes(32)
        if is_valid_secret(curve, key):
            return key


def get_public_key(
    curve: EllipticCurve, secret: bytes, compressed: bool = False
) -> bytes:
    if curve == "secp256k1":
        return PublicKey.from_secret(secret).format(compressed)
    raise NotImplementedError


def get_shared_point(
    curve: EllipticCurve, sk: bytes, pk: bytes, compressed: bool = False
) -> bytes:
    if curve == "secp256k1":
        return PublicKey(pk).multiply(sk).format(compressed)
    raise NotImplementedError


def convert_public_key(
    curve: EllipticCurve, data: bytes, compressed: bool = False
) -> bytes:
    if curve == "secp256k1":
        # handle 33/65/64 bytes
        return PublicKey(pad_eth_public_key(data)).format(compressed)
    raise NotImplementedError


# private below
def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def pad_eth_public_key(data: bytes):
    if len(data) == ETH_PUBLIC_KEY_LENGTH:
        data = b"\x04" + data
    return data
