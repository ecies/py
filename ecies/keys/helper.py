from coincurve import PublicKey
from coincurve.utils import GROUP_ORDER_INT
from Crypto.Protocol.DH import (
    import_x25519_private_key,
    import_x25519_public_key,
    key_agreement,
)
from Crypto.PublicKey.ECC import EccKey
from Crypto.Random import get_random_bytes
from Crypto.Signature.eddsa import import_private_key as import_ed25519_private_key
from Crypto.Signature.eddsa import import_public_key as import_ed25519_public_key

from ..config import EllipticCurve
from ..consts import ETH_PUBLIC_KEY_LENGTH, SECRET_KEY_SIZE


def is_valid_secret(curve: EllipticCurve, secret: bytes) -> bool:
    if len(secret) != SECRET_KEY_SIZE:
        return False
    if curve == "secp256k1":
        return 0 < bytes_to_int(secret) < GROUP_ORDER_INT
    elif curve == "x25519":
        return True
    elif curve == "ed25519":
        return True
    else:
        raise NotImplementedError


def get_valid_secret(curve: EllipticCurve) -> bytes:
    while True:
        key = get_random_bytes(SECRET_KEY_SIZE)
        if is_valid_secret(curve, key):
            return key


def get_public_key(
    curve: EllipticCurve, secret: bytes, compressed: bool = False
) -> bytes:
    if curve == "secp256k1":
        return PublicKey.from_secret(secret).format(compressed)
    elif curve == "x25519":
        return import_x25519_private_key(secret).public_key().export_key(format="raw")
    elif curve == "ed25519":
        return import_ed25519_private_key(secret).public_key().export_key(format="raw")
    else:
        raise NotImplementedError


def get_shared_point(
    curve: EllipticCurve, sk: bytes, pk: bytes, compressed: bool = False
) -> bytes:
    if curve == "secp256k1":
        return PublicKey(pk).multiply(sk).format(compressed)
    elif curve == "x25519":
        return key_agreement(
            kdf=lambda x: x,
            static_priv=import_x25519_private_key(sk),
            eph_pub=import_x25519_public_key(pk),
        )
    elif curve == "ed25519":
        shared_point = (
            import_ed25519_public_key(pk).pointQ * import_ed25519_private_key(sk).d
        )
        return EccKey(curve=curve, point=shared_point).export_key(format="raw")
    else:
        raise NotImplementedError


def convert_public_key(
    curve: EllipticCurve, data: bytes, compressed: bool = False
) -> bytes:
    if curve == "secp256k1":
        # handle 33/65/64 bytes
        return PublicKey(pad_eth_public_key(data)).format(compressed)
    elif curve == "x25519":
        return import_x25519_public_key(data).export_key(format="raw")
    elif curve == "ed25519":
        return import_ed25519_public_key(data).export_key(format="raw")
    else:
        raise NotImplementedError


# private below
def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def pad_eth_public_key(data: bytes):
    if len(data) == ETH_PUBLIC_KEY_LENGTH:
        data = b"\x04" + data
    return data
