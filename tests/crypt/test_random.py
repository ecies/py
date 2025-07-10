import pytest

from ecies import ECIES_CONFIG, decrypt, encrypt
from ecies.config import EllipticCurve
from ecies.keys import PrivateKey
from ecies.utils import decode_hex

from .helper import config_manager


def __check_random(data: bytes, k: PrivateKey, compressed: bool = False):
    sk_hex = k.to_hex()
    pk_hex = k.public_key.to_bytes(compressed).hex()
    assert data == decrypt(sk_hex, encrypt(pk_hex, data))
    assert data == decrypt(decode_hex(sk_hex), encrypt(decode_hex(pk_hex), data))


@pytest.mark.parametrize(
    "curve,compressed",
    [
        ("secp256k1", False),
        ("secp256k1", True),
        ("x25519", False),
        ("x25519", True),
        ("ed25519", False),
        ("ed25519", True),
    ],
)
def test_elliptic_ok(data, curve: EllipticCurve, compressed: bool):
    with config_manager(curve):
        __check_random(data, PrivateKey(curve), compressed)


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_hkdf_config(curve, data):
    ECIES_CONFIG.is_hkdf_key_compressed = True
    with config_manager(curve):
        __check_random(data, PrivateKey(curve))
    ECIES_CONFIG.is_hkdf_key_compressed = False


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_ephemeral_key_config(curve, data):
    ECIES_CONFIG.is_ephemeral_key_compressed = True
    with config_manager(curve):
        __check_random(data, PrivateKey(curve))
    ECIES_CONFIG.is_ephemeral_key_compressed = False


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_aes_nonce_config(curve, data):
    ECIES_CONFIG.symmetric_nonce_length = 12
    with config_manager(curve):
        __check_random(data, PrivateKey(curve))
    ECIES_CONFIG.symmetric_nonce_length = 16
