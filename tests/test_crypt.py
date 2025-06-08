from contextlib import contextmanager

import pytest

from ecies import ECIES_CONFIG, decrypt, encrypt
from ecies.config import EllipticCurve
from ecies.keys import PrivateKey
from ecies.utils import decode_hex


@contextmanager
def config_manager(curve: EllipticCurve):
    _curve = ECIES_CONFIG.elliptic_curve
    ECIES_CONFIG.elliptic_curve = curve
    yield
    ECIES_CONFIG.elliptic_curve = _curve


def __check_random(data: bytes, k: PrivateKey, compressed: bool = False):
    sk_hex = k.to_hex()
    pk_hex = k.public_key.to_bytes(compressed).hex()
    assert data == decrypt(sk_hex, encrypt(pk_hex, data))
    assert data == decrypt(decode_hex(sk_hex), encrypt(decode_hex(pk_hex), data))


def __check_known(sk: str, pk: str, data: bytes, encrypted: bytes):
    assert encrypt(pk, data) != encrypted
    assert decrypt(sk, encrypted) == data


@pytest.mark.parametrize(
    "curve,compressed",
    [
        ("secp256k1", False),
        ("secp256k1", True),
        ("x25519", False),
        ("x25519", True),
    ],
)
def test_elliptic_ok(data, curve: EllipticCurve, compressed: bool):
    with config_manager(curve):
        __check_random(data, PrivateKey(curve), compressed)


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_encrypt_error(curve, data):
    with pytest.raises(TypeError):
        encrypt(1, data)  # type: ignore


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_decrypt_error(curve, data):
    pk_hex = PrivateKey(curve).public_key.to_bytes(True).hex()
    with config_manager(curve):
        encrypted = encrypt(bytes.fromhex(pk_hex), data)
        with pytest.raises(TypeError):
            decrypt(1, encrypted)  # type: ignore


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_hkdf_config(curve, data):
    ECIES_CONFIG.is_hkdf_key_compressed = True
    with config_manager(curve):
        __check_random(data, PrivateKey(curve))
    ECIES_CONFIG.is_hkdf_key_compressed = False


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_ephemeral_key_config(curve, data):
    ECIES_CONFIG.is_ephemeral_key_compressed = True
    with config_manager(curve):
        __check_random(data, PrivateKey(curve))
    ECIES_CONFIG.is_ephemeral_key_compressed = False


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_aes_nonce_config(curve, data):
    ECIES_CONFIG.symmetric_nonce_length = 12
    with config_manager(curve):
        __check_random(data, PrivateKey(curve))
    ECIES_CONFIG.symmetric_nonce_length = 16


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_sym_config(curve, data):
    ECIES_CONFIG.symmetric_algorithm = "xchacha20"
    if curve == "secp256k1":
        sk = "0000000000000000000000000000000000000000000000000000000000000002"
        pk = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        encrypted = decode_hex(
            "04e314abc14398e07974cd50221b682ed5f0629e977345fc03e2047208ee6e279f"
            "fb2a6942878d3798c968d89e59c999e082b0598d1b641968c48c8d47c570210d0a"
            "b1ade95eeca1080c45366562f9983faa423ee3fd3260757053d5843c5f453e1ee6"
            "bb955c8e5d4aee8572139357a091909357a8931b"
        )
    elif curve == "x25519":
        sk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        pk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        encrypted = decode_hex(
            "cfff9c146116355d0e7ce81df984b4d64c5e5c9c055fbfda0ff8169e11d05e12ed"
            "f025069032adf3e16b763d886f3812bc8f1902fd29204ed3b6a2ea4e52a01dc440"
            "72ed1635aefbad1571bd5b972a7304ba25301f12"
        )
    else:
        raise NotImplementedError

    with config_manager(curve):
        __check_random(data, PrivateKey(curve))
        __check_known(sk, pk, data, encrypted)

    ECIES_CONFIG.symmetric_algorithm = "aes-256-gcm"
