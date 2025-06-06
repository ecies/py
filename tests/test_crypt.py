import pytest

from ecies import ECIES_CONFIG, decrypt, encrypt
from ecies.keys import PrivateKey
from ecies.utils import decode_hex


def generate_key():
    return PrivateKey("secp256k1")


def __check(data: bytes, k: PrivateKey, compressed: bool = False):
    sk_hex = k.to_hex()
    pk_hex = k.public_key.to_bytes(compressed).hex()
    assert data == decrypt(sk_hex, encrypt(pk_hex, data))
    assert data == decrypt(decode_hex(sk_hex), encrypt(decode_hex(pk_hex), data))


def __check_known(sk: str, pk: str, data: bytes, encrypted: bytes):
    assert encrypt(pk, data) != encrypted
    assert decrypt(sk, encrypted) == data


@pytest.mark.parametrize(
    "key,compressed",
    [
        (generate_key(), False),
        (generate_key(), True),
    ],
)
def test_elliptic_ok(data, key: PrivateKey, compressed: bool):
    __check(data, key, compressed)


def test_elliptic_error(data):
    with pytest.raises(TypeError):
        encrypt(1, data)

    k = generate_key()
    pk_hex = k.public_key.to_bytes(True).hex()

    with pytest.raises(TypeError):
        decrypt(1, encrypt(bytes.fromhex(pk_hex), data))


def test_hkdf_config(data):
    ECIES_CONFIG.is_hkdf_key_compressed = True
    __check(data, generate_key())
    ECIES_CONFIG.is_hkdf_key_compressed = False


def test_ephemeral_key_config(data):
    ECIES_CONFIG.is_ephemeral_key_compressed = True
    __check(data, generate_key())
    ECIES_CONFIG.is_ephemeral_key_compressed = False


def test_aes_nonce_config(data):
    ECIES_CONFIG.symmetric_nonce_length = 12
    __check(data, generate_key())
    ECIES_CONFIG.symmetric_nonce_length = 16


def test_sym_config(data):
    ECIES_CONFIG.symmetric_algorithm = "xchacha20"
    __check(data, generate_key())

    sk = "0000000000000000000000000000000000000000000000000000000000000002"
    pk = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    encrypted = decode_hex(
        "0x04e314abc14398e07974cd50221b682ed5f0629e977345fc03e2047208ee6e279f"
        + "fb2a6942878d3798c968d89e59c999e082b0598d1b641968c48c8d47c570210d0a"
        + "b1ade95eeca1080c45366562f9983faa423ee3fd3260757053d5843c5f453e1ee6"
        + "bb955c8e5d4aee8572139357a091909357a8931b"
    )
    __check_known(sk, pk, data, encrypted)

    ECIES_CONFIG.symmetric_algorithm = "aes-256-gcm"
