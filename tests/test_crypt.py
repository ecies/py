import pytest
from coincurve import PrivateKey

from ecies import ECIES_CONFIG, decrypt, encrypt
from ecies.utils import decode_hex, generate_key

data = b"this is a test"


def __check_bytes(k, compressed=False):
    sk_hex = k.to_hex()
    pk_hex = k.public_key.format(compressed).hex()
    assert data == decrypt(sk_hex, encrypt(pk_hex, data))


def __check_hex(sk_hex: str, pk_hex: str):
    sk_bytes = decode_hex(sk_hex)
    pk_bytes = decode_hex(pk_hex)
    assert data == decrypt(sk_bytes, encrypt(pk_bytes, data))


@pytest.mark.parametrize(
    "key,compressed",
    [
        (generate_key(), False),
        (generate_key(), True),
    ],
)
def test_elliptic_ok(key: PrivateKey, compressed: bool):
    sk_hex = key.to_hex()
    pk_hex = key.public_key.format(compressed).hex()
    __check_hex(sk_hex, pk_hex)


def test_elliptic_error():
    with pytest.raises(TypeError):
        encrypt(1, data)

    k = generate_key()
    pk_hex = k.public_key.format(True).hex()

    with pytest.raises(TypeError):
        decrypt(1, encrypt(bytes.fromhex(pk_hex), data))


def test_hkdf_config():
    ECIES_CONFIG.is_hkdf_key_compressed = True
    __check_bytes(generate_key())
    ECIES_CONFIG.is_hkdf_key_compressed = False


def test_ephemeral_key_config():
    ECIES_CONFIG.is_ephemeral_key_compressed = True
    __check_bytes(generate_key())
    ECIES_CONFIG.is_ephemeral_key_compressed = False


def test_aes_nonce_config():
    ECIES_CONFIG.symmetric_nonce_length = 12
    __check_bytes(generate_key())
    ECIES_CONFIG.symmetric_nonce_length = 16


def test_sym_config():
    ECIES_CONFIG.symmetric_algorithm = "xchacha20"
    __check_bytes(generate_key())
    ECIES_CONFIG.symmetric_algorithm = "aes-256-gcm"
