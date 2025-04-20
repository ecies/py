import pytest
from coincurve import PrivateKey

from ecies import ECIES_CONFIG, decrypt, encrypt
from ecies.utils import decode_hex, generate_key


def __check(data: bytes, k: PrivateKey, compressed: bool = False):
    sk_hex = k.to_hex()
    pk_hex = k.public_key.format(compressed).hex()
    assert data == decrypt(sk_hex, encrypt(pk_hex, data))
    assert data == decrypt(decode_hex(sk_hex), encrypt(decode_hex(pk_hex), data))


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
    pk_hex = k.public_key.format(True).hex()

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
    ECIES_CONFIG.symmetric_algorithm = "aes-256-gcm"
