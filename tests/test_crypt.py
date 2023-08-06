import pytest
from coincurve import PrivateKey
from eth_keys import keys

from ecies import ECIES_CONFIG, decrypt, encrypt
from ecies.utils import generate_eth_key, generate_key
from ecies.utils.hex import decode_hex

data = b"this is a test"


def __check(k, compressed=False):
    sk_hex = k.to_hex()
    if isinstance(k, PrivateKey):
        pk_hex = k.public_key.format(compressed).hex()
    elif isinstance(k, keys.PrivateKey):
        pk_hex = k.public_key.to_hex()
    else:
        raise NotImplementedError
    assert data == decrypt(sk_hex, encrypt(pk_hex, data))
    sk_bytes = decode_hex(sk_hex)
    pk_bytes = decode_hex(pk_hex)
    if len(pk_bytes) == 64:  # eth
        pk_bytes = b"\x04" + pk_bytes
    assert data == decrypt(sk_bytes, encrypt(pk_bytes, data))


def test_elliptic():
    __check(generate_eth_key())
    __check(generate_key())
    __check(generate_key(), True)

    with pytest.raises(TypeError):
        encrypt(1, data)

    k = generate_key()
    pk_hex = k.public_key.format(True).hex()

    with pytest.raises(TypeError):
        decrypt(1, encrypt(bytes.fromhex(pk_hex), data))


def test_hkdf_config():
    ECIES_CONFIG.is_hkdf_key_compressed = True
    __check(generate_key())
    ECIES_CONFIG.is_hkdf_key_compressed = False


def test_ephemeral_key_config():
    ECIES_CONFIG.is_ephemeral_key_compressed = True
    __check(generate_key())
    ECIES_CONFIG.is_ephemeral_key_compressed = False


def test_aes_nonce_config():
    ECIES_CONFIG.symmetric_nonce_length = 12
    __check(generate_key())
    ECIES_CONFIG.symmetric_nonce_length = 16


def test_sym_config():
    ECIES_CONFIG.symmetric_algorithm = "xchacha20"
    __check(generate_key())
    ECIES_CONFIG.symmetric_algorithm = "aes-256-gcm"
