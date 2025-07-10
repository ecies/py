import pytest

from ecies import decrypt, encrypt
from ecies.keys import PrivateKey

from .helper import config_manager


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_encrypt_error(curve, data):
    with pytest.raises(TypeError):
        encrypt(1, data)  # type: ignore


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_decrypt_error(curve, data):
    pk_hex = PrivateKey(curve).public_key.to_bytes(True).hex()
    with config_manager(curve):
        encrypted = encrypt(bytes.fromhex(pk_hex), data)
        with pytest.raises(TypeError):
            decrypt(1, encrypted)  # type: ignore
