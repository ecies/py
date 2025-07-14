# TODO: delete
import pytest

from ecies import decrypt, encrypt
from ecies.utils import (
    decode_hex,
    generate_eth_key,
    hex2pk,
    hex2sk,
    sha256,
)

eth_keys = pytest.importorskip("eth_keys")


@pytest.fixture(scope="session")
def sk():
    return generate_eth_key()


def test_elliptic_ok_eth(data, sk):
    sk_hex = sk.to_hex()
    pk_hex = sk.public_key.to_hex()
    assert data == decrypt(sk_hex, encrypt(pk_hex, data))
    assert data == decrypt(decode_hex(sk_hex), encrypt(decode_hex(pk_hex), data))


def test_hex_to_pk(sk):
    data = b"0" * 32
    data_hash = sha256(data)
    cc_sk = hex2sk(sk.to_hex())
    assert sk.sign_msg_hash(data_hash).to_bytes() == cc_sk.sign_recoverable(data)

    pk_hex = sk.public_key.to_hex()
    computed_pk = hex2pk(pk_hex)
    assert computed_pk == cc_sk.public_key


def test_hex_to_sk(sk):
    sk_hex = sk.to_hex()
    pk_hex = sk.public_key.to_hex()
    computed_sk = hex2sk(sk_hex)
    assert computed_sk.to_int() == int(sk.to_hex(), 16)
    assert computed_sk.public_key.format(False)[1:] == decode_hex(pk_hex)
