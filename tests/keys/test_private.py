import pytest

from ecies.keys import PrivateKey


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_repr(k1, k2):
    assert eval(repr(k1)) == k1
    assert eval(repr(k2)) == k2


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_equal(curve, k1, k2, random_sk):
    assert k1 == k1 and k2 == k2 and k1 != k2
    assert k1 != "" and "" != k1

    assert random_sk != PrivateKey(curve)


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_bytes(curve, k1, k2, random_sk):
    assert k1 == PrivateKey(curve, k1.secret)
    assert k2 == PrivateKey(curve, k2.secret)

    assert random_sk == PrivateKey(curve, random_sk.secret)


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_hex(curve, k1, k2, random_sk):
    assert (
        k1.to_hex()
        == "0000000000000000000000000000000000000000000000000000000000000002"
    )
    assert (
        k2.to_hex()
        == "0000000000000000000000000000000000000000000000000000000000000003"
    )
    assert k1 == PrivateKey.from_hex(curve, k1.to_hex())
    assert k2 == PrivateKey.from_hex(curve, k2.to_hex())

    assert random_sk == PrivateKey.from_hex(curve, random_sk.to_hex())
