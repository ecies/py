import pytest

from ecies.keys import PrivateKey


@pytest.mark.parametrize("curve", ["secp256k1"])
def test_equal(curve, k1, k2):
    assert k1 == k1 and k2 == k2 and k1 != k2
    assert k1 != "" and "" != k1

    assert PrivateKey(curve) != PrivateKey(curve)


@pytest.mark.parametrize("curve", ["secp256k1"])
def test_bytes(curve, k1, k2):
    assert k1 == PrivateKey(curve, k1.secret)
    assert k2 == PrivateKey(curve, k2.secret)

    random_key = PrivateKey(curve)
    assert random_key == PrivateKey(curve, random_key.secret)


@pytest.mark.parametrize("curve", ["secp256k1"])
def test_hex(curve, k1, k2):
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

    random_key = PrivateKey(curve)
    assert random_key == PrivateKey.from_hex(curve, random_key.to_hex())


@pytest.mark.parametrize("curve", ["secp256k1"])
def test_encapsulate_decapsulate(k1, k2):
    assert k1.to_int() == 2
    assert k2.to_int() == 3

    assert k1.encapsulate(k2.public_key) == k1.public_key.decapsulate(k2)
    assert (
        k1.encapsulate(k2.public_key).hex()
        == "6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82"
    )
