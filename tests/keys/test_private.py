import pytest

from ecies.keys import PrivateKey


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_repr(k1, k2):
    assert eval(repr(k1)) == k1
    assert eval(repr(k2)) == k2


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_equal(curve, k1, k2):
    assert k1 == k1 and k2 == k2 and k1 != k2
    assert k1 != "" and "" != k1

    assert PrivateKey(curve) != PrivateKey(curve)


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_bytes(curve, k1, k2):
    assert k1 == PrivateKey(curve, k1.secret)
    assert k2 == PrivateKey(curve, k2.secret)

    random_key = PrivateKey(curve)
    assert random_key == PrivateKey(curve, random_key.secret)


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
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


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_encapsulate_decapsulate(curve, k1, k2):
    assert k1.to_int() == 2
    assert k2.to_int() == 3

    assert k1.encapsulate(k2.public_key) == k1.public_key.decapsulate(k2)
    assert k1.encapsulate(k2.public_key, True) == k1.public_key.decapsulate(k2, True)

    if curve == "secp256k1":
        known_shared_secret = (
            "6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82"
        )
        known_shared_secret_compressed = (
            "b192b226edb3f02da11ef9c6ce4afe1c7e40be304e05ae3b988f4834b1cb6c69"
        )
    elif curve == "x25519":
        known_shared_secret = (
            "d8f3f4d3ed301a58dd1309c372cfd147ad881dc44f495948b3e47c4e07114d0c"
        )
        known_shared_secret_compressed = (
            "d8f3f4d3ed301a58dd1309c372cfd147ad881dc44f495948b3e47c4e07114d0c"
        )
    else:
        raise NotImplementedError

    assert k1.encapsulate(k2.public_key).hex() == known_shared_secret
    assert k1.encapsulate(k2.public_key, True).hex() == known_shared_secret_compressed
