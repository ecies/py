import pytest

from ecies.keys import PrivateKey, PublicKey


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_repr(pk1, pk2):
    assert eval(repr(pk1)) == pk1
    assert eval(repr(pk2)) == pk2


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_equal(curve, pk1, pk2):
    assert pk1 != pk2
    assert pk1 == pk1 and pk2 == pk2
    assert pk1 != "" and "" != pk1

    assert PrivateKey(curve) != PrivateKey(curve)


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_bytes(curve, pk1, pk2):
    assert pk1 == PublicKey(curve, pk1.to_bytes())
    assert pk2 == PublicKey(curve, pk2.to_bytes())

    random_key = PrivateKey(curve).public_key
    assert random_key == PublicKey(curve, random_key.to_bytes())


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_hex(curve, pk1, pk2):
    assert pk1 == PublicKey.from_hex(curve, pk1.to_hex())
    assert pk2 == PublicKey.from_hex(curve, pk2.to_hex())

    random_key = PrivateKey(curve).public_key
    assert random_key == PublicKey.from_hex(curve, random_key.to_hex())
