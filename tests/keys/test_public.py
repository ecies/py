import pytest

from ecies.keys import PublicKey


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_repr(pk1, pk2):
    assert eval(repr(pk1)) == pk1
    assert eval(repr(pk2)) == pk2


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_equal(pk1, pk2, random_sk, random_pk):
    assert pk1 != pk2
    assert pk1 == pk1 and pk2 == pk2
    assert pk1 != "" and "" != pk1

    assert random_pk != random_sk.public_key


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_bytes(curve, pk1, pk2, random_pk):
    assert pk1 == PublicKey(curve, pk1.to_bytes())
    assert pk2 == PublicKey(curve, pk2.to_bytes())

    assert random_pk == PublicKey(curve, random_pk.to_bytes())


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_hex(curve, pk1, pk2, random_pk):
    assert pk1 == PublicKey.from_hex(curve, pk1.to_hex())
    assert pk2 == PublicKey.from_hex(curve, pk2.to_hex())

    assert random_pk == PublicKey.from_hex(curve, random_pk.to_hex())
