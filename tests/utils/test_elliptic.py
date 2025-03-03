from coincurve import PrivateKey

from ecies.utils import decapsulate, encapsulate


def test_encapsulate_decapsulate():
    k1 = PrivateKey(secret=bytes([2]))
    assert k1.to_int() == 2

    k2 = PrivateKey(secret=bytes([3]))
    assert k2.to_int() == 3

    assert encapsulate(k1, k2.public_key) == decapsulate(k1.public_key, k2)
    assert (
        encapsulate(k1, k2.public_key).hex()
        == "6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82"
    )
