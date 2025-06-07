import pytest
from coincurve.utils import GROUP_ORDER_INT

from ecies.config import EllipticCurve
from ecies.keys import PrivateKey


def test_group_order():
    sk1 = PrivateKey("secp256k1", int(1).to_bytes(32, "big"))
    sk2 = PrivateKey("secp256k1", (GROUP_ORDER_INT - 1).to_bytes(32, "big"))
    assert sk1.multiply(sk2.public_key) == sk2.public_key.to_bytes()

    with pytest.raises(ValueError, match="Invalid secp256k1 secret key"):
        PrivateKey("secp256k1", b"\x00" * 32)

    with pytest.raises(ValueError, match="Invalid secp256k1 secret key"):
        PrivateKey("secp256k1", (GROUP_ORDER_INT + 1).to_bytes(32, "big"))


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_invalid_length(curve: EllipticCurve):
    with pytest.raises(ValueError, match=f"Invalid {curve} secret key"):
        PrivateKey(curve, b"\x00")
