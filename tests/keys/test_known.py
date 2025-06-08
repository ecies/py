import pytest

from ecies.config import EllipticCurve
from ecies.keys import PrivateKey, PublicKey


@pytest.mark.parametrize("curve", ["secp256k1", "x25519"])
def test_known(curve: EllipticCurve):
    if curve == "secp256k1":
        sk = "5b5b1a0ff51e4350badd6f58d9e6fa6f57fbdbde6079d12901770dda3b803081"
        pk = "048e41409f2e109f2d704f0afd15d1ab53935fd443729913a7e8536b4cef8cf5773d4db7bbd99e9ed64595e24a251c9836f35d4c9842132443c17f6d501b3410d2"
    elif curve == "x25519":
        sk = "a8abababababababababababababababababababababababababababababab6b"
        pk = "e3712d851a0e5d79b831c5e34ab22b41a198171de209b8b8faca23a11c624859"
    else:
        raise NotImplementedError
    assert PrivateKey.from_hex(curve, sk).public_key == PublicKey.from_hex(curve, pk)
