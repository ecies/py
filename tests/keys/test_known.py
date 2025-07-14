import pytest

from ecies.config import EllipticCurve
from ecies.keys import PrivateKey, PublicKey


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_known(curve: EllipticCurve):
    if curve == "secp256k1":
        sk = "5b5b1a0ff51e4350badd6f58d9e6fa6f57fbdbde6079d12901770dda3b803081"
        pk = "048e41409f2e109f2d704f0afd15d1ab53935fd443729913a7e8536b4cef8cf5773d4db7bbd99e9ed64595e24a251c9836f35d4c9842132443c17f6d501b3410d2"
    elif curve == "x25519":
        sk = "a8abababababababababababababababababababababababababababababab6b"
        pk = "e3712d851a0e5d79b831c5e34ab22b41a198171de209b8b8faca23a11c624859"
    elif curve == "ed25519":
        sk = "0000000000000000000000000000000000000000000000000000000000000000"
        pk = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
    else:
        raise NotImplementedError

    assert PrivateKey.from_hex(curve, sk).public_key == PublicKey.from_hex(curve, pk)


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
def test_multiply(curve: EllipticCurve):
    if curve == "secp256k1":
        sk = "0000000000000000000000000000000000000000000000000000000000000003"
        peer_pk = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        shared = "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556"
    elif curve == "x25519":
        sk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        peer_pk = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    elif curve == "ed25519":
        sk = "0000000000000000000000000000000000000000000000000000000000000000"
        peer_pk = "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"
        shared = "79a82a4ed2cbf9cab6afbf353df0a225b58642c0c7b3760a99856bf01785817f"
    else:
        raise NotImplementedError

    assert PrivateKey.from_hex(curve, sk).multiply(
        PublicKey.from_hex(curve, peer_pk), compressed=True
    ) == bytes.fromhex(shared)


@pytest.mark.parametrize("curve", ["secp256k1", "x25519", "ed25519"])
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
        known_shared_secret_compressed = known_shared_secret
    elif curve == "ed25519":
        known_shared_secret = (
            "0c39bd5bbeaa991f10dfb399c1d326a1280812a53ba143a5edae0a8d737c45ca"
        )
        known_shared_secret_compressed = known_shared_secret
    else:
        raise NotImplementedError

    assert k1.encapsulate(k2.public_key).hex() == known_shared_secret
    assert k1.encapsulate(k2.public_key, True).hex() == known_shared_secret_compressed
