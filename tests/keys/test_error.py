import pytest

from ecies.keys import PrivateKey


def test_invalid():
    with pytest.raises(ValueError, match="Invalid secp256k1 secret key"):
        PrivateKey("secp256k1", b"\x00" * 32)
