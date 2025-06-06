import pytest

from ecies.config import EllipticCurve
from ecies.keys import PrivateKey


@pytest.fixture
def k1(curve: EllipticCurve):
    return PrivateKey(curve, b"\x00" * 31 + b"\x02")


@pytest.fixture
def k2(curve: EllipticCurve):
    return PrivateKey(curve, b"\x00" * 31 + b"\x03")


@pytest.fixture
def pk1(k1: PrivateKey):
    return k1.public_key


@pytest.fixture
def pk2(k2: PrivateKey):
    return k2.public_key
