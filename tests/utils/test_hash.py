from ecies.utils import derive_key


def test_hkdf():
    derived = derive_key(b"secret").hex()
    assert derived == "2f34e5ff91ec85d53ca9b543683174d0cf550b60d5f52b24c97b386cfcf6cbbf"
