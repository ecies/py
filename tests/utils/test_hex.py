from ecies.utils import decode_hex


def test_decode_hex():
    assert decode_hex("0x7468697320697320612074657374") == b"this is a test"
