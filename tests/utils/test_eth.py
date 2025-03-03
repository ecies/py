from ecies.utils import hex2pk, to_eth_address


def test_checksum_address():
    pk = "02d9ed78008e7b6c4bdc2beea13230fb3ccb8072728c0986894a3d544485e9b727"
    address = "0x7aD23D6eD9a1D98E240988BED0d78e8C81Ec296C"
    assert to_eth_address(hex2pk(pk)) == address
