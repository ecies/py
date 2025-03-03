import pytest


@pytest.fixture(scope="session")
def data():
    return "hello world🌍".encode()


@pytest.fixture(scope="session")
def big_data():
    return b"1" * 1024 * 1024 * 100  # 100 MB
