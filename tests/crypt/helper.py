from contextlib import contextmanager


from ecies import ECIES_CONFIG
from ecies.config import EllipticCurve


@contextmanager
def config_manager(curve: EllipticCurve):
    _curve = ECIES_CONFIG.elliptic_curve
    ECIES_CONFIG.elliptic_curve = curve
    yield
    ECIES_CONFIG.elliptic_curve = _curve
