import pytest
from pyaauth import Pyaauth

def authn() -> bool:
    return True


def authz() -> bool:
    return True


def test_create_pyaauth_no_authx_fns():
    pya = Pyaauth()
    assert isinstance(pya, Pyaauth)

def test_create_pyaauth_no_authn_fn():
    pya = Pyaauth(authz_fn=authz)
    assert isinstance(pya, Pyaauth)


def test_create_pyaauth_no_authz_fn():
    pya = Pyaauth(authn_fn=authn)
    assert isinstance(pya, Pyaauth)


def test_create_pyaauth():
    pya = Pyaauth(authn_fn=authn, authz_fn=authz)
    assert isinstance(pya, Pyaauth)
