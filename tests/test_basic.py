import pytest
from paella import Paella

def authn() -> bool:
    return True


def authz() -> bool:
    return True


def test_create_Paella_no_authx_fns():
    pyaa = Paella()
    assert isinstance(pyaa, Paella)

def test_create_Paella_no_authn_fn():
    pyaa = Paella(authz_fn=authz)
    assert isinstance(pyaa, Paella)


def test_create_Paella_no_authz_fn():
    pyaa = Paella(authn_fn=authn)
    assert isinstance(pyaa, Paella)


def test_create_Paella():
    pyaa = Paella(authn_fn=authn, authz_fn=authz)
    assert isinstance(pyaa, Paella)
