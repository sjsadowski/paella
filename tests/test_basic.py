import pytest
from paella import Paella


def test_create_Paella():
    paella_auth = Paella()
    assert isinstance(paella_auth, Paella)
