import pytest

import jwt
from pyaauth import Pyaauth

@pytest.mark.asyncio
async def test_fail_no_authn_fn():
    auth = Pyaauth()
    with pytest.raises(NotImplementedError):
        await auth.authenticate()


def test_fail_jwt():
    assert False

def test_issue_jwt():
    assert False

def test_fail_jwt_decode():
    assert False

def test_jwt_decode():
    assert False
