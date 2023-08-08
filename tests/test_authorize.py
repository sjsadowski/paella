import pytest
from pyaauth import Pyaauth

@pytest.mark.asyncio
async def test_fail_no_authz_fn():
    auth = Pyaauth()
    with pytest.raises(NotImplementedError):
        await auth.authorize()


def test_jwt_bad():
    assert False


def test_jwt_claim_fail():
    assert False


def test_jwt_claim():
    assert False
