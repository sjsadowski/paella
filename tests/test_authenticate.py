import pytest

import jwt
from paella import Paella

@pytest.fixture
def sql3_sync_obj():
    return True

@pytest.fixture
def sql3_async_obj():
    return True

@pytest.fixture
def paella_auth():
    return Paella()


@pytest.mark.asyncio
async def test_fail_no_authn_fn(paella_auth):
    with pytest.raises(NotImplementedError):
        await paella_auth.authenticate()


def test_fail_jwt():
    assert False

def test_issue_jwt():
    assert False

def test_fail_jwt_decode():
    assert False

def test_jwt_decode():
    assert False
