import pytest

import aiosqlite
import sqlite3
import jwt

from paella import Paella

@pytest.fixture
def sql3_sync_obj():
    return sqlite3.connect("./tests/db/test_users.db")

@pytest.fixture
def sql3_async_obj():
    return aiosqlite.connect("./tests/db/test_users.db")

@pytest.fixture
def paella_auth():
    return Paella()


@pytest.mark.asyncio
async def test_fail_no_authn_fn(paella_auth):
    with pytest.raises(NotImplementedError):
        await paella_auth.authenticate()


@pytest.mark.asyncio
async def test_async_authenticate_basic(paella_auth, sql3_async_obj):
    assert False

# Providing clarity for the below test:
# The Paella.authenticate() function is asynchronous
# But for ease of use you can pass a standard (synchronous) function
# Just testing to make sure both work as expected, even
# though the synchronous function will block.
@pytest.mark.asyncio
async def test_authenticate_basic(paella_auth, sql3_async_obj):
    assert False

def test_fail_jwt():
    assert False

def test_issue_jwt():
    assert False

def test_fail_jwt_decode():
    assert False

def test_jwt_decode():
    assert False
