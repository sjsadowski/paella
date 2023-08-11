from aiosqlite import connect as aconnect, Connection as AConnection
from sqlite3 import connect, Connection
from typing import Any, Callable

import pytest
import jwt

from paella import Paella



def sync_authn_fn(cxobj: Any, id: str, secret: str) -> bool:
    cur = cxobj.cursor()
    cur.execute("SELECT id FROM Users WHERE email=? and password=?", (id, secret))
    res = cur.fetchone()
    if res is not None:
        return True
    else:
        return False



async def async_authn_fn(cxobj: Any, id: str, secret: str) -> bool:
    cur = await cxobj.cursor()
    await cur.execute("SELECT id FROM Users WHERE email=? and password=?", (id, secret))
    res = await cur.fetchone()
    if res is not None:
        return True
    else:
        return False



@pytest.fixture
def sql3_sync_db():
    db: Connection = connect("./tests/db/test_users.db")
    yield db
    db.close()

@pytest.fixture(autouse=True)
async def sql3_async_db():
    db: AConnection = await aconnect("./tests/db/test_users.db")
    yield db
    await db.close()

@pytest.fixture
def paella_auth():
    return Paella()

@pytest.fixture
def privkey():
    with open('./tests/keys/test_rsa_priv') as f:
        priv = f.read()

    return priv

@pytest.fixture
def pubkey():
    with open('./tests/keys/test_rsa_pub') as f:
        pub = f.read()
    return pub


@pytest.mark.asyncio
async def test_fail_no_authn_fn(paella_auth):
    with pytest.raises(NotImplementedError):
        await paella_auth.authenticate()


@pytest.mark.asyncio
async def test_async_authenticate_basic(paella_auth: Paella, sql3_async_db: AConnection):

    paella_auth.cxobj = sql3_async_db
    paella_auth.authn_fn = async_authn_fn

    authn_value: bool = await paella_auth.authenticate()

    assert authn_value == True

# Providing clarity for the below test:
# The Paella.authenticate() function is asynchronous
# But for ease of use you can pass a standard (synchronous) function
# Just testing to make sure both work as expected, even
# though the synchronous function will block.

@pytest.mark.asyncio
async def test_authenticate_basic(paella_auth: Paella, sql3_sync_db: Connection):

    paella_auth.cxobj = sql3_sync_db
    paella_auth.authn_fn = sync_authn_fn

    authn_value: bool = await paella_auth.authenticate()

    assert authn_value == True

async def test_authenticate_basic(paella_auth: Paella, sql3_sync_db: Connection):

    def sync_authn_fn(cxobj: Any, id: str, secret: str) -> bool:
        cur = cxobj.cursor()
        cur.execute("SELECT id FROM Users WHERE email=? and password=?", (id, secret))
        res = cur.fetchone()
        if res is not None:
            return True
        else:
            return False


    paella_auth.cxobj = sql3_sync_db
    paella_auth.authn_fn = sync_authn_fn

    authn_value: bool = await paella_auth.authenticate()

    assert authn_value == True



def test_fail_jwt():
    assert False

def test_issue_jwt():
    assert False

def test_fail_jwt_decode():
    assert False

def test_jwt_decode():
    assert False
