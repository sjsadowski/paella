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


def sync_authz_fn(cxobj, **kwargs) -> bool:
    return True

async def async_authz_fn(cxobj, **kwargs) -> bool:
    return True

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
    with open('./tests/keys/test_rsa_priv.crt') as f:
        priv = f.read()

    return priv

@pytest.fixture
def pubkey():
    with open('./tests/keys/test_rsa_pub.crt') as f:
        pub = f.read()
    return pub


@pytest.mark.asyncio
async def test_fail_no_authn_fn(paella_auth):
    with pytest.raises(NotImplementedError):
        await paella_auth.authenticate()


@pytest.mark.asyncio
async def test_fail_jwt_decode_no_pubkey(paella_auth: Paella, privkey: str):
    paella_auth.privkey = privkey
    jwt_str = await paella_auth.jwt_authn("testuser@test.com","a_very_basic_password")

    with pytest.raises(ValueError):
        jwt_dec = await paella_auth.jwt_authz(jwt_str)


@pytest.mark.asyncio
async def test_jwt_decode(paella_auth: Paella, sql3_async_db: AConnection, privkey: str, pubkey: str):
    paella_auth.cxobj = sql3_async_db
    paella_auth.pubkey = pubkey
    paella_auth.authz_fn = async_authz_fn
    jwt_str = jwt.encode({'id': "testuser@test.com", 'secret': "a_very_basic_password"}, key=privkey, algorithm="RS256")
    valid_token = await paella_auth.jwt_authz(jwt_str)
    assert valid_token == True


@pytest.mark.asyncio
async def test_fail_jwt_decode_no_authz_fn(paella_auth: Paella, privkey: str, pubkey: str):
    paella_auth.privkey = privkey
    paella_auth.pubkey = pubkey
    jwt_str = await paella_auth.jwt_authn("testuser@test.com","a_very_basic_password")

    with pytest.raises(NotImplementedError):
        jwt_dec = await paella_auth.jwt_authz(jwt_str)


def test_jwt_bad():
    assert False


def test_jwt_claim_fail():
    assert False


def test_jwt_claim():
    assert False
