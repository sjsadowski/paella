import asyncio
from typing import Callable, Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt

class Paella:

    __slots__ = [
        '_authn_fn',
        '_authz_fn',
        '_pubkey',
        '_privkey',
        '_password',
        '_cxobj'
    ]

    _authn_fn: Callable
    _authz_fn: Callable
    _pubkey: str
    _privkey: str
    _password: bytes
    _cxobj: Any

    def __init__(self, authn_fn=None, authz_fn=None, cxobj=None, privkey=None, password=None, pubkey=None) -> None:
        self.authn_fn = authn_fn
        self.authz_fn = authz_fn
        self.privkey = privkey
        self.password = password
        self.pubkey = pubkey
        self.cxobj = cxobj


    @property
    def authn_fn(self) -> Callable | None:
        return self._authn_fn

    @authn_fn.setter
    def authn_fn(self, authn_fn: Callable | None) -> None:
        self._authn_fn = authn_fn

    @property
    def authz_fn(self) -> Callable | None:
        return self._authz_fn

    @authz_fn.setter
    def authz_fn(self, authz_fn: Callable | None) -> None:
        self._authz_fn = authz_fn

    @property
    def pubkey(self) -> str | None:
        return self._pubkey

    @pubkey.setter
    def pubkey(self, pubkey: str | None) -> None:
        self._pubkey = pubkey

    @property
    def privkey(self) -> str | None:
        return self._privkey

    @privkey.setter
    def privkey(self, privkey: str | None) -> None:
        private_key = privkey
        if privkey is not None:
            pem_bytes = privkey.encode()

            private_key = serialization.load_pem_private_key(
                pem_bytes, password=self._password, backend=default_backend(),
            )
        self._privkey = private_key


    @property
    def password(self) -> str | None:
        return self._password

    @password.setter
    def password(self, password: str | None) -> None:

        if password is not None:
            self._password = password.encode()
        else:
            self._password = password



    @property
    def cxobj(self) -> Any:
        return self._cxobj

    @cxobj.setter
    def cxobj(self, cxobj: Any) -> None:
        self._cxobj = cxobj


    # If authenticated, returns jwt or None
    async def authenticate(self, id: str = '', secret: str = '') -> dict | bool:

        # default: not authenticated
        authn: bool | dict = False

        if self._authn_fn is None:
            raise NotImplementedError('No authentication function is set')

        try:
            if asyncio.iscoroutinefunction(self.authn_fn):
                authn = await self.authn_fn(self._cxobj, id, secret)
            else:
                authn = self.authn_fn(self._cxobj, id, secret)
        except Exception as exc:
            raise RuntimeWarning(f'While attempting to authenticate, an exception was raised: {exc}')

        if authn:
            pass

        return authn

    # Authorization - note, this only validates a sig/checks a claim
    async def authorize(self, **kwargs) -> str | bool:

        # default: unauthorized
        authz: bool = False

        if self.authz_fn is None:
            raise NotImplementedError('No authorization function is set')

        try:
            if asyncio.iscoroutinefunction(self.authz_fn):
                authz = await self._authz_fn(self._cxobj, **kwargs)
            else:
                authz = self._authz_fn(self._cxobj, **kwargs)
        except Exception as exc:
            raise RuntimeWarning(f'While attempting to authorize, an exception was raised: {exc}')

        return authz

    async def jwt_authn(self, id: str = '', secret: str = '') -> str:
        if self.privkey is None:
            raise ValueError("No private key set for encoding")

        return jwt.encode({'test': 'testdata'}, key=self.privkey, algorithm="RS256")

    # if there's no claimset, will return as valid if the token is valid
    async def jwt_authz(self, token: str = '', claimset: dict | None = None) -> bool:
        if self.pubkey is None:
            raise ValueError("No private key set for encoding")

        token_dict: str = jwt.decode(token, self.pubkey, algorithms=["RS256"])

        authz = await self.authorize(token_dict=token_dict, claimset=claimset)

        return authz