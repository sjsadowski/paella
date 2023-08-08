import asyncio
from typing import Callable, Any
import jwt

class Pyaauth:

    __slots__ = [
        '_authn_fn',
        '_authz_fn',
        '_pubkey',
        '_privkey',
        '_cxobj'
    ]

    def __init__(self, authn_fn=None, authz_fn=None, cxobj=None, privkey=None, pubkey=None) -> None:
        self.authn_fn = authn_fn
        self.authz_fn = authz_fn
        self.privkey = privkey
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
        self._privkey = privkey


    @property
    def cxobj(self) -> Any:
        return self._cxobj

    @cxobj.setter
    def privkey(self, cxobj: Any) -> None:
        self._cxobj = cxobj


    # If authenticated, returns jwt or None
    async def authenticate(self, id: str, secret: str) -> str | bool:

        # default: not authenticated
        authn: bool = False

        if self.authn_fn is None:
            raise NotImplementedError('No authentication function is set')

        if asyncio.isawaitable(self.authn_fn):
            authn = await self.authn_fn(id, secret)
        else:
            authn = self.authn_fn(id, secret)

        if authn:
            pass

        return authn

    # Authorization - note, this only validates a sig/checks a claim
    async def authorize(self, jwt: str = '', claim: str = '', value: str = '') -> str | bool:

        # default: unauthorized
        authz: bool = False

        if self.authz_fn is None:
            raise NotImplementedError('No authorization function is set')


        if asyncio.isawaitable(self.authz_fn):
            await self.authn_fn(jwt, claim, value)
        else:
            self.authn_fn(jwt, claim, value)


        return authz