import asyncio
from typing import Callable
import jwt

class Pyaauth:

    __slots__ = [
        'authn_fn',
        'authz_fn'
    ]

    def __init__(self, authn_fn=None, authz_fn=None) -> None:
        self.set_authn_fn(authn_fn)
        self.set_authz_fn(authz_fn)


    def set_authn_fn(self, authn_fn: Callable | None) -> None:
        self.authn_fn = authn_fn


    def set_authz_fn(self, authz_fn: Callable | None) -> None:
        self.authz_fn = authz_fn


    # If authenticated, returns jwt or None
    async def authenticate(self, id: str, secret: str) -> str | bool:
        if self.authn_fn is None:
            raise NotImplementedError('No authentication function is set')

        if asyncio.isawaitable(self.authn_fn):
            await self.authn_fn(id, secret)
        else:
            self.authn_fn(id, secret)

    # Authorization
    async def authorize(self, jwt: str, claim: str, value: str) -> str | bool:
        if self.authz_fn is None:
            raise NotImplementedError('No authorization function is set')


        if asyncio.isawaitable(self.authz_fn):
            await self.authn_fn(jwt, claim, value)
        else:
            self.authn_fn(jwt, claim, value)

