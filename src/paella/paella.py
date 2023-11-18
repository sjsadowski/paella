import asyncio
import functools

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
        if authn_fn is None:
            self.authn_fn = self.default_authn_fn
        else:
            self.authn_fn = authn_fn

        if authz_fn is None:
            self.authz_fn = self.default_authz_fn
        else:
            self.authz_fn = authz_fn

        self.password = password
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

    @staticmethod
    async def default_authn_fn(cxobj, *args, **kwargs) -> bool:

        # defaults to not authenticated if we pass no arguments to it
        authn: dict | bool = False
        if len(kwargs) > 0:
            authn = kwargs

        return authn

    @staticmethod
    async def default_authz_fn(cxobj, *args, **kwargs) -> bool:
        authz: bool = True

        # if we have a token_dict and a claimset, do comparison
        if 'token_dict' in kwargs.keys() and 'claimset' in kwargs.keys():
            token_dict = kwargs['token_dict']
            claimset = kwargs['claimset']

            # iterate through the claimset to make sure the key is present
            # if the key is not present, the authorization is False
            # if the key is present, but the value doesn't match, the
            # authorization is also False
            for k,v in claimset.items():
                if k in token_dict.keys():
                    if token_dict[k] != v:
                        authz = False
                        break
                else:
                    authz = False
                    break

        # if we have a token_dict but no claimset, assume authorized
        elif 'token_dict' in kwargs:
            authz = True

        else:
            authz = False

        return authz

    # If authenticated, returns jwt or None
    async def authenticate(self, id: str = '', secret: str = '') -> dict | bool:

        # default: not authenticated
        authn: bool | dict = False

        if self._authn_fn is None:
            raise NotImplementedError('No authentication function is set')

        try:
            authn = await self.authn_fn(self._cxobj, id, secret)
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
            authz = await self._authz_fn(self._cxobj, **kwargs)
        except Exception as exc:
            raise RuntimeWarning(f'While attempting to authorize, an exception was raised: {exc}')

        return authz

    # If the authn_fn returns a boolean, encodes the id/secret and returns that in the jwt
    # Otherwise, if it is a dict, encodes the dict values.
    async def jwt_authn(self, id: str = '', secret: str = '') -> str:
        if self.privkey is None:
            raise ValueError("No private key set for encoding")

        authn: dict | bool = await self.authenticate(id, secret)
        token: dict = {}

        if isinstance(authn, dict):
            token = authn
        else:
            token = {'id': id, 'secret': secret}

        return jwt.encode(token, key=self.privkey, algorithm="RS256")


    # get the dict from the token
    async def decode(self, token: str | None = None) -> dict:
        if token is None:
            raise ValueError("No token available to decode")

        if self.pubkey is None:
            raise ValueError("No public key set for decoding")

        loop = asyncio.get_running_loop()

        decoded_token = await loop.run_in_executor(
                    None,
                    functools.partial(
                        jwt.decode, token, self.pubkey, algorithms=["RS256"]
                        )
                    )

        return decoded_token



    # if there's no claimset, will return as valid if the token is valid
    async def jwt_authz(self, token: str = '', claimset: dict | None = None) -> bool:
        if self.pubkey is None:
            raise ValueError("No public key set for decoding")

        token_dict: dict = await self.decode(token)

        authz = await self.authorize(token_dict=token_dict, claimset=claimset)

        return authz

