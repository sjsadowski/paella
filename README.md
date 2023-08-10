# paella

Simple Asynchronous Auth library

## \*WARNING\*
THIS REPOSITORY CONTAINS SECRETS FOR USE IN TESTING

DO NOT REUSE THESE SECRETS FOR PRODUCTION

## requirements
- python >= 3.11 (uses modern union typehints)

## dependencies
- pyjwt[crypto] >= 2.8.0"

## testing
I deliberately included a test keypair, please see the warning above.

### test data
In ```./tests/db/test_users.db``` there is minimal prepopulated data:

```sql
sqlite> .schema Users
CREATE TABLE Users (id int primary key not null, email char(128) not null, password char(128) not null);
sqlite> select * from Users;
1|testuser@test.com|a_very_basic_password
2|testuser2@test.com|65332c4349d159ab3d41b8e1a01db7d77928f1b8215fd345e19e5cfe016f468a
```
testuser2@test.com has a sha256 hash of the following string: ```salt+basic_password```

## Usage

### Creating auth object
By default uses RSA public/private keys. PyJWT does not have a concept of
unencrypted JWTs. This project is designed specifically to rely on
asynchronous RSA keypairs, which means that you do not have to use it
for authentication, but can use it for authorization so long as the pubkey
and the authorization function are properly configured.

Initially you can create an empty auth object (if you so desire) that doesn't
really do anything:

```py
from paella import Paella

auth: Paella = Paella()
```

#### Authentication (authn) Function

The authentication function takes in an id and a secret and returns a boolean or a dict. If a dict is returned,
that is then used to populate a JWT with custom claims or override the defaults, otherwise the defaults are used
if the value returned is ```True```.

The authentication function itself must have a function signature that matches the below:

```py
async def authn(connection: Any, id: str, secret: str) -> dict | bool:
```

#### Authorization (authz) Function

The authorization function takes in a dict and returns a boolean.

The authorization function itself must have a function signature that matches the below:

```py
async def authn(connection: Any, claimset: dict) -> bool:
```

### Caveats
uses a passed function to evaluate authentication and authorization, this function can be asynchronous (and probably should be)

This assumes two things - first, that you are setting up a connection object of some sort (if necessary) and secondly that your authentication and authorization functions accurately perform their duties.

For example: it is 100% acceptable to have a authorization function that lools like this:

```py
async def authenticate(cxobj: Any, id: str, secret: str) -> bool:
    return True
```
or
```py
async def authenticate(cxobj: Any, id: str, secret: str) -> bool:
    return False
```


The first will always pass, the second will always fail, being their return values are ```True``` and ```False``` respectively.