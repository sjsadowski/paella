# pyaauth

Simple Asynchronous Auth library



# Notes

by default uses RSA public/private keys.

uses a passed function to evaluate authentication and authorization, this function can be asynchronous (and probably should be)

This assumes two things - first, that you are setting up a connection object of some sort (if necessary) and secondly that your authentication and authorization functions accurately perform their duties.

For example: it is 100% acceptable to have a authorization function that lools like this:

```py
async def authenticate() -> bool:
    return True
```
or
```py
async def authenticate() -> bool:
    return False
```


The first will always pass, the second will always fail, being their return values are ```True``` and ```False``` respectively.