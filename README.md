# aiohttp-oauth2-session

A small package that adds OAuth2 support for aiohttp.ClientSession.

## Installation

```bash
pip install aiohttp-oauth2-session
```

## Basic Usage

```python
from aiohttp_oauth2_session import OAuth2Session
```

You can create a session with or without a token already known.

```python
token = {
    "access_token": "abc1234",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "def5678",
}

session = OAuth2Session(
    client_id="client_id",
    client_secret="client_secret",
    redirect_uri="https://example.com/oauth/redirect",
    scope="scope1 scope2",
    token=token,
)

# Which allows you to make authenticated requests straight away.
resp = await session.get("https://example.com/api/resource")
await session.close()
```

You can also create a session without a token and fetch one later.

```python
session = OAuth2Session(
    client_id="client_id",
    client_secret="client_secret",
    redirect_uri="https://example.com/oauth/redirect",
    scope="scope1 scope2",
)

await session.fetch_token(
    token_url="https://example.com/oauth/token",
    authorization_response="https://example.com/oauth/redirect?code=abc1234",
)

# now you can make authenticated requests.
resp = await session.get("https://example.com/api/resource")
await session.close()
```

You can also use context managers to automatically close the session.

```python
async with OAuth2Session(
    client_id="client_id",
    client_secret="client_secret",
    redirect_uri="https://example.com/oauth/redirect",
    scope="scope1 scope2",
) as session:
    await session.fetch_token(
        token_url="https://example.com/oauth/token",
        authorization_response="https://example.com/oauth/redirect?code=abc1234",
    )
    async with session.get("https://example.com/api/resource") as resp:
        print(await resp.json())
```

## Feel free to contribute!

What still needs to be done:

- [ ] Add more comprehensive tests
- [ ] Add typed support for other aiohttp client sessions
- [ ] Expand the depency versions to be less restrictive
- [ ] Make the code more readable, it's a bit messy right now
- [ ] Whatever else you can think of. Please do open an issue or PR!

---

This package is based on [a gist](https://gist.github.com/kellerza/5ca798f49983bb702bc6e7a05ba53def) by [kellerza](https://gist.github.com/kellerza). Thank you very much!
