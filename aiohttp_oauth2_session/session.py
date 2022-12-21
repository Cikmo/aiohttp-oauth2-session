from typing import Any, Awaitable, Callable, Mapping, Self

import aiohttp
from aiohttp.typedefs import LooseHeaders, StrOrURL
from oauthlib.oauth2 import InsecureTransportError, TokenExpiredError

from .typed_oauthlib import (
    WebApplicationClient,
    generate_token,
    is_secure_transport,
    urldecode,
)

JsonCompatibleDict = Mapping[str, str | int | float | bool | None]

Token = JsonCompatibleDict


class TokenUpdated(Warning):
    """Exception."""

    def __init__(self, token: Token):
        super(TokenUpdated, self).__init__()
        self.token = token


class OAuth2Session(aiohttp.ClientSession):
    """OAuth2 support for aiohttp.ClientSession."""

    def __init__(
        self,
        client_id: str,
        scope: str,
        redirect_uri: str,
        token: Token | None = None,
        client: WebApplicationClient | None = None,
        auto_refresh_url: str | None = None,
        auto_refresh_kwargs: JsonCompatibleDict | None = None,
        state: str | None = None,
        token_updater: Callable[[Token], Awaitable[None]] | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize OAuth2Session."""
        super().__init__(**kwargs)

        self._client = client or WebApplicationClient(client_id, token=token)
        self.state = state
        self.scope = scope
        self.redirect_uri = redirect_uri
        self.auto_refresh_url = auto_refresh_url
        self.auto_refresh_kwargs = auto_refresh_kwargs or {}
        self.token_updater = token_updater

        # Allow customizations for non compliant providers through various
        # hooks to adjust requests and responses.
        self.compliance_hook: dict[str, set[Callable[..., Any]]] = {
            "access_token_response": set(),
            "refresh_token_response": set(),
            "protected_request": set(),
        }

    def new_state(self) -> str:
        """Generates a state string to be used in authorizations sets it as the current state.

        Returns:
            The generated state string.
        """
        self.state = generate_token()
        return self.state

    @property
    def client_id(self) -> str:
        return self._client.client_id

    @client_id.setter
    def client_id(self, value: str) -> None:
        self._client.client_id = value

    @client_id.deleter
    def client_id(self) -> None:
        del self._client.client_id

    @property
    def token(self) -> Token:
        """Get the token."""
        return self._client.token

    @token.setter
    def token(self, value: Token) -> None:
        self._client.token = value
        self._client.populate_token_attributes(value)

    @property
    def access_token(self) -> str | None:
        """Get the access token."""
        return self._client.access_token

    @access_token.setter
    def access_token(self, value: str | None):
        self._client.access_token = value

    @access_token.deleter
    def access_token(self):
        del self._client.access_token

    @property
    def authorized(self):
        """Boolean that indicates whether this session has an OAuth token
        or not. If True, you can reasonably expect
        OAuth-protected requests to the resource to succeed. If
        False, you need the user to go through the OAuth
        authentication dance before OAuth-protected requests to the resource
        will succeed.
        """
        return bool(self.access_token)

    def authorization_url(
        self, url: str, state: str | None = None, **kwargs: Any
    ) -> tuple[str, str]:
        """Form an authorization URL.

        Args:
            url: Authorization endpoint url, must be HTTPS.
            state: An optional state string for CSRF protection. If not
                      given it will be generated for you.
            kwargs: Extra parameters to include.
        Returns:
            authorization_url, state
        """
        state = state or self.new_state()
        return (
            self._client.prepare_request_uri(
                url,
                redirect_uri=self.redirect_uri,
                scope=self.scope,
                state=state,
                **kwargs,
            ),
            state,
        )

    async def fetch_token(
        self,
        token_url: str,
        code: str | None = None,
        authorization_response: str | None = None,
        body: str = "",
        auth: aiohttp.BasicAuth | None = None,
        username: str | None = None,
        password: str | None = None,
        method: str = "POST",
        force_querystring: bool = False,
        timeout: int | float | None = None,
        headers: dict[str, str | int] | None = None,
        verify_ssl: bool = True,
        proxy: StrOrURL | None = None,
        include_client_id: bool | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        **kwargs: Any,
    ) -> Token:
        """Fetch a token.

        Returns:
            A token dict.
        """
        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        if not code and authorization_response:
            self._client.parse_request_uri_response(
                authorization_response, state=self._client.code
            )
            code = self._client.code
        elif not code:
            code = self._client.code
            if not code:
                raise ValueError(
                    "Please supply either code or " "authorization_response parameters."
                )

        if username is not None:
            kwargs["username"] = username
        if password is not None:
            kwargs["password"] = password

        # is an auth explicitly supplied?
        if auth is not None:
            # if we're dealing with the default of `include_client_id` (None):
            # we will assume the `auth` argument is for an RFC compliant server
            # and we should not send the `client_id` in the body.
            # This approach allows us to still force the client_id by submitting
            # `include_client_id=True` along with an `auth` object.
            if include_client_id is None:
                include_client_id = False

        # otherwise we may need to create an auth header
        else:
            # since we don't have an auth header, we MAY need to create one
            # it is possible that we want to send the `client_id` in the body
            # if so, `include_client_id` should be set to True
            # otherwise, we will generate an auth header
            if include_client_id is not True:
                include_client_id = False  # idk if this is correct, but I need to set it to something to avoid a None value being passed on.
                client_id = self.client_id
            if client_id:
                client_secret = client_secret if client_secret is not None else ""
                auth = aiohttp.BasicAuth(login=client_id, password=client_secret)

        if include_client_id:
            # this was pulled out of the params
            # it needs to be passed into prepare_request_body
            if client_secret is not None:
                kwargs["client_secret"] = client_secret

        body = self._client.prepare_request_body(
            code=code,
            body=body,
            redirect_uri=self.redirect_uri,
            include_client_id=include_client_id,
            **kwargs,
        )

        headers = headers or {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        }

        self.token = {}
        request_kwargs = {}
        if method.upper() == "POST":
            request_kwargs["params" if force_querystring else "data"] = dict(
                urldecode(body)
            )
        elif method.upper() == "GET":
            request_kwargs["params"] = dict(urldecode(body))
        else:
            raise ValueError("The method kwarg must be POST or GET.")

        async with self.request(
            method=method,
            url=token_url,
            timeout=timeout,
            headers=headers,
            auth=auth,
            verify_ssl=verify_ssl,
            proxy=proxy,
            data=request_kwargs["data"],
        ) as resp:
            text = await resp.text()
            (resp,) = self._invoke_hooks("access_token_response", resp)

        self._client.parse_request_body_response(text, scope=self.scope)
        return self.token

    def token_from_fragment(self, authorization_response: str) -> Token:
        """Parse token from the URI fragment, used by MobileApplicationClients.

        Args:
            authorization_response: The full URL of the redirect back to you.
        Returns:
            A token dict.
        """
        self._client.parse_request_uri_response(
            authorization_response, state=self.state
        )
        self.token = self._client.token
        return self.token

    async def refresh_token(
        self,
        token_url: str,
        refresh_token: str | None = None,
        body: str = "",
        auth: aiohttp.BasicAuth | None = None,
        timeout: int | None = None,
        headers: dict[str, str | int] | None = None,
        verify_ssl: bool = True,
        proxy: StrOrURL | None = None,
        **kwargs: Any,
    ) -> Token:
        """Fetch a new access token using a refresh token.

        Returns:
            A token dict.
        """
        if not token_url:
            raise ValueError("No token endpoint set for auto_refresh.")

        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        refresh_token = refresh_token or self._client.refresh_token

        kwargs.update(self.auto_refresh_kwargs)
        body = self._client.prepare_refresh_body(
            refresh_token=refresh_token, body=body, scope=self.scope, **kwargs
        )

        if headers is None:
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            }

        async with self.post(
            token_url,
            data=dict(urldecode(body)),
            auth=auth,
            timeout=timeout,
            headers=headers,
            verify_ssl=verify_ssl,
            withhold_token=True,
            # proxy=proxies,
        ) as resp:
            text = await resp.text()
            (resp,) = self._invoke_hooks("refresh_token_response", resp)

        self.token = self._client.parse_request_body_response(text, scope=self.scope)
        if "refresh_token" not in self.token:
            new_token: Token = dict(self.token)
            new_token["refresh_token"] = refresh_token
            self.token = new_token
        return self.token

    async def _request(
        self,
        method: str,
        str_or_url: StrOrURL,
        *,
        data: Any = None,
        headers: LooseHeaders | None = None,
        withhold_token: bool = False,
        client_id: str | None = None,
        client_secret: str | None = None,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        """Intercept all requests and add the OAuth 2 token if present.

        Returns:
            A response.
        """
        if not is_secure_transport(str(str_or_url)):
            raise InsecureTransportError()
        if self.token and not withhold_token:
            str_or_url, headers, data = self._invoke_hooks(
                "protected_request", str(str_or_url), headers, data
            )
            try:
                str_or_url, headers, data = self._client.add_token(
                    str(str_or_url), http_method=method, body=data, headers=headers
                )
            # Attempt to retrieve and save new access token if expired
            except TokenExpiredError:
                if self.auto_refresh_url:
                    # We must not pass auth twice.
                    auth = kwargs.pop("auth", None)
                    if client_id and client_secret and (auth is None):
                        auth = aiohttp.BasicAuth(
                            login=client_id, password=client_secret
                        )
                    token = await self.refresh_token(
                        self.auto_refresh_url, auth=auth, **kwargs
                    )
                    if self.token_updater:
                        await self.token_updater(token)
                        str_or_url, headers, data = self._client.add_token(
                            str(str_or_url),
                            http_method=method,
                            body=data,
                            headers=headers,
                        )
                    else:
                        raise TokenUpdated(token)
                else:
                    raise
        return await super()._request(  # type: ignore
            method, str_or_url, headers=headers, data=data, **kwargs
        )

    def register_compliance_hook(
        self, hook_type: str, hook: Callable[..., Any]
    ) -> None:
        """Register a hook for request/response tweaking.
        Available hooks are:
            access_token_response invoked before token parsing.
            refresh_token_response invoked before refresh token parsing.

        Args:
            hook_type: The hook type.
            hook: The hook.
        """
        if hook_type not in self.compliance_hook:
            raise ValueError(f"Hook type {hook_type} is not in {self.compliance_hook}.")
        self.compliance_hook[hook_type].add(hook)

    def _invoke_hooks(self, hook_type: str, *hook_data: Any) -> tuple[Any, ...]:
        """Invoke registered hooks."""
        for hook in self.compliance_hook[hook_type]:
            hook_data = hook(*hook_data)
        return hook_data

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()
