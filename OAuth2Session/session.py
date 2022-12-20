"""OAuth2 support for aiohttp.ClientSession.
Based on the requests_oauthlib class
Based on: https://gist.github.com/kellerza/5ca798f49983bb702bc6e7a05ba53def
"""

import aiohttp
from typing import Any, Callable

# pyright: reportUnusedImport=false
from .typed_oauthlib import (
    generate_token,
    urldecode,
    is_secure_transport,
    WebApplicationClient,
)

# from oauthlib.oauth2 import (
#     InsecureTransportError,
#     LegacyApplicationClient,
#     TokenExpiredError,
# )


# Example token response
# {
#   "access_token": "6qrZcUqja7812RVdnEKjpzOL4CvHBFG",
#   "token_type": "Bearer",
#   "expires_in": 604800,
#   "refresh_token": "D43f5y0ahjqew82jZ4NViEr2YafMKhue",
#   "scope": "identify"
# }

# Type aliases
JsonCompatibleDict = dict[str, str | int | float | bool | None]

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
        token_updater: Callable[[Token], None] | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize OAuth2Session."""
        super().__init__(**kwargs)

        self._client = client or WebApplicationClient(client_id, token=token)
        self.state = state
        self.scope = scope
        self.redirect_uri = redirect_uri

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
