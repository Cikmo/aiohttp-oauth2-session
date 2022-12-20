"""Some type annotated wrapper's for used oauthlib functions and classes."""

from typing import Any
from oauthlib.common import (
    generate_token as _generate_token,  # type: ignore
    urldecode as _urldecode,  # type: ignore
    UNICODE_ASCII_CHARACTER_SET,
)

from oauthlib.oauth2 import (
    WebApplicationClient as _WebApplicationClient,  # type: ignore
)

from oauthlib.oauth2 import is_secure_transport as _is_secure_transport  # type: ignore

Token = dict[str, str | int | float | bool | None]


## oauthlib.common ##
def generate_token(length: int = 32, chars: str = UNICODE_ASCII_CHARACTER_SET) -> str:
    """Typed wrapper for oauthlib.common.generate_token.

    Generates a non-guessable OAuth token

    OAuth (1 and 2) does not specify the format of tokens except that they
    should be strings of random characters. Tokens should not be guessable
    and entropy when generating the random characters is important. Which is
    why SystemRandom is used instead of the default random.choice method.

    Args:
        length: Length of the token. Defaults to 32.
        chars: Characters to use when generating the token. Defaults to ascii characters.

    """
    if chars == "":
        raise ValueError("Invalid character set")
    if length < 1:
        raise ValueError("Token length must be greater than 0")
    return _generate_token(length, chars)  # type: ignore


def urldecode(query: str) -> list[tuple[str, str]]:
    """Typed wrapper for oauthlib.common.urldecode.

    Decode a query string in x-www-form-urlencoded format into a sequence
    of two-element tuples.

    Unlike urlparse.parse_qsl(..., strict_parsing=True) urldecode will enforce
    correct formatting of the query string by validation. If validation fails
    a ValueError will be raised. urllib.parse_qsl will only raise errors if
    any of name-value pairs omits the equals sign.

    Args:
        query: The query string to decode.

    """
    return _urldecode(query)  # type: ignore


## oauthlib.oauth2 ##
def is_secure_transport(url: str) -> bool:
    """Typed wrapper for oauthlib.oauth2.is_secure_transport.

    Check if the uri is over ssl.

    Args:
        url: The URL to check.

    """
    return _is_secure_transport(url)  # type: ignore


class WebApplicationClient(_WebApplicationClient):
    def __init__(self, client_id: str, code: str | None = None, **kwargs: Any) -> None:
        super().__init__(client_id, code, **kwargs)  # type: ignore
        self.client_id: str
        self.token: Token
        self.code: str | None
        self.access_token: str | None

    def populate_token_attributes(self, response: Token) -> None:
        super().populate_token_attributes(response)  # type: ignore

    def prepare_request_uri(
        self,
        uri: str,
        redirect_uri: str | None = None,
        scope: str | None = None,
        state: str | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        **kwargs: Any,
    ) -> str:  # type: ignore
        return super().prepare_request_uri(  # type: ignore
            uri=uri,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            kwargs=kwargs,
        )
