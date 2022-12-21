from typing import Iterable

import pytest

from aiohttp_oauth2_session.typed_oauthlib import (
    UNICODE_ASCII_CHARACTER_SET,
    generate_token,
    is_secure_transport,
    urldecode,
    WebApplicationClient,
)


class TestGenerateToken:
    # Add more test cases using the parametrize decorator
    @pytest.mark.parametrize(
        "length, chars, expected_length",
        [
            (32, UNICODE_ASCII_CHARACTER_SET, 32),
            (64, UNICODE_ASCII_CHARACTER_SET, 64),
            (32, "abcdef12345", 32),
            (100, UNICODE_ASCII_CHARACTER_SET, 100),
        ],
    )
    def test_generate_valid_token(self, length: int, chars: str, expected_length: int):
        """Test that the function generates a valid token"""
        token = generate_token(length=length, chars=chars)
        assert (
            len(token) == expected_length
        ), f"Invalid token length: {len(token)}. Expected {expected_length}."
        assert all(
            c in chars for c in token
        ), f"Invalid character in token: {set(token) - set(chars)}"

    def test_generate_token_invalid_chars(self):
        """Test that the function raises an error when an invalid character set is provided"""
        with pytest.raises(ValueError, match="Invalid character set"):
            generate_token(chars="")

    def test_generate_token_invalid_length(self):
        """Test that the function raises an error when an invalid length is provided"""
        with pytest.raises(ValueError, match="Token length must be greater than 0"):
            generate_token(length=-1)

    def test_generate_token_uniqueness(self):
        """Test that the function generates unique tokens each time it is called"""
        tokens: Iterable[str] = set()
        for _ in range(100):
            token = generate_token()
            assert token not in tokens, f"Duplicate token generated: {token}"
            tokens.add(token)


@pytest.mark.parametrize(
    "query, expected",
    [
        (
            "name=value&othername=othervalue",
            [("name", "value"), ("othername", "othervalue")],
        ),
        (
            "name=value&othername=other%20value",
            [("name", "value"), ("othername", "other value")],
        ),
        ("", []),
    ],
)
def test_urldecode(query: str, expected: list[tuple[str, str]]):
    """Test that the function correctly decodes a query string"""
    assert urldecode(query) == expected


class TestIsSecureTransport:
    @pytest.mark.parametrize(
        "url, expected", [("https://example.com", True), ("http://example.com", False)]
    )
    def test_is_secure_transport(self, url: str, expected: bool):
        """Test that the function correctly determines whether a URL uses a secure transport"""
        assert is_secure_transport(url) == expected

    def test_is_secure_transport_insecure_transport(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Test that the function returns True when OAUTHLIB_INSECURE_TRANSPORT is set"""
        monkeypatch.setenv("OAUTHLIB_INSECURE_TRANSPORT", "1")
        assert is_secure_transport("http://example.com") == True


@pytest.fixture
def web_application_client() -> WebApplicationClient:
    client_id = "test_client_id"
    return WebApplicationClient(client_id)


def test_init(web_application_client: WebApplicationClient) -> None:
    assert web_application_client.client_id == "test_client_id"
    assert web_application_client.code is None
    assert web_application_client.access_token is None
    assert web_application_client.refresh_token is None


# test typed WebApplicationClient class
def test_populate_token_attributes(
    web_application_client: WebApplicationClient,
) -> None:
    token = {
        "access_token": "test_access_token",
        "refresh_token": "test_refresh_token",
        "token_type": "Bearer",
        "expires_in": 3600,
    }
    web_application_client.populate_token_attributes(token)
    assert web_application_client.access_token == "test_access_token"
    assert web_application_client.refresh_token == "test_refresh_token"
    assert web_application_client.token_type == "Bearer"
    assert web_application_client.expires_in == 3600


def test_parse_request_uri_response(
    web_application_client: WebApplicationClient,
) -> None:
    uri = "https://test.com?code=test_code&state=test_state"
    state = "test_state"
    response = web_application_client.parse_request_uri_response(uri, state)
    assert response == {"code": "test_code", "state": "test_state"}
