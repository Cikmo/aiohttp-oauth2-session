import pytest

from aiohttp import ClientSession

from OAuth2Session import OAuth2Session

from unittest import mock


@pytest.fixture
def oauth2_session():
    return OAuth2Session(
        client_id="test_client_id", scope="test_scope", redirect_uri="test_redirect_uri"
    )


def test_init(oauth2_session: OAuth2Session):
    assert isinstance(oauth2_session, ClientSession)
    assert oauth2_session.client_id == "test_client_id"
    assert oauth2_session.scope == "test_scope"
    assert oauth2_session.redirect_uri == "test_redirect_uri"
    assert oauth2_session.state is None
    assert len(oauth2_session.token) == 0


def test_init_with_token(oauth2_session: OAuth2Session):
    oauth2_session = OAuth2Session(
        client_id="test_client_id",
        scope="test_scope",
        redirect_uri="test_redirect_uri",
        token={"access_token": "abcdef", "token_type": "Bearer"},
    )
    assert oauth2_session.access_token == "abcdef"


def test_new_state(oauth2_session: OAuth2Session):
    state = oauth2_session.new_state()
    assert isinstance(state, str)
    assert len(state) == 32
    assert oauth2_session.state == state


def test_new_state_token(oauth2_session: OAuth2Session):
    oauth2_session.token = {"access_token": "abcdefg", "token_type": "Bearer"}
    assert oauth2_session.access_token == "abcdefg"
    oauth2_session.token = {"access_token": "hijklmn", "token_type": "Bearer"}
    assert oauth2_session.access_token == "hijklmn"


def test_get_client_id(oauth2_session: OAuth2Session):
    assert oauth2_session.client_id == "test_client_id"


def test_new_client_id(oauth2_session: OAuth2Session):
    oauth2_session.client_id = "new_client_id"
    assert oauth2_session.client_id == "new_client_id"


def test_authorized(oauth2_session: OAuth2Session):
    assert not oauth2_session.authorized
    oauth2_session.token = {"access_token": "abcdefg", "token_type": "Bearer"}
    assert oauth2_session.authorized


def test_authorization_url():
    oauth2_session = OAuth2Session(
        client_id="test_client_id",
        scope="test_scope",
        redirect_uri="komodo.link/redirect",
        token={"access_token:": "abcdef", "token_type": "Bearer"},
    )

    state = oauth2_session.new_state()

    url, returned_state = oauth2_session.authorization_url(
        "https://example.com", state=state
    )
    assert (
        url
        == f"https://example.com?response_type=code&client_id=test_client_id&redirect_uri=komodo.link%2Fredirect&scope=test_scope&state={state}"
    )
    assert oauth2_session.state == returned_state


@pytest.mark.asyncio
async def test_fetch_token():
    # Create a mock token object
    token = {"access_token": "mock_access_token", "token_type": "mock_token_type"}

    # Set up the test parameters
    token_url = "https://example.com/token"
    code = "mock_code"
    authorization_response = "https://example.com/redirect"
    body = ""
    auth = None
    username = "mock-username"
    password = "mock-password"
    method = "POST"
    force_querystring = False
    timeout = None
    headers = {"Accept": "application/json"}
    verify_ssl = True
    proxy = None
    include_client_id = None
    client_id = "mock-client-id"
    client_secret = "mock-client-secret"

    # Create the object being tested
    object_being_tested = OAuth2Session(
        client_id=client_id,
        scope="test_scope",
        redirect_uri="test_redirect_uri",
    )

    # Call the method being tested
    result = await object_being_tested.fetch_token(
        token_url,
        code,
        authorization_response,
        body,
        auth,
        username,
        password,
        method,
        force_querystring,
        timeout,
        headers,
        verify_ssl,
        proxy,
        include_client_id,
        client_id,
        client_secret,
    )
