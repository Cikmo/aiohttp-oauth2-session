"""A small package that adds OAuth2 support for aiohttp.ClientSession."""

__version__ = "0.0.0"
__version_info__ = tuple(int(i) for i in __version__.split("."))

from .session import OAuth2Session as OAuth2Session
