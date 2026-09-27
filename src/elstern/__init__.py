"""elstern — a free, software-only client for ElsterSecure (Mein ELSTER)."""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("elstern")
except PackageNotFoundError:
    __version__ = "0+unknown"
