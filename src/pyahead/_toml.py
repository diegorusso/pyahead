"""Strict parsing of TOML configuration documents."""

import tomllib

from pyahead.model import ConfigurationError


def parse_toml_document(raw: bytes, label: str) -> dict[str, object]:
    """Decode UTF-8 TOML, naming ``label`` in every rejection."""
    try:
        return tomllib.loads(raw.decode("utf-8", errors="strict"))
    except RecursionError as error:
        message = f"{label}: configuration nesting is too deep"
        raise ConfigurationError(message) from error
    except UnicodeError as error:
        message = f"{label}: configuration is not valid UTF-8 TOML"
        raise ConfigurationError(message) from error
    except tomllib.TOMLDecodeError as error:
        message = f"{label}: configuration is not valid TOML"
        raise ConfigurationError(message) from error
