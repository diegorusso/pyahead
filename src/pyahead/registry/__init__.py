"""Compatibility registry loading."""

from pyahead.model import Registry
from pyahead.registry.loader import load_registry
from pyahead.registry.schema import RegistryError

__all__ = ["Registry", "RegistryError", "load_registry"]
