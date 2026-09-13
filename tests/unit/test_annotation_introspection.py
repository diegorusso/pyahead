"""Controlled runtime evidence for the typing-alias investigation decision."""

from __future__ import annotations

import types
import typing
from typing import Any

import pytest


@pytest.mark.parametrize("name", ["AnyStr", "Text", "Hashable", "Sized"])
def test_stored_annotation_can_break_only_when_introspected(name: str) -> None:
    """Simulated alias removal breaks deferred hints despite successful calls."""
    subject = getattr(typing, name)
    owner = types.SimpleNamespace(**{name: subject})
    namespace: dict[str, Any] = {"owner": owner}
    source = (
        "from __future__ import annotations\n"
        f"def identity(value: owner.{name}): return value\n"
    )
    exec(source, namespace)  # noqa: S102 - fixed, test-owned source and names.
    identity = namespace["identity"]
    assert identity.__annotations__ == {"value": f"owner.{name}"}
    assert typing.get_type_hints(identity) == {"value": subject}
    assert identity("sample") == "sample"

    # Remove only the synthetic owner's slot, never a real typing attribute.
    delattr(owner, name)
    assert identity("sample") == "sample"
    with pytest.raises(AttributeError, match=name):
        typing.get_type_hints(identity)


@pytest.mark.parametrize("name", ["AnyStr", "Text", "Hashable", "Sized"])
def test_guarded_annotation_lacks_a_binding_before_any_removal(name: str) -> None:
    """Supplying a hint namespace answers a different question from live C1."""
    namespace: dict[str, Any] = {}
    source = (
        "from __future__ import annotations\n"
        f"if False:\n    from typing import {name}\n"
        f"def identity(value: {name}) -> {name}: return value\n"
    )
    exec(source, namespace)  # noqa: S102 - fixed, test-owned source and names.
    identity = namespace["identity"]
    assert name not in identity.__globals__
    assert identity("sample") == "sample"
    with pytest.raises(NameError, match=name):
        typing.get_type_hints(identity)

    subject = getattr(typing, name)
    assert typing.get_type_hints(identity, globalns={name: subject}) == {
        "value": subject,
        "return": subject,
    }
    assert name not in identity.__globals__
    with pytest.raises(NameError, match=name):
        typing.get_type_hints(identity)


@pytest.mark.parametrize("name", ["AnyStr", "Text", "Hashable", "Sized"])
def test_local_annotation_is_unstored_even_without_a_live_alias(name: str) -> None:
    """A function-local annotation remains absent from runtime type hints."""
    namespace: dict[str, Any] = {}
    source = (
        "from __future__ import annotations\n"
        f"if False:\n    from typing import {name}\n"
        "def identity(value):\n"
        f"    local: {name} = value\n"
        "    return local\n"
    )
    exec(source, namespace)  # noqa: S102 - fixed, test-owned source and names.
    identity = namespace["identity"]
    assert name not in identity.__globals__
    assert identity("sample") == "sample"
    assert identity.__annotations__ == {}
    assert typing.get_type_hints(identity) == {}
