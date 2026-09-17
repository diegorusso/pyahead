import plistlib


def read(options: dict[str, object]) -> object:
    """Load with options the analyser cannot see through."""
    return plistlib.loads(b"", **options)
