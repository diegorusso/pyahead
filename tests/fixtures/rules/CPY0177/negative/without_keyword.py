import plistlib
from pathlib import Path

with Path("a.plist").open("rb") as handle:
    loaded = plistlib.load(handle, fmt=None)
parsed = plistlib.loads(b"")
