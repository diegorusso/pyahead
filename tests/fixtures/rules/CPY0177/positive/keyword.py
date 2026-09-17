import plistlib
from pathlib import Path

with Path("a.plist").open("rb") as handle:
    loaded = plistlib.load(handle, use_builtin_types=False)
parsed = plistlib.loads(b"", use_builtin_types=True)
