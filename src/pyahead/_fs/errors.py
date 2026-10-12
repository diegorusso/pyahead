"""Typed failures shared by the hardened readers and writers."""


class UnsafeEntryError(OSError):
    """A path is not a stable regular file beneath real directories."""


class NotRegularFileError(UnsafeEntryError):
    """The entry is a link, device, directory, or other non-regular file."""


class NotRealDirectoryError(UnsafeEntryError):
    """A parent of the entry is a link or other non-directory."""


class EntryChangedError(UnsafeEntryError):
    """The entry or a parent changed identity while it was opened or read."""


class NotAFilePathError(ValueError):
    """A rooted path names the root itself rather than a file beneath it."""
