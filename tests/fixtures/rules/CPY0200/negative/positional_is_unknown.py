import gettext

# A positional codeset cannot be told apart statically; it is not claimed.
gettext.install("app", "/usr/share/locale", "utf-8")
