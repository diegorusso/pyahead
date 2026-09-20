import gettext

translation = gettext.translation("app", codeset="utf-8", fallback=True)
gettext.install("app", codeset="utf-8")
