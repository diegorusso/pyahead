import gettext

translation = gettext.translation("app", fallback=True)
gettext.install("app", names=["ngettext"])
