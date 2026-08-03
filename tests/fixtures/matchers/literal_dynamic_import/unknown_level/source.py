level = 0
options: dict[str, object] = {}

__import__("targetpkg", level=level)
__import__("targetpkg", **options)
