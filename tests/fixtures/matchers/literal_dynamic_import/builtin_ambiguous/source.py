use_builtin = True

if use_builtin:
    from builtins import __import__ as load_module
else:
    from replacement import load_module

load_module("targetpkg", level=0)
