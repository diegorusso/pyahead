use_standard_library = False

if use_standard_library:
    from importlib import import_module as load_module
else:
    from replacement import import_module as load_module

load_module("targetpkg")
