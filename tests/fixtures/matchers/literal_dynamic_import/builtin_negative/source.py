from builtins import __import__ as load_module

name = "targetpkg"
load_module(name, level=0)
load_module("targetpkg", level=1)
