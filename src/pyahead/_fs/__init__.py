"""Hardened file access shared by every reader and writer in PyAhead.

rooted: bounded reads of a regular file beneath a trusted root that refuse
links and detect replacement while reading. windows: the same guarantees,
and atomic writes, through native handles on Windows. errors: the typed
failures both raise.
"""
