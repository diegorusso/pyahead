from webbrowser import MacOSXOSAScript

# The class itself is deprecated in 3.15 (CPY0206); this fixture isolates _name.
v = MacOSXOSAScript._name  # pyahead: ignore[CPY0206] -- see above  # noqa: SLF001
