import bz2

# A third positional argument cannot be told apart statically; it is not claimed.
archive = bz2.BZ2File("a.bz2", "rb", 9)
