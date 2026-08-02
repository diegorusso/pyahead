from shutil import rmtree

rmtree("cache", onerror=lambda *_args: None)
