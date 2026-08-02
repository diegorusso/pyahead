from shutil import rmtree

rmtree("cache", onexc=lambda *_args: None)
