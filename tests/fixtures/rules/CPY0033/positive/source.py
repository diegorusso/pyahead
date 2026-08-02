from urllib.request import urlopen

urlopen("https://example.invalid", cafile="bundle.pem")
