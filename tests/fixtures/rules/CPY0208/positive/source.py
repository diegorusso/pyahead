import hashlib

digest = hashlib.sha256(string=b"payload").hexdigest()
