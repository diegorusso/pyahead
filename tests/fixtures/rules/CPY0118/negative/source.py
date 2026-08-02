from ssl import PROTOCOL_TLS_CLIENT, SSLContext

options: dict[str, object] = {}

SSLContext(PROTOCOL_TLS_CLIENT)
SSLContext(unproved=True)
SSLContext(**options)
