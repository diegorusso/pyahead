import binascii

encoded = binascii.b2a_base64(b"data")
checksum = binascii.crc_hqx(b"data", 0)
