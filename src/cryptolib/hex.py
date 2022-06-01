import binascii
import base64

def hex2bytes(str):
    """ str --> bytes"""
    return binascii.unhexlify(str)

def bytes2hex(bytestr):
    """ bytes --> str """
    return str(bytestr.hex())

def bytes_to_base64(bytestr):
    """ Same as base64.b64encode but also converts to string"""
    return base64.b64encode(bytestr).decode()

def base64_to_bytes(base64str):
    """ Same as base64.b64encode but also converts to string"""
    return base64.b64decode(base64str)

