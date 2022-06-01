from cryptolib.openssl.dll import ssl
import ctypes


def ssl_RAND_bytes(length):
    buffer = ctypes.create_string_buffer(length)
    ssl.RAND_bytes(buffer, length)
    return buffer.raw


def ssl_RAND_add(data, entropy):
    ssl.RAND_add(data, len(data), ctypes.c_double(entropy))
