import ctypes
from ctypes.util import find_library
import os
import platform

if os.name == 'nt':
    arch = platform.architecture()[0]
    ssl = ctypes.WinDLL("libeay32.dll")
else:
    basename = os.path.dirname(__file__)
    crypto = ctypes.cdll.LoadLibrary("libcrypto.so")
    ssl = ctypes.cdll.LoadLibrary("libssl.so")
    assert ssl.EC_KEY_new_by_curve_name(714) is not None
