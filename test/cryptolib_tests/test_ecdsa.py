import unittest
from cryptolib.openssl.ecdsa import KEY
from cryptolib.hex import bytes2hex, hex2bytes


class TestECDSA(unittest.TestCase):

    def setUp(self):
        pass

    def test_ecdsa_set_privkey_getprivkey(self):
        privkey = "305402010104200a914c41e0dbae7f4a3a7e743ca7e274f7f79841fec93688aad19349fdfe9920a00706052b8104000aa12403220003a24397cc62845ae1b61011be687e3cbe6f8525e5b13d6a478daac5006f8a0a8d"
        key = KEY()

        key.set_privkey(hex2bytes(privkey),False)

        self.assertEqual(bytes2hex(key.get_privkey()), privkey)

    def test_ecdsa_get_privkey_b256(self):
        privkey = "305402010104200a914c41e0dbae7f4a3a7e743ca7e274f7f79841fec93688aad19349fdfe9920a00706052b8104000aa12403220003a24397cc62845ae1b61011be687e3cbe6f8525e5b13d6a478daac5006f8a0a8d"
        key = KEY()
        key.set_privkey(hex2bytes(privkey))

        result = bytes2hex(key.get_privkey_b256())

        self.assertEqual(result, "0a914c41e0dbae7f4a3a7e743ca7e274f7f79841fec93688aad19349fdfe9920")

    def test_ecdsa_set_privkey_b256(self):
        privkey = "0a914c41e0dbae7f4a3a7e743ca7e274f7f79841fec93688aad19349fdfe9920"
        key = KEY()
        key.set_privkey_b256(hex2bytes(privkey))

        result = bytes2hex(key.get_privkey())
        self.assertEqual(result, "305402010104200a914c41e0dbae7f4a3a7e743ca7e274f7f79841fec93688aad19349fdfe9920a00706052b8104000aa12403220003a24397cc62845ae1b61011be687e3cbe6f8525e5b13d6a478daac5006f8a0a8d")

    def test_ecdsa_get_pubkey_compressed(self):
        privkey = "0a914c41e0dbae7f4a3a7e743ca7e274f7f79841fec93688aad19349fdfe9920"
        key = KEY()
        key.set_privkey_b256(hex2bytes(privkey))

        result = bytes2hex(key.get_pubkey())

        self.assertEqual(result, "03a24397cc62845ae1b61011be687e3cbe6f8525e5b13d6a478daac5006f8a0a8d")
    def test_ecdsa_get_pubkey_notcompressed(self):
        privkey = "0a914c41e0dbae7f4a3a7e743ca7e274f7f79841fec93688aad19349fdfe9920"
        key = KEY()
        key.set_privkey_b256(hex2bytes(privkey), compressed=False)

        result = bytes2hex(key.get_pubkey())

        self.assertEqual(
            result,
            "04a24397cc62845ae1b61011be687e3cbe6f8525e5b13d6a478daac5006f8a0a8d6bd0fab7ab81e73c4f9b9e258838eedcddc5eb666fc0be1b687e85be8cb2618d")

    def test_ecdsa_sign_verify(self):
        privkey = "0a914c41e0dbae7f4a3a7e743ca7e274f7f79841fec93688aad19349fdfe9920"
        key = KEY()
        key.set_privkey_b256(hex2bytes(privkey))
        key2 = KEY()
        key2.set_pubkey(hex2bytes(
            "04a24397cc62845ae1b61011be687e3cbe6f8525e5b13d6a478daac5006f8a0a8d6bd0fab7ab81e73c4f9b9e258838eedcddc5eb666fc0be1b687e85be8cb2618d"))
        key2.set_pubkey(hex2bytes("03a24397cc62845ae1b61011be687e3cbe6f8525e5b13d6a478daac5006f8a0a8d"))
        TEXT = b"hello ok"

        sig = key.sign(TEXT)
        result = key2.verify(TEXT, sig)
        self.assertEqual(result, 1)

    def test_generate(self):
        """ generate is a bit difficult to test, as we can't inject fake random from openssl, so we test it indirectly"""
        key = KEY()
        key.generate()
        key_sign = KEY()
        key_verify = KEY()
        key_sign.set_privkey(key.get_privkey())
        key_verify.set_pubkey(key.get_pubkey())
        TEXT = b"hello ok"

        sig = key_sign.sign(TEXT)
        result = key_verify.verify(TEXT, sig)

        self.assertEqual(result, 1)

if __name__ == "__main__":
    unittest.main()
