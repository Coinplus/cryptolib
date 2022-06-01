
from cryptolib.address.address import BitcoinAddress
from cryptolib.openssl.ecdsa import KEY
from cryptolib.sha256 import doublesha256
from cryptolib.openssl.ecdsa import *
from cryptolib.crypto import *
import ctypes
import random
import asynctest
import unittest



test_vector = [{"encrypted_private_key_58": "S6YkJJ2GhU5S6RRXTPHdvaiPF4mz",
                             "passpoint1": "xtnVsbjnbV7Me3jNmX5Woah6pV6kBYfAkt6PUMTnLuiW",
                             "security_code_58": "991cFStzEJyBSd",
                             "passpoint2": "jruYrWhygeoKi6Muxm7yKkgEyubiRbxmaniH42L47JvT",
                             "publickey": "02a6f17fdf17597d181ee746e84daaf41fa0be1a2e4557c173f378540ced7d348f",
                             "address_btc": "134NrMn8hYResFMVH2CD2bhCbwfW1qKLuF",
                             "address_ltc": "LMHL7a5xnCfi843eTABWJckxpA2n5RVTFj",
                             "address_eth": "0x964cBA4814f8CbE9e856F9A07Ce3aE1863BE1579",
                             "privatekey": "7a81f3dbb44a764dbdda52cfdbf38607aabab507f063ae5ebbf1dc50b0ee6eb2",
                             "privatekey_wifltc": "T7A7gPd2ka9a2KNWCMvikthGDcTA1RD6Xx7iEyfc4f9duPDw6DWw",
                             "privatekey_wif": "L1KrEeKrMCAyFUjdeiyrYY9tGkoqwLCCikDTPB34VgyUPVeTzVLu"},
                            {"encrypted_private_key_58": "rHo7riutuSrLdEGsvDmt7FJmA3X9",
                             "passpoint1": "odQjb72x9HkigMxAhVnraFhVxsUnqKNh4VsCEieUwkqT",
                             "security_code_58": "gxfLiRe3u7dNKS",
                             "passpoint2": "nez7GXwg7uV1XB3c91BhwsitHf1sC81JVpnj4rnwrH4c",
                             "publickey": "028236ac8b31ecdb48af37b5a7ca10f01b53288ca68d17e5fa175a02d3705ee6ce",
                             "address_btc": "12Ve7TxcoJ4AGyx2mPUmC4URxj5QQnWkjh",
                             "address_ltc": "LLibNgGSsxJDXneBwXU4U5YCAwSgWVrooG",
                             "address_eth": "0xe18a9010D8B205eEbCC0448a7D02dAf239E86e72",
                             "privatekey": "60dfa17396b14cd679a52107226139bb5fab57c85470b570052d0bddc9f1155b",
                             "privatekey_wifltc": "T6JHagi57zwdg9CjSHw5htXp551NPtTqgY7iaVvTY9bc78dm7PYm",
                             "privatekey_wif": "KzU28wQticy2uJZrtezDVXzS8DN4KoSwsLDTihHuyBRSbF5c7LRB"},
                            {"encrypted_private_key_58": "PBnDMwjgM17DWxxVkqFA4rMWmZdL",
                             "passpoint1": "gdMXKvFbSWADynW1dR6urekQF5m5ADhtAbMu6nPwmgqL",
                             "security_code_58": "gaFMoSMp8qLyXZ",
                             "passpoint2": "ysFs7DFLCXSY2to5ikqLqX1cqqCazcnj5QMiWcZkMmKp",
                             "publickey": "02950fc531fd5c00a1f637acd9aa625e6340d1d26f7ef203aa8a4773dc6fd86a00",
                             "address_btc": "1B4W2A6twoM7H7yYktzFnKgiZziXMmp4kx",
                             "address_ltc": "LVHTHNQj2TbAXvfhw2yZ4LkUnD5oTka4i3",
                             "address_eth": "0xA4E2e082bC5D5b9c3e80ED91599185F4cBcFc27D",
                             "privatekey": "e95ec182bb9771e1239f3de34341f13c23b8af093471c860a0e5f8d0611f4376",
                             "privatekey_wifltc": "TAscovMwG1HieKzCfFpSfyowk6rAFnHCfgvgpsPKHaQAEU3qJV8x",
                             "privatekey_wif": "L53MNB4krdK7sVML7csaTdGZoFCrBhGJrV2Ry4kmicDziaXf4hEt",},
                            {"encrypted_private_key_58": "ndgnrDoazcnBcePcm51ufc2VdvpU",
                             "passpoint1": "gr6PhVsG6NJxW3PqVvqUR18GaiiNfMsVBgUftcz2SmL1",
                             "security_code_58": "g42szVUceSZdg3",
                             "passpoint2": "278VnEdAiUHqtrg5ixUB1La9uVMg3Xi9X4ZWtEmASfq9K",
                             "publickey": "020f6b14b6155e882bdef59d7730212bd4cc24661250d89fcec0b4b28f24156a82",
                             "address_btc": "1DZVkJ2QiRZkqdDwBsCG8cMFPtT3wk4Yp1",
                             "address_ltc": "LXnT1WLEo5op6Rv6N1BZQdR1c6pL4PNsjn",
                             "address_eth": "0xD55B7c7363F359822538A70C568a75E3a6981662",
                             "privatekey": "864f14c02deebb1ea362d6fca0d9d052e42cd9156ced3898d94d48c06e0d1665",
                             "privatekey_wifltc": "T7Z4D4cygqN1nYXbtHXDvGKf4RcBXXMciqRE71oeKrZ4ipy2UNPP",
                             "privatekey_wif": "L1inmKKoHTPR1htjLeaMhunH7ZxsTSLiudWyFDB6ktNuCwV1xtf7",},
                            {"encrypted_private_key_58": "w1hdoDeaqvX8kRBTSWoWBgyXkYs4",
                             "passpoint1": "27U3fsbY5BR6uugoVRmKmAsGXdW5DgKd5rDNBLMpRmYZB",
                             "security_code_58": "qNd6RJkjTb1UhT",
                             "passpoint2": "dPYrLa6v3drSFCknPicDrj3rEGDozjqSZTnNZdw92GGB",
                             "publickey": "02dd638ef5554996b3d64700c8ef8cb30c11fe726830c8a3b2c52b6318788f855b",
                             "address_btc": "12yG1SYQhpVrM6SFq2SBnueXpQVVHTVbwg",
                             "address_ltc": "LMCDGerEnUjubu8R1ARV4viJ2crmUvrsQE",
                             "address_eth": "0x135e23b424410487eA0d7eFEf799fA174B3c52c8",
                             "privatekey": "0f4d8e77fbfaf37a4d7bfc3e6e272f628ddb0280338d85f9a124e4f6a820ed47",
                             "privatekey_wifltc": "T3Zix8NentP6v1PxuybuQq9nmst8w8m5gmEyd8W3MJcQbEprD87m",
                             "privatekey_wif": "KwjTWP5UPWQW9Am6NLf3CUcQq2Eps3kBsZLimKsVnLSF5MMdH7Y8",}
                            ]

class TestCrypto(asynctest.TestCase):


    async def test_passpointGeneration(self):
        for v in test_vector:
            passpoint = generate_passpoint_fromsecret(v["encrypted_private_key_58"])
            self.assertEqual(passpoint, v["passpoint1"])
            passpoint = generate_passpoint_fromsecret(v["security_code_58"])
            self.assertEqual(passpoint, v["passpoint2"])
            
    async def test_computePublicKeyFromPasspoints(self):
        for v in test_vector:
            publickey = compute_public_key(v["passpoint1"], v["passpoint2"])
            self.assertEqual(publickey, bytes.fromhex(v["publickey"]))
            
            
    async def test_publickeyGenerationBTC(self):
        for v in test_vector:
            address = generate_address_frompublickey_btc(bytes.fromhex(v["publickey"]))
            self.assertEqual(address, v["address_btc"])
            
    async def test_publickeyGenerationLTC(self):
        for v in test_vector:
            address = generate_address_frompublickey_ltc(bytes.fromhex(v["publickey"]))
            self.assertEqual(address, v["address_ltc"])
    async def test_publickeyGenerationETH(self):
        for v in test_vector:
            address = generate_address_frompublickey_eth(bytes.fromhex(v["publickey"]))
            self.assertEqual(address, v["address_eth"])
    async def test_computePrivateKeyFromSecrets(self):
        for v in test_vector:
            privatekey, publickey = compute_privatekey(v["encrypted_private_key_58"], v["security_code_58"])
            self.assertEqual(privatekey, bytes.fromhex(v["privatekey"]))
            self.assertEqual(publickey, bytes.fromhex(v["publickey"]))

    async def test_computePrivatekeyWIF(self):
        for v in test_vector:
            privatekey_wif, address_btc, publickey = compute_privatekeywif_and_address_btc(v["encrypted_private_key_58"], v["security_code_58"])
            self.assertEqual(address_btc, v["address_btc"])
            self.assertEqual(privatekey_wif, v["privatekey_wif"])
            
    async def test_computePrivatekeyWIFLTC(self):
        for v in test_vector:
            privatekey_wif, address_ltc, publickey = compute_privatekeywif_and_address_ltc(v["encrypted_private_key_58"], v["security_code_58"])
            self.assertEqual(address_ltc, v["address_ltc"])
            self.assertEqual(privatekey_wif, v["privatekey_wifltc"])
            
    async def test_computePrivatekeyWIFFromPrivateKey(self):
        for v in test_vector:
            privatekey_wif = convertprivatekeytowif(bytes.fromhex(v["privatekey"]))
            self.assertEqual(privatekey_wif, v["privatekey_wif"])
    

if __name__ == '__main__':
    unittest.main()


