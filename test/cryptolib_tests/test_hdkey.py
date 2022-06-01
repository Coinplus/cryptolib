import unittest
from cryptolib.hdkey import HDKey
from cryptolib.address.address import BitcoinAddress
from cryptolib.hex import hex2bytes, bytes2hex


class TestHDKey(unittest.TestCase):

    def setUp(self):
        pass

    def test_HDKey_FingerPrintOnTestVector1_IsCorrect(self):
        key = HDKey.from_seed(hex2bytes("000102030405060708090a0b0c0d0e0f"))

        fingerprint = bytes2hex(key.fingerprint())

        self.assertEqual(fingerprint, "3442193e")

    def test_HDKey_SerializedOnTestVector1_IsCorrect(self):
        key = HDKey.from_seed(hex2bytes("000102030405060708090a0b0c0d0e0f"))

        serialized = key.serialize()

        self.assertEqual(
            serialized,
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")

    def test_HDKey_PubKeyOfHDkeyOfVector1_IsCorrect(self):
        key = HDKey.from_seed(hex2bytes("000102030405060708090a0b0c0d0e0f"))

        pubkey = key.pubkey()

        self.assertEqual(bytes2hex(pubkey), "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")

    def test_HDKey_AddressOfHDkeyOfVector1_IsCorrect(self):
        key = HDKey.from_seed(hex2bytes("000102030405060708090a0b0c0d0e0f"))

        address = key.address()

        self.assertEqual(address, BitcoinAddress.from_base58addr("15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"))


    def test_HDKey_TestVector1_0H(self):
        key = HDKey.from_seed(hex2bytes("000102030405060708090a0b0c0d0e0f"))

        self.assertEqual(key.child(0, is_hardened=True).serialize(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
        self.assertEqual(key.child(0, is_hardened=True).hd_pubkey().serialize(),
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")

    def test_HDKey_TestVector1_0H_1(self):
        key = HDKey.from_seed(hex2bytes("000102030405060708090a0b0c0d0e0f"))

        self.assertEqual(key.child(0, is_hardened=True).child(1).serialize(),
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
        self.assertEqual(key.child(0, is_hardened=True).child(1).hd_pubkey().serialize(),
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")


    def test_HDKey_TestVector1_0H_1_2H(self):
        key = HDKey.from_seed(hex2bytes("000102030405060708090a0b0c0d0e0f"))

        self.assertEqual(key.child(0, is_hardened=True).child(1).child(2, is_hardened=True).serialize(),
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM")
        self.assertEqual(key.child(0, is_hardened=True).child(1).child(2, is_hardened=True).hd_pubkey().serialize(),
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")

    def test_HDKey_TestVector1_0H_1_2H_2(self):
        key = HDKey.from_seed(hex2bytes("000102030405060708090a0b0c0d0e0f"))

        self.assertEqual(key.child(0, is_hardened=True).child(1).child(2, is_hardened=True).child(2).serialize(),
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334")
        self.assertEqual(key.child(0, is_hardened=True).child(1).child(2, is_hardened=True).child(2).hd_pubkey().serialize(),
            "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")

    def test_HDKey_TestVector1_0H_1_2H_2_1000000000(self):
        key = HDKey.from_seed(hex2bytes("000102030405060708090a0b0c0d0e0f"))

        self.assertEqual(key.child(0, is_hardened=True).child(1).child(2, is_hardened=True).child(2).child(1000000000).serialize(),
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
        self.assertEqual(key.child(0, is_hardened=True).child(1).child(2, is_hardened=True).child(2).child(1000000000).hd_pubkey().serialize(),
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")


    def test_HDKey_FingerPrintOnTestVector2_IsCorrect(self):
        key = HDKey.from_seed(hex2bytes(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))

        fingerprint = bytes2hex(key.fingerprint())

        self.assertEqual(fingerprint, "bd16bee5")

    def test_HDKey_Child0AddressSerializedOnTestVector2_IsCorrect(self):
        key = HDKey.from_seed(hex2bytes(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))

        address = key.child(0).address()

        self.assertEqual(address, BitcoinAddress.from_base58addr("19EuDJdgfRkwCmRzbzVBHZWQG9QNWhftbZ"))


    def test_HDKey_TestVector2_m(self):
        key = HDKey.from_seed(hex2bytes(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))

        self.assertEqual(key.serialize(),
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")
        self.assertEqual(key.hd_pubkey().serialize(),
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")

    def test_HDKey_TestVector2_m_0(self):
        key = HDKey.from_seed(hex2bytes(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))

        self.assertEqual(key.child(0).serialize(),
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt")
        self.assertEqual(key.child(0).hd_pubkey().serialize(),
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")

    def test_HDKey_TestVector2_m_0_2147483647H(self):
        key = HDKey.from_seed(hex2bytes(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))

        self.assertEqual(key.child(0).child(2147483647, is_hardened=True).serialize(),
            "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9")
        self.assertEqual(key.child(0).child(2147483647, is_hardened=True).hd_pubkey().serialize(),
            "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a")

    def test_HDKey_TestVector2_m_0_2147483647H_1(self):
        key = HDKey.from_seed(hex2bytes(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))

        self.assertEqual(key.child(0).child(2147483647, is_hardened=True).child(1).serialize(),
            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef")
        self.assertEqual(key.child(0).child(2147483647, is_hardened=True).child(1).hd_pubkey().serialize(),
            "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon")

    def test_HDKey_TestVector2_m_0_2147483647H_1_2147483646H(self):
        key = HDKey.from_seed(hex2bytes(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))

        self.assertEqual(key.child(0).child(2147483647, is_hardened=True).child(1).child(2147483646, is_hardened=True).serialize(),
            "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc")
        self.assertEqual(key.child(0).child(2147483647, is_hardened=True).child(1).child(2147483646, is_hardened=True).hd_pubkey().serialize(),
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL")

    def test_HDKey_TestVector2_m_0_2147483647H_1_2147483646H_2(self):
        key = HDKey.from_seed(hex2bytes(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))

        self.assertEqual(key.child(0).child(2147483647, is_hardened=True).child(1).child(2147483646, is_hardened=True).child(2).serialize(),
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j")
        self.assertEqual(key.child(0).child(2147483647, is_hardened=True).child(1).child(2147483646, is_hardened=True).child(2).hd_pubkey().serialize(),
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")


    def test_HDKeyTestVector3_m(self):
        key = HDKey.from_seed(hex2bytes(
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"))

        self.assertEqual(key.serialize(),
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")
        self.assertEqual(key.hd_pubkey().serialize(),
            "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")

    def test_HDKeyTestVector3_m_0h(self):
        key = HDKey.from_seed(hex2bytes(
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"))

        self.assertEqual(key.child(0, is_hardened=True).serialize(),
            "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L")
        self.assertEqual(key.child(0, is_hardened=True).hd_pubkey().serialize(),
            "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y")


    def test_HDKeyTest_addresses(self):
        """Test from BIP39 mnemonic 'fruit wave dwarf banana earth journey tattoo true farm silk olive fence'"""
        key = HDKey.from_seed(hex2bytes(
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"))

        self.assertEqual(key.serialize(),
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")
        self.assertEqual(key.child(44, True).child(0, True).child(0, True).child(0).serialize(),
            "xprv9zpPKuR9VgJTuXbdUDaRL2yQj9LbvzYuGW1P1t2mFQV6AZUJ8cJmimBSLSxBYuLuBkmuvngszpiEF7ZQbyFDLDrvBC7SDY8TUeKwBXG3FEW")
        self.assertEqual(key.child(44, True).child(0, True).child(0, True).child(0).child(0).address().to_base58addr(),
                         "17rxURoF96VhmkcEGCj5LNQkmN9HVhWb7F")
        self.assertEqual(key.child(44, True).child(0, True).child(0, True).child(0).child(1).address().to_base58addr(),
                         "1HP21Jkjvukstc2mNe4ZXGZJoDU6dzDVZo")
        self.assertEqual(key.child(44, True).child(0, True).child(0, True).child(0).child(2).address().to_base58addr(),
                         "14xg2vKsVdf1mHiPRFTwSiXCjTFe2foVLm")
        


    def test_HDKeyTest_DeriveChildPublicFromMasterPublic(self):
        # verified using electrum
        key = HDKey.deserialize("xpub661MyMwAqRbcEqF2ycCvWhtSfxhFZrLu4roRL61XiPzoET4jexyaSs3G86qupAj3kqcwY9XeiokwTq7S32SkESWqMidF5JjCWKxVfcM4wR8")
        
        self.assertEqual(bytes2hex(key.child(0).child(0).pubkey()),
            "023c84d084c5f8754a01d2489017d9ec043376f251e35d701d55a32b5bd9c988a5")
        self.assertEqual(bytes2hex(key.child(0).child(1).pubkey()),
            "03de70454dc903ce9fe62ccb3a55904bfbf3639a0f7555666c8285bef427c4a8b5")
        self.assertEqual(bytes2hex(key.child(0).child(2).pubkey()),
            "02c1cdb4fa6425a65dc81f6b4e0a03a01e48309df3c931e4843d2f4f4fbf6c2df9")


if __name__ == "__main__":
    unittest.main()
