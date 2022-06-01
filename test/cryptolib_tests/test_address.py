from cryptolib.address.address import BitcoinAddress, InvalidBitcoinAddress, BitcoinCashAddress, InvalidBitcoinCashAddress, LitecoinAddress, \
    InvalidLitecoinAddress
import unittest
from cryptolib.address.address_version import AddressVersion,\
    PUBKEY_ADDRESS_TEST, SCRIPT_ADDRESS_TEST, PUBKEY_ADDRESS_MAIN,\
    SCRIPT_ADDRESS_MAIN, BitcoinCashAddressVersion, BITCOINCASH_P2KH, BITCOINCASH_SIZEHASH, LitecoinAddressVersion, LITECOIN_PUBKEY_ADDRESS_MAIN,\
    LITECOIN_PUBKEY_ADDRESS_TEST, LITECOIN_SCRIPT_ADDRESS_MAIN
from cryptolib.address.runmode import TESTNET, MAIN, BITCOINCASH_MAIN
from cryptolib.hex import bytes2hex, hex2bytes
from cryptolib import hash160


class TestBitcoinAddress(unittest.TestCase):

    def setUp(self):
        pass

    def test_address_from_public_key(self):
        """
        public: 023053536687205cbf57a25386ac466c7f85105032ced1ae9c54486a83c6dd3bab
        private: 049db42589b263e8700eb747a402b74604aae54ebc04f1cbe9a1cf584683f100
        """
        addr1 = BitcoinAddress.from_publickey(
            hex2bytes("023053536687205cbf57a25386ac466c7f85105032ced1ae9c54486a83c6dd3bab"), MAIN)
        self.assertEqual(addr1.to_base58addr(), "171waY81rzeFaBYhsiKibhBW5WAG8X7DLk")

    def test_address_from_bytestring(self):
        addr1 = BitcoinAddress.from_bytestring(hex2bytes("0041fe507633463c246ec91502c2d67e8b3d81618e"))
        self.assertEqual(addr1.to_base58addr(), "171waY81rzeFaBYhsiKibhBW5WAG8X7DLk")
        with self.assertRaises(InvalidBitcoinAddress):
            # not 21 characters
            addr2 = BitcoinAddress.from_bytestring(hex2bytes("0041fe507633463c246ec91502c2d67e8b3d81618e61"))

    def test_address_from_base58addr(self):
        # TESTNET
        addr1 = BitcoinAddress.from_base58addr("n4MsBRWD7VxKGsqYRSLaFZC6hQrsrKLaZo")
        self.assertEqual(bytes2hex(addr1.get_hash160()), 'fa92e151722c0ebca07059a505252218b4c50e7a')
        self.assertEqual(addr1.get_addr_version(), AddressVersion(PUBKEY_ADDRESS_TEST))
        # TESTNET script address
        addr2 = BitcoinAddress.from_base58addr("2NG68seqhTqLnniguW6efUDKyCHm4LYEFRa")
        self.assertEqual(bytes2hex(addr2.get_hash160()), 'fa92e151722c0ebca07059a505252218b4c50e7a')
        self.assertEqual(addr2.get_addr_version(), AddressVersion(SCRIPT_ADDRESS_TEST))
        # MAIN
        addr2 = BitcoinAddress.from_base58addr("1PqutNREJUX4VmMvhsNCRdymqRGAzifdsx")
        self.assertEqual(bytes2hex(addr2.get_hash160()), 'fa92e151722c0ebca07059a505252218b4c50e7a')
        self.assertEqual(addr2.get_addr_version(), AddressVersion(PUBKEY_ADDRESS_MAIN))
        # MAIN Script address
        addr2 = BitcoinAddress.from_base58addr("3QXvouufrNqSaw4Mpy2nrGLhywYtXx6wsi")
        self.assertEqual(bytes2hex(addr2.get_hash160()), 'fa92e151722c0ebca07059a505252218b4c50e7a')
        self.assertEqual(addr2.get_addr_version(), AddressVersion(SCRIPT_ADDRESS_MAIN))
        # TODO: MAIN with extra 1s

    def test_address_to_base58addr(self):
        self.assertEqual(BitcoinAddress(hex2bytes("b0600c55b16851c4f9d0e2c82fa161ac8190e04c"),
                                         AddressVersion(PUBKEY_ADDRESS_MAIN)).to_base58addr(),
                          "1H5azJoKoYd92DxjXX7k7gejpbLVMAczAi")

    def test_address_to_bytestring(self):
        self.assertEqual(BitcoinAddress(hex2bytes("b0600c55b16851c4f9d0e2c82fa161ac8190e04c"),
                                         AddressVersion(PUBKEY_ADDRESS_MAIN)).to_bytestring(),
                          hex2bytes("00b0600c55b16851c4f9d0e2c82fa161ac8190e04c"))

    def test_address_to_hexstring(self):
        self.assertEqual(BitcoinAddress(hex2bytes("b0600c55b16851c4f9d0e2c82fa161ac8190e04c"),
                                         AddressVersion(PUBKEY_ADDRESS_MAIN)).to_hexstring(),
                          "00b0600c55b16851c4f9d0e2c82fa161ac8190e04c")

    def test_address_get_hash160(self):
        self.assertEqual(BitcoinAddress(hex2bytes("b0600c55b16851c4f9d0e2c82fa161ac8190e04c"),
                                         AddressVersion(PUBKEY_ADDRESS_MAIN)).get_hash160(),
                          hex2bytes("b0600c55b16851c4f9d0e2c82fa161ac8190e04c"))

    def test_address_get_addr_version(self):
        self.assertEqual(BitcoinAddress(hex2bytes("b0600c55b16851c4f9d0e2c82fa161ac8190e04c"),
                                         AddressVersion(PUBKEY_ADDRESS_TEST)).get_addr_version(),
                          AddressVersion(PUBKEY_ADDRESS_TEST))

    def test_address_is_valid(self):
        assert BitcoinAddress.is_valid("2NG68seqhTqLnniguW6efUDKyCHm4LYEFRa", TESTNET)  # script addr
        assert BitcoinAddress.is_valid("n4MsBRWD7VxKGsqYRSLaFZC6hQrsrKLaZo", TESTNET)
        assert BitcoinAddress.is_valid("112z9tWej11X94khKKzofFgWbdhiXLeHPD", MAIN)
        assert BitcoinAddress.is_valid("3QXvouufrNqSaw4Mpy2nrGLhywYtXx6wsi", MAIN)  # script addr
        # null string
        assert not BitcoinAddress.is_valid("", TESTNET)
        # checksum error
        assert not BitcoinAddress.is_valid("n4NsBRWD7VxKGsqYRSLaFZC6hQrsrKLaZo", TESTNET)
        # invalid base64char l
        assert not BitcoinAddress.is_valid("n4lsBRWD7VxKGsqYRSLaFZC6hQrsrKLaZo", TESTNET)
        # special case for MAIN, starting with multiple 1s
        assert BitcoinAddress.is_valid("112z9tWej11X94khKKzofFgWbdhiXLeHPD", MAIN)
        assert BitcoinAddress.is_valid("1111MJe7b4ZnktoPZabb6DLAKfac8tvx", MAIN)
        # address with 27 chars
        assert BitcoinAddress.is_valid("1111111111111111111114oLvT2", MAIN)

        # Some common validators errorneously consider these addresses as valid,
        # but they are not valid in bitcoind due to an incorrect number of leading zeros in base58
        # (tested with the "validateaddress" rpc command)
        assert not BitcoinAddress.is_valid("11111MJe7b4ZnktoPZabb6DLAKfac8tvx", MAIN)
        assert not BitcoinAddress.is_valid("111MJe7b4ZnktoPZabb6DLAKfac8tvx", MAIN)


class TestBitcoinCashAddress(unittest.TestCase):

    def setUp(self):
        pass

    def test_address_from_public_key(self):
        """
        public: 03C199B4A781EB500C243A8677C557E8B61C8DD45F6FBF72EB7524E1B2829FA5FA
        private: F0028C95232C8E1DC8844793C3B23B051D9542B3A6F7C9C3B98169F894877CBB
        """
        addr1 = BitcoinCashAddress.from_publickey(
            hex2bytes("03C199B4A781EB500C243A8677C557E8B61C8DD45F6FBF72EB7524E1B2829FA5FA"), BITCOINCASH_MAIN)
        self.assertEqual(addr1.to_base32addr(), "bitcoincash:qq8a07g99pt4plk5tm524rguwap0hamg8yvu8rj622")

    def test_address_from_bytestring(self):
        addr1 = BitcoinCashAddress.from_bytestring( b"bitcoincash",hex2bytes("000FD7F905285750FED45EE8AA8D1C7742FBF76839"))
        self.assertEqual(addr1.to_base32addr(),  "bitcoincash:qq8a07g99pt4plk5tm524rguwap0hamg8yvu8rj622")


    def test_address_from_base32addr(self):
        # TESTNET
        addr1 = BitcoinCashAddress.from_base32addr(b"bitcoincash:qq8a07g99pt4plk5tm524rguwap0hamg8yvu8rj622")
        self.assertEqual(bytes2hex(addr1.hash).upper(), '0FD7F905285750FED45EE8AA8D1C7742FBF76839')
        version = BitcoinCashAddressVersion(BITCOINCASH_MAIN, BITCOINCASH_P2KH + BITCOINCASH_SIZEHASH[160] )
        self.assertEqual(addr1.address_version, version) 
        
        """KzwxfUBPxa5s1bodhEGAXLtBdffrmpBtAhNySh9gVqqVWQf2TEyg"""
        addr1 = BitcoinCashAddress.from_base32addr(b"bitcoincash:qz538cax852nztdp3h86xl6qs7mn6u2nnczggls825")
        self.assertEqual(addr1.hash, hash160.hash_160( hex2bytes('03AFDC4285F774AA6D7610C26A7761AEE2EFD5A55AFDD08065EBAC5BDDF84D1732')))
        version = BitcoinCashAddressVersion(BITCOINCASH_MAIN, BITCOINCASH_P2KH + BITCOINCASH_SIZEHASH[160] )
        self.assertEqual(addr1.address_version, version) 

        """L5QySAFzveFbriDnR8QNGCeBtzvvtANpiGbXALCzEeHWFe1xEU73"""
        addr1 = BitcoinCashAddress.from_base32addr(b"bitcoincash:qpps3g05hygdsnchufvkyzt4pvsh3g5zsyrk6wn4ec")
        self.assertEqual(addr1.hash, hash160.hash_160( hex2bytes('02F328BCC2AA70A883E2BE2C79438A41ED088F618011086A42064A9A30AB8B6699')))
        version = BitcoinCashAddressVersion(BITCOINCASH_MAIN, BITCOINCASH_P2KH + BITCOINCASH_SIZEHASH[160] )
        self.assertEqual(addr1.address_version, version) 

        """L1TCTQgZjDuHzirFRbxEqmfwF2GYQZEpZxSi8ndwDEGJgFDnbDRb"""
        addr1 = BitcoinCashAddress.from_base32addr(b"bitcoincash:qzss7lzh4gttktz7w9uvrx8sghd0hemh6yhjuqlglx")
        self.assertEqual(addr1.hash, hash160.hash_160( hex2bytes('0377C4BBF557D04AD51B527A715990995B581AC6937369340662F3FDAB941A95EF')))
        version = BitcoinCashAddressVersion(BITCOINCASH_MAIN, BITCOINCASH_P2KH + BITCOINCASH_SIZEHASH[160] )
        self.assertEqual(addr1.address_version, version) 
        
        """KxXsVTuGCZXdHb72rVvsfqQkNtsxAYXpW59m7bt8yesrUHnDJtFW"""
        addr1 = BitcoinCashAddress.from_base32addr(b"bitcoincash:qqlqvuhsvgea4sf5ml9cchwpswz80ngyqg9qywjkjx")
        self.assertEqual(addr1.hash, hash160.hash_160( hex2bytes('03A2558B1ED26BF00274CBB60B9D677DEB6AABA7D161BC07807BB9E586FD4E9EF3')))
        version = BitcoinCashAddressVersion(BITCOINCASH_MAIN, BITCOINCASH_P2KH + BITCOINCASH_SIZEHASH[160] )
        self.assertEqual(addr1.address_version, version) 

        """L4XZfT3jELHTfEBbsjZREVAX8BydoBMzuAt9FbQ7mpHXscQxGeFq"""
        addr1 = BitcoinCashAddress.from_base32addr(b"bitcoincash:qramwzuc2fa4te3fp3ue3vrsxamckc9kk57jl0mfza")
        self.assertEqual(addr1.hash, hash160.hash_160( hex2bytes('0289BBCDAAA8D1B07F48C10F737FF6D1218FFDF25032FE14426C5AF5CB1E73BBB4')))
        version = BitcoinCashAddressVersion(BITCOINCASH_MAIN, BITCOINCASH_P2KH + BITCOINCASH_SIZEHASH[160] )
        self.assertEqual(addr1.address_version, version) 


    
    def test_address_is_valid(self):
        assert BitcoinCashAddress.is_valid(b"bitcoincash:qq8a07g99pt4plk5tm524rguwap0hamg8yvu8rj622", BITCOINCASH_MAIN)  # script addr
        assert not BitcoinCashAddress.is_valid(b"bitcoincash:qq8a07g99pt4plk5tm524rguwap0hamg8yvu8rj622", TESTNET)


class TestLitecoinAddress(unittest.TestCase):

    def setUp(self):
        pass

    def test_address_from_public_key(self):
        """
        public: LfqRkuP8JR2LaGUJbcY4jzEHrM7GtAmhb2
        private: T5unZhrNdbhSZ5WGzVgwqMtPwYhKswsuC5gUtVzFcxPW9hLjqQGW
        private hex: 554C6E1E330B8152485F6FDC41C1C3BDD7C2B3FE29BF14D662785CACF0ED3A7E
        pub hex: 03C2453D9DA2E44FF2070155F7CF8955F21F0AD08F36647D047ACD51835236A3C8
        rip
        """
        addr1 = LitecoinAddress.from_publickey(
            hex2bytes("03C2453D9DA2E44FF2070155F7CF8955F21F0AD08F36647D047ACD51835236A3C8"), MAIN)
        self.assertEqual(addr1.to_base58addr(), "LfqRkuP8JR2LaGUJbcY4jzEHrM7GtAmhb2")


        addr1 = LitecoinAddress.from_publickey(
            hex2bytes("03294DFA35866E7FB89C947A15C5A74BB1C609B1774B19AE12692F415F8D539E55"), MAIN)
        self.assertEqual(addr1.to_base58addr(), "LQpceqvuoQaDuEjjwuZrYJvuZekKpJMEVC")

        addr1 = LitecoinAddress.from_publickey(
            hex2bytes("02E797145CFF7C6DDE8D3F4F088C88FB1D1EB9E2B414F2EF252281DF947C67A664"), MAIN)
        self.assertEqual(addr1.to_base58addr(), "LKbM1vThSiWfqsaXTks6sMkUp75Vpm5ydV")

        addr1 = LitecoinAddress.from_publickey(
            hex2bytes("024D4F9AB2E8396594A6921E21DFF7D06954EA3541D6E8588EB85AE847A95260A0"), MAIN)
        self.assertEqual(addr1.to_base58addr(), "LXu2x2d6fx2fCgNCBb9ePcZHTCrLFahF2b")

        addr1 = LitecoinAddress.from_publickey(
            hex2bytes("02FB21A3617F65AB298684AF35D0719F3FC0A31A0A633D41182F8FDCA0F00F4F79"), MAIN)
        self.assertEqual(addr1.to_base58addr(), "LYi53tsvk3D2ABn6HqR7akNi5LwgP1decQ")

        addr1 = LitecoinAddress.from_publickey(
            hex2bytes("02168522B7724726E1ACBC6F60B747EE24825895CB31ED50DD59F56C83A871E11F"), MAIN)
        self.assertEqual(addr1.to_base58addr(), "LZU461khkTXzx1Y2DEayJNeMoGJxRXtJb7")

    def test_address_from_bytestring(self):
        addr1 = LitecoinAddress.from_bytestring(hex2bytes("30E21806967F66533003D3341B45847B681D9DD983"))
        self.assertEqual(addr1.to_base58addr(), "LfqRkuP8JR2LaGUJbcY4jzEHrM7GtAmhb2")
        with self.assertRaises(InvalidLitecoinAddress):
            # not 21 characters
            addr2 = LitecoinAddress.from_bytestring(hex2bytes("30E21806967F66533003D3341B45847B681D9DD98454"))


    def test_address_from_base58addr(self):
        # TESTNET
        addr1 = LitecoinAddress.from_base58addr("LfqRkuP8JR2LaGUJbcY4jzEHrM7GtAmhb2")
        self.assertEqual(bytes2hex(addr1.hash160).upper(), 'E21806967F66533003D3341B45847B681D9DD983')
        version = LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_MAIN )
        self.assertEqual(addr1.address_version, version) 


        '''T9ivk2ytWsa2ngjugKSpPYCtgr7oBQGHsTUE8oUwEi24UYMeaHbQ'''
        addr1 = LitecoinAddress.from_base58addr("LQpceqvuoQaDuEjjwuZrYJvuZekKpJMEVC")
        self.assertEqual(addr1.hash160, hash160.hash_160( hex2bytes("03294DFA35866E7FB89C947A15C5A74BB1C609B1774B19AE12692F415F8D539E55")))
        version = LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_MAIN )
        self.assertEqual(addr1.address_version, version) 

        """T9KJW9Ua2ozqC8jRBwDkKFwJf8TrzJPLQ5fyKZ6YQEsrpigas2q8"""
        addr1 = LitecoinAddress.from_base58addr("LKbM1vThSiWfqsaXTks6sMkUp75Vpm5ydV")
        self.assertEqual(addr1.hash160, hash160.hash_160( hex2bytes("02E797145CFF7C6DDE8D3F4F088C88FB1D1EB9E2B414F2EF252281DF947C67A664")))
        version = LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_MAIN )
        self.assertEqual(addr1.address_version, version) 


        """T7XBCzsp1R2ADZSzDb44oCpuN3PTnq8DwkAUVt6aC12YyQUMVQWE"""
        addr1 = LitecoinAddress.from_base58addr("LXu2x2d6fx2fCgNCBb9ePcZHTCrLFahF2b")
        self.assertEqual(addr1.hash160, hash160.hash_160( hex2bytes("024D4F9AB2E8396594A6921E21DFF7D06954EA3541D6E8588EB85AE847A95260A0")))
        version = LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_MAIN )
        self.assertEqual(addr1.address_version, version) 


        """T3ti3Q1WpxAy8SEuSANvJf5XvFabcPCsefmECbGiPznG7auNvVr4"""
        addr1 = LitecoinAddress.from_base58addr("LYi53tsvk3D2ABn6HqR7akNi5LwgP1decQ")
        self.assertEqual(addr1.hash160, hash160.hash_160( hex2bytes("02FB21A3617F65AB298684AF35D0719F3FC0A31A0A633D41182F8FDCA0F00F4F79")))
        version = LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_MAIN )
        self.assertEqual(addr1.address_version, version) 


        """T9QLcNteVfx5GzjczUQbrkxYGfjypwVe3ZLXp62Kw5NR23eKtZsT"""
        addr1 = LitecoinAddress.from_base58addr("LZU461khkTXzx1Y2DEayJNeMoGJxRXtJb7")
        self.assertEqual(addr1.hash160, hash160.hash_160( hex2bytes("02168522B7724726E1ACBC6F60B747EE24825895CB31ED50DD59F56C83A871E11F")))
        version = LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_MAIN )
        self.assertEqual(addr1.address_version, version) 


        
    def test_address_to_base58addr(self):
        self.assertEqual(LitecoinAddress(hex2bytes("E21806967F66533003D3341B45847B681D9DD983"),
                                         LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_MAIN)).to_base58addr(),
                          "LfqRkuP8JR2LaGUJbcY4jzEHrM7GtAmhb2")







    def test_address_to_bytestring(self):
        self.assertEqual(LitecoinAddress(hex2bytes("E21806967F66533003D3341B45847B681D9DD983"),
                                         LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_MAIN)).to_bytestring(),
                          hex2bytes("30E21806967F66533003D3341B45847B681D9DD983"))

    def test_address_to_hexstring(self):
        self.assertEqual(LitecoinAddress(hex2bytes("E21806967F66533003D3341B45847B681D9DD983"),
                                         LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_MAIN)).to_hexstring(),
                          "30E21806967F66533003D3341B45847B681D9DD983".lower())

    def test_address_get_hash160(self):
        self.assertEqual(LitecoinAddress(hex2bytes("E21806967F66533003D3341B45847B681D9DD983"),
                                         LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_MAIN)).get_hash160(),
                          hex2bytes("E21806967F66533003D3341B45847B681D9DD983"))

    def test_address_get_addr_version(self):
        self.assertEqual(LitecoinAddress(hex2bytes("E21806967F66533003D3341B45847B681D9DD983"),
                                         LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_MAIN)).get_addr_version(),
                          LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_MAIN))

        self.assertEqual(LitecoinAddress(hex2bytes("E21806967F66533003D3341B45847B681D9DD983"),
                                         LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_TEST)).get_addr_version(),
                          LitecoinAddressVersion(LITECOIN_PUBKEY_ADDRESS_TEST))

    def test_address_is_valid(self):
        assert LitecoinAddress.is_valid("La475NX5qRbJJFjHeUweVmAj5hnrYhaoxC", MAIN)  # script addr
        assert LitecoinAddress.is_valid("33u8VTwJvtdRNwgrqzBNQCJhV1UEqzmDNj", MAIN)
        assert LitecoinAddress.is_valid("LSPsovnzCmejteq7brdRdJ3w1drFFjFWrd", MAIN)
        assert LitecoinAddress.is_valid("3EAsnwPz997iugmmE9xwZX2PDWa7K8uS61", MAIN)  # script addr
        # null string
        assert not LitecoinAddress.is_valid("", MAIN)
        assert not LitecoinAddress.is_valid("", TESTNET)
        # checksum error
        assert not LitecoinAddress.is_valid("n4NsBRWD7VxKGsqYRSLaFZC6hQrsrKLaZo", TESTNET)
        # invalid base64char l
        assert not LitecoinAddress.is_valid("n4lsBRWD7VxKGsqYRSLaFZC6hQrsrKLaZo", TESTNET)


if __name__ == '__main__':
    unittest.main()
