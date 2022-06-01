from cryptolib.address.runmode import is_main, is_main_cash, BITCOINCASH_MAIN, BITCOINCASH_TEST, BITCOINCASH_REG

PUBKEY_ADDRESS_MAIN = 0
SCRIPT_ADDRESS_MAIN = 5
PUBKEY_ADDRESS_TEST = 111
SCRIPT_ADDRESS_TEST = 196

ADDRESS_TYPES = [PUBKEY_ADDRESS_MAIN, SCRIPT_ADDRESS_MAIN, PUBKEY_ADDRESS_TEST, SCRIPT_ADDRESS_TEST]
ADDRESS_TYPE_NAMES = {PUBKEY_ADDRESS_MAIN: "MAIN/Addr",
                      SCRIPT_ADDRESS_MAIN: "MAIN/Script",
                      PUBKEY_ADDRESS_TEST: "TEST/Addr",
                      SCRIPT_ADDRESS_TEST: "TEST/Script"}

LITECOIN_PUBKEY_ADDRESS_MAIN = 48
LITECOIN_SCRIPT_ADDRESS_MAIN = 5
LITECOIN_SCRIPT2_ADDRESS_MAIN = 50
LITECOIN_PUBKEY_ADDRESS_TEST = 111
LITECOIN_SCRIPT_ADDRESS_TEST = 196


LITECOIN_ADDRESS_TYPES = [LITECOIN_PUBKEY_ADDRESS_MAIN, LITECOIN_SCRIPT_ADDRESS_MAIN, LITECOIN_SCRIPT2_ADDRESS_MAIN, LITECOIN_PUBKEY_ADDRESS_TEST, LITECOIN_SCRIPT_ADDRESS_TEST]
LITECOIN_ADDRESS_TYPE_NAMES = {LITECOIN_PUBKEY_ADDRESS_MAIN: "MAIN/Addr",
                      LITECOIN_SCRIPT_ADDRESS_MAIN: "MAIN/Script",
                      LITECOIN_SCRIPT2_ADDRESS_MAIN: "MAIN/Script",
                      LITECOIN_PUBKEY_ADDRESS_TEST: "TEST/Addr",
                      LITECOIN_SCRIPT_ADDRESS_TEST: "TEST/Script"}

BITCOINCASH_P2KH = 0 << 3
BITCOINCASH_P2SH = 1 << 3 


BITCOINCASH_ADDRESS_TYPE_NAMES = {(BITCOINCASH_MAIN,BITCOINCASH_P2SH): "MAIN/Script",
                      (BITCOINCASH_MAIN,BITCOINCASH_P2KH): "MAIN/Addr",
                      (BITCOINCASH_TEST,BITCOINCASH_P2SH): "TEST/Script",
                      (BITCOINCASH_TEST,BITCOINCASH_P2KH): "TEST/Addr"}

BITCOINCASH_SIZEHASH_rev = {0: 160, 1: 198, 2: 224, 3:256, 4: 320, 5: 384, 6:448, 7:512 }
BITCOINCASH_SIZEHASH = {160: 0, 192: 1, 224: 2, 256:3, 320: 4, 384: 5, 448: 6, 512: 7}

class AddressVersion():

    def __init__(self, value):
        self.value = value

    @staticmethod
    def from_byte(value):
        return AddressVersion(value)

    def to_byte(self):
        return self.value

    def to_bytes(self):
        return bytes([self.value])

    def to_char(self):
        return chr(self.value)

    def is_main(self):
        return (self.value == PUBKEY_ADDRESS_MAIN or self.value == SCRIPT_ADDRESS_MAIN)

    def is_script_address(self):
        return (self.value == SCRIPT_ADDRESS_MAIN or self.value == SCRIPT_ADDRESS_TEST)

    @staticmethod
    def from_parameters(is_main, is_script):
        PARAMS = {(True, True): SCRIPT_ADDRESS_MAIN,
                  (True, False): PUBKEY_ADDRESS_MAIN,
                  (False, True): SCRIPT_ADDRESS_TEST,
                  (False, False): PUBKEY_ADDRESS_TEST}
        return AddressVersion(PARAMS[(is_main, is_script)])

    @staticmethod
    def from_runmode(runmode, is_script=False):
        return AddressVersion.from_parameters(is_main(runmode), is_script)

    def __eq__(self, other):
        return self.value == other.value

    def __hash__(self):
        return hash(self.value)

    def __str__(self):
        return ADDRESS_TYPE_NAMES[self.value]

    def is_valid_on(self, runmode):
        if is_main(runmode):
            return self.is_main()
        return not self.is_main()
    
class LitecoinAddressVersion(AddressVersion):
    @staticmethod
    def from_byte(value):
        return LitecoinAddressVersion(value)

    def is_main(self):
        return (self.value == LITECOIN_PUBKEY_ADDRESS_MAIN or self.value == LITECOIN_SCRIPT_ADDRESS_MAIN or self.value == LITECOIN_SCRIPT2_ADDRESS_MAIN)

    def is_script_address(self):
        return (self.value == LITECOIN_PUBKEY_ADDRESS_TEST or self.value == LITECOIN_SCRIPT_ADDRESS_TEST)

    @staticmethod
    def from_parameters(is_main, is_script):
        PARAMS = {(True, 1): LITECOIN_SCRIPT_ADDRESS_MAIN,
                  (True, 2): LITECOIN_SCRIPT2_ADDRESS_MAIN,
                  (True, 0): LITECOIN_PUBKEY_ADDRESS_MAIN,
                  (False, 1): LITECOIN_SCRIPT_ADDRESS_TEST,
                  (False, 0): LITECOIN_PUBKEY_ADDRESS_TEST}
        return LitecoinAddressVersion(PARAMS[(is_main, is_script)])

    @staticmethod
    def from_runmode(runmode, is_script=False):
        return LitecoinAddressVersion.from_parameters(is_main(runmode), is_script)

    def __str__(self):
        return LITECOIN_ADDRESS_TYPE_NAMES[self.value]

class BitcoinCashAddressVersion(AddressVersion):


    def __init__(self, prefix, value):
        self.prefix = prefix
        self.value = value

    @staticmethod
    def from_byte( prefix, value):
        return BitcoinCashAddressVersion(prefix, value)

    def is_main(self):
        return (self.prefix == BITCOINCASH_MAIN)

    def is_script_address(self):
        return (self.value & BITCOINCASH_P2SH)

    @staticmethod
    def from_parameters(is_main, is_script):
        PARAMS = {(True, True): (BITCOINCASH_MAIN, BITCOINCASH_P2SH),
                  (True, False): (BITCOINCASH_MAIN, BITCOINCASH_P2KH),
                  (False, True): (BITCOINCASH_TEST, BITCOINCASH_P2SH),
                  (False, False): (BITCOINCASH_TEST, BITCOINCASH_P2KH)}
        prefix, value = PARAMS[(is_main, is_script)]
        return BitcoinCashAddressVersion( prefix, value)

    @staticmethod
    def from_runmode(runmode, is_script=False):
        return BitcoinCashAddressVersion.from_parameters(is_main_cash(runmode), is_script)

    def __eq__(self, other):
        return self.value == other.value and self.prefix == other.prefix

    def __str__(self):
        return BITCOINCASH_ADDRESS_TYPE_NAMES[(self.prefix, self.value&0xf8)]+'(%s, %s)'%(self.value& 0xf8, BITCOINCASH_SIZEHASH_rev[self.value&0x07])

    def is_valid_on(self, runmode):
        return self.prefix == runmode
