
TESTNET, MAIN = RUNMODES = list(range(2))
RUNMODE_NAMES = {TESTNET: "Testnet", MAIN: "Main"}
BITCOINCASH_MAIN = b"bitcoincash"
BITCOINCASH_TEST = b"bchtest"
BITCOINCASH_REG = b"bchreg"

def is_testnet(runmode):
    return (runmode != MAIN)

def is_main(runmode):
    return (runmode == MAIN)

def is_main_cash(runmode):
    return (runmode == BITCOINCASH_MAIN)
