import smartpy as sp

class myContract(sp.Contract):
    def __init__(self):
        self.init(
            hashed_secret = sp.none
        )

    @sp.entry_point
    def store_hash(self, message):
        self.data.hashed_secret = sp.some(sp.sha256(message))

@sp.add_test(name = 'Test')
def test():
    c = myContract()

    secret = sp.string('My secret message')
    password = sp.string('avada_kedavra')
    packed = sp.pack(secret) + sp.pack(password)
    hashed = sp.sha256(packed)

    scenario = sp.test_scenario()
    scenario.register(c, show = True) # same as scenario += c
    c.store_hash(hashed)