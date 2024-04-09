import smartpy as sp

class myContract(sp.Contract):
    def __init__(self):
        self.init(
            records = sp.big_map()
        )

    @sp.entry_point
    def new_user(self):
        sp.verify(~self.data.records.contains(sp.sender), 'User already registered.')
        self.data.records[sp.sender] = {}

    @sp.entry_point
    def add_record(self, params):
        sp.verify(self.data.records.contains(sp.sender), 'User not registerd.')
        sp.verify(~self.data.records[sp.sender].contains(params.message), 'This message is already stored.')
        self.data.records[sp.sender][params.message] = params.sig

@sp.add_test(name = 'Test')
def test():
    c = myContract()
    alice = sp.test_account('Alice')
   
    scenario = sp.test_scenario()
    scenario += c

    scenario.show(alice)

    c.new_user().run(sender = alice.address)
    c.new_user().run(sender = alice.address, valid = False)

    secret = 'This is my secret.'
    message = sp.sha256(sp.sha256(sp.pack(secret)))
    sig = sp.make_signature(alice.secret_key, message, message_format = 'Raw')
    scenario.show(sig)

    check = sp.check_signature(alice.public_key, sig, message)
    scenario.show(check)

    c.add_record(message = message, sig = sig).run(sender = alice.address)
    c.add_record(message = message, sig = sig).run(sender = alice.address, valid = False)

    bob = sp.test_account('Bob')
    secret = '[{a:b, c:d},{e:f}]'
    message = sp.sha256(sp.sha256(sp.pack(secret)))
    sig = sp.make_signature(bob.secret_key, message, message_format = 'Raw')
    
    c.add_record(message = message, sig = sig).run(sender = bob.address, valid = False)
    c.new_user().run(sender = bob.address)
    c.add_record(message = message, sig = sig).run(sender = bob.address)

    bob = sp.test_account('Bob')
    # an alternative follows that combines the secret with the public key hash 
    secret = sp.pack('This is my secret.') + sp.pack(bob.public_key_hash)
    message = sp.sha256(sp.sha256(secret))
    sig = sp.make_signature(bob.secret_key, message, message_format = 'Raw')
    c.add_record(message = message, sig = sig).run(sender = bob.address)