import smartpy as sp

class Verification(sp.Contract):
    def __init__(self, owner_address, init_counter):
        self.init(
            counter = init_counter,
            owner = owner_address,
            last_caller = sp.none
            )

    @sp.entry_point
    def increment(self, params):
        sp.verify(params.value <= 10, 'Increment too large')
        sp.verify(self.data.last_caller != sp.some(sp.sender), 'Subsequent calls must be from different addresses')
        self.data.counter += params.value
        self.data.last_caller = sp.some(sp.sender)
    
    @sp.entry_point
    def decrement(self, params):
        sp.verify(self.data.owner == sp.sender, 'Only the ownwer may decrement')
        self.data.counter -= params.value

    @sp.entry_point
    def reset(self):
        sp.verify(self.data.owner == sp.sender, 'Only the ownwer may reset')
        self.data.counter = 0


@sp.add_test(name = "Test")
def test():
    alice = sp.test_account('Alice')
    bob = sp.test_account('Bob')
    owner = sp.test_account('Owner')
    c1 = Verification(owner_address = owner.address, init_counter = 0)
    scenario = sp.test_scenario()
    scenario += c1
    c1.increment(value = 5).run(sender = alice.address)
    c1.increment(value = 12).run(sender = alice.address, valid = False)
    c1.increment(value = 7).run(sender = alice.address, valid = False)
    c1.increment(value = 8).run(sender = bob.address)
    c1.decrement(value = 2).run(sender = bob.address, valid = False)
    c1.decrement(value = 3).run(sender = owner.address)
    c1.reset().run(sender = bob.address, valid = False)
    c1.reset().run(sender = owner.address)