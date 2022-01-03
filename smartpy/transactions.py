import smartpy as sp

class myContract(sp.Contract):
    def __init__(self, owner, max_collect_percent):
        self.init(
            owner = owner,
            max_collect_percent = max_collect_percent,
            next_collect = sp.none
            )

    @sp.entry_point
    def deposit(self, max_collect_percent):
        sp.verify(sp.amount >= sp.tez(100), 'Deposit must be at least 100 tez.')
        sp.verify(max_collect_percent >= 1, 'Maximum withdrawal amount must be at least 1 percent of balance.')
        self.data.max_collect_percent = max_collect_percent


    @sp.entry_point
    def collect(self, amount):
        sp.verify(sp.sender == self.data.owner, 'Only owner can collect.')
        max_collect = sp.compute(sp.split_tokens(sp.balance,sp.nat(100),self.data.max_collect_percent))
        sp.verify(amount <= max_collect, 'Withdrawal amount exceeds allowed limit.')
        sp.if (self.data.next_collect.is_some()):
            sp.verify(sp.some(sp.now) > self.data.next_collect, 'Withdrawal frequency exceeds limit.')
        self.data.next_collect = sp.some(sp.now.add_seconds(120))
        sp.send(self.data.owner, amount)



@sp.add_test(name = "Test")
def test():
    owner = sp.test_account('Owner')
    alice = sp.test_account('Alice')
    bob = sp.test_account('Bob')
    c = myContract(owner = owner.address, max_collect_percent = sp.nat(50))
    scenario = sp.test_scenario()
    scenario += c

    scenario.h1('Test Accounts')
    scenario.show(alice)
    scenario.show(bob)
    scenario.show(owner)

    c.deposit(sp.nat(20)).run(sender = alice.address, amount = sp.tez(100))
    c.deposit(sp.nat(20)).run(sender = bob.address, amount = sp.tez(50), valid = False)
    c.deposit(sp.nat(40)).run(sender = bob.address, amount = sp.tez(200))
    c.deposit(sp.nat(0)).run(sender = bob.address, amount = sp.tez(100), valid = False)
    c.collect(sp.tez(50)).run(sender = alice.address, valid = False)
    c.collect(sp.tez(50)).run(sender = owner.address)
    c.collect(sp.tez(40)).run(sender = owner.address, valid = False)
    c.collect(sp.tez(40)).run(sender = owner.address, valid = False)
    c.collect(sp.tez(40)).run(sender = owner.address, now = sp.timestamp(100), valid = False)
    c.collect(sp.tez(40)).run(sender = owner.address, now = sp.timestamp(150))

