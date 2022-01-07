import smartpy as sp

class myContract(sp.Contract):
    def __init__(self, owner1, owner2):
        self.init(
            locks = {owner1: False, owner2: False}
        )
    
    @sp.entry_point
    def deposit(self):
        pass

    @sp.entry_point
    def withdraw(self, params):
        # verity that the account is unlocked
        sp.for lock in self.data.locks.values():
            sp.verify(lock == False, 'Funds are locked.')
        # verify that the requester is one of the owners
        sp.verify(self.data.locks.contains(sp.sender), 'Sender not an account owner.')
        # send funds
        sp.verify(sp.balance >= params.amount, 'Insufficient balance.')
        sp.send(params.account, params.amount)

    @sp.entry_point
    def lock(self):
        sp.verify(self.data.locks.contains(sp.sender), 'Sender not an account owner.')
        sp.verify(self.data.locks[sp.sender] == False, 'Funds alredy locked.')
        self.data.locks[sp.sender] = True
    
    @sp.entry_point
    def unlock(self):
        sp.verify(self.data.locks.contains(sp.sender), 'Sender not an account owner.')
        sp.verify(self.data.locks[sp.sender] == True, 'Funds already unlocked.')
        self.data.locks[sp.sender] = False

@sp.add_test(name = 'Test')
def test():
    alice = sp.test_account('Alice')
    bob = sp.test_account('Bob')
    attacker = sp.test_account('Attacker')

    c = myContract(owner1 = alice.address, owner2 = bob.address)
    scenario = sp.test_scenario()
    scenario += c

    scenario.h2("Anyone can make deposits.")
    c.deposit().run(sender = alice.address, amount = sp.tez(100))
    c.deposit().run(sender = bob.address, amount = sp.tez(100))
    c.deposit().run(sender = attacker.address, amount = sp.tez(100))
    
    scenario.h2("Only owners and make withdrawals.")
    c.withdraw(amount = sp.tez(50), account = alice.address).run(sender = alice.address)
    c.withdraw(amount = sp.tez(50), account = bob.address).run(sender = alice.address)
    c.withdraw(amount = sp.tez(50), account = alice.address).run(sender = bob.address)
    c.withdraw(amount = sp.tez(50), account = alice.address).run(sender = attacker.address, valid = False)

    scenario.h2("If either of the owners lock, withdrawals are no longer allowed.")
    c.lock().run(sender = attacker.address, valid = False)
    c.lock().run(sender = alice.address)
    c.lock().run(sender = alice.address, valid = False)

    c.withdraw(amount = sp.tez(50), account = alice.address).run(sender = alice.address, valid = False)
    c.withdraw(amount = sp.tez(50), account = attacker.address).run(sender = attacker.address, valid = False)
    c.withdraw(amount = sp.tez(50), account = bob.address).run(sender = bob.address, valid = False)
    c.deposit().run(amount = sp.tez(100)) # anybody can still deposit

    c.lock().run(sender = bob.address)
    c.withdraw(amount = sp.tez(50), account = alice.address).run(sender = alice.address, valid = False)
    c.withdraw(amount = sp.tez(50), account = alice.address).run(sender = bob.address, valid = False)
    c.withdraw(amount = sp.tez(50), account = alice.address).run(sender = attacker.address, valid = False)

    c.unlock().run(sender = alice.address)
    c.unlock().run(sender = alice.address, valid = False)
    c.withdraw(amount = sp.tez(50), account = alice.address).run(sender = alice.address, valid = False)
    c.unlock().run(sender = attacker.address, valid = False)
    c.unlock().run(sender = bob.address)

    c.withdraw(amount = sp.tez(200), account = bob.address).run(sender = alice.address)
    c.withdraw(amount = sp.tez(500), account = bob.address).run(sender = bob.address, valid = False)