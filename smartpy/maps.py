import smartpy as sp

class myContract(sp.Contract):
    def __init__(self):
        self.init(
            visitors = {}
        )

    @sp.entry_point
    def register(self, login, name):
        self.data.visitors[login] = sp.record(visits = 0, name = name, last_visit = sp.none)

    @sp.entry_point
    def visit(self, login):
        sp.verify(sp.some(sp.now.add_days(-10)) > self.data.visitors[login].last_visit, 'Must wait 10 days between visits.')
        sp.if (self.data.visitors[login].visits == 0):
            sp.verify(sp.amount == sp.tez(5), 'Must pay 5 tez for first visit.')
        sp.else:
            sp.verify(sp.amount == sp.tez(3), 'Must pay 3 tez for the second and each subsequent visits.')
        
        self.data.visitors[login].visits += 1
        self.data.visitors[login].last_visit = sp.some(sp.now)

@sp.add_test(name = 'Test')
def test():
    alice = sp.test_account('Alice')
    bob = sp.test_account('Bob')
    ts = sp.timestamp(0)
    c = myContract()
    scenario = sp.test_scenario()
    scenario.register(c, show = True) # same as scenario += c
    c.register(login = alice.address, name = sp.string('Alice')).run(now = ts)
    ts = ts.add_days(1)
    c.register(login = bob.address, name = sp.string('Bob')).run(now = ts)
    ts = ts.add_days(2)
    c.visit(alice.address).run(amount = sp.tez(5), now = ts)
    c.visit(alice.address).run(amount = sp.tez(5), now = ts, valid = False)
    ts = ts.add_days(4)
    c.visit(alice.address).run(amount = sp.tez(3), now = ts, valid = False)
    ts = ts.add_days(7)
    c.visit(alice.address).run(amount = sp.tez(3), now = ts)
    ts = ts.add_days(11)
    c.visit(alice.address).run(amount = sp.tez(3), now = ts)
    c.visit(bob.address).run(amount = sp.tez(3), now = ts, valid = False)
    c.visit(bob.address).run(amount = sp.tez(5), now = ts)
    c.visit(bob.address).run(amount = sp.tez(15), now = ts, valid = False)
    ts = ts.add_days(12)
    c.visit(bob.address).run(amount = sp.tez(3), now = ts)
