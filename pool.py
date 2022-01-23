class Account(object):
    def __init__(self, account):
        self.address = self.w3.toChecksumAddress(account)
        self.unpaid = 0
        self.paid = 0
        self.shares = []
    
class Pool(object):
    def __init__(self, NodeAddress):
        from importlib import import_module
        self.node = NodeAddress
        self.client = getattr(import_module("miningClient"), "Client")(NodeAddress)
        self.w3 = getattr(import_module("web3.auto"), "w3")
        self.accounts = {}
        self.difficulty = 1
    
    def ensureExistence(self, account):
        _address = self.w3.toChecksumAddress(account)
        if not self.accounts.get(_address):
            self.accounts[_address] = Account(_address)
            
    def calcReward(self):
        self.client.refresh()
        return (50*self.difficulty)/(self.client.difficulty)
    