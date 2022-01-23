class Pool(object):
    class Account(object):
        def __init__(self, data):
            self.address = data.get("address")
            self.unpaid = data["unpaid"]
            self.paid = data["paid"]
            self.shares = data["shares"]
        
        def dumpJSON(self):
            return {"paid": self.paid, "unpaid": self.unpaid, "shares": self.shares}

    def __init__(self, NodeAddress):
        from importlib import import_module
        self.node = NodeAddress
        self.client = getattr(import_module("miningClient"), "Client")(NodeAddress)
        self.w3 = getattr(import_module("web3.auto"), "w3")
        self.json = import_module("json")
        
        self.shares = []
        self.accounts = {}
        self.difficulty = 1000000 # 1M
    
    def ensureExistence(self, account):
        _address = self.w3.toChecksumAddress(account)
        if not self.accounts.get(_address):
            self.accounts[_address] = self.Account({"address": _address, "paid": 0, "unpaid": 0, "shares": []})
    
    
    def dumpAccounts():
        acctsJSON = {}
        for key, value in self.accounts.items():
            acctsJSON[key] = value.dumpJSON()
        return acctsJSON
    
    def saveDB():
        file = open("SiriCoinPool.json", "w")
        file.write(json.dumps({"shares": self.shares, "accounts": self.dumpAccounts(), "difficulty": self.difficulty}))
        file.close()
    
    def loadDB():
        try:
            file = open("SiriCoinPool.json", "r")
            data = json.load(file)
            file.close()
        except:
            data = {"accounts": {}, "difficulty": self.difficulty, "shares": []}
        file.close()
        for key, value in data.get("accounts").items():
            self.accounts[key] = self.Account(value)
        self.difficulty = data.get("difficulty")
        self.shares = data.get("shares")
    
    
    
    def calcReward(self):
        self.client.refresh()
        return ((min(((50*self.difficulty)/(self.client.difficulty)), 50))*0.9)
    