import sys

class MiningThread(object):
    def __init__(self, pool, wallet):
        from importlib import import_module
        self.w3 = getattr(import_module("web3.auto"), "w3")
        self.requests = import_module("requests")
        self.random = import_module("random")
        self.wallet = self.w3.toChecksumAddress(wallet)
        self.pool = pool
        self.difficulty = 1
        self.target = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        self.hashtomine = ""
        self.shares = 0
    
    def refresh(self):
        _info = self.requests.get(f"{self.pool}/miningData").json().get("result")
        self.hashtomine = _info.get("hashtomine")
        self.difficulty = _info.get("difficulty")
        self.target = _info.get("target")
    
    def mine(self):
        self.refresh()
        nonce = 0
        _hash = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        while int(_hash, 16) >= int(self.target, 16):
            nonce = int(self.random.random()*10000000000)
            _hash = self.w3.soliditySha3(["bytes32", "uint256"], [self.hashtomine, nonce]).hex()
        return self.requests.get(f"{self.pool}/submitShare/{self.wallet}/{nonce}").json().get("success")
    
    def mineForever(self):
        while True:
            result = self.mine()
            if result:
                self.shares += 1
            print(f"{self.shares} accepted shares !")

if __name__ == "__main__":
    _miner = MiningThread(sys.argv[1], sys.argv[2])
    _miner.mineForever()