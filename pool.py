import flask, sys
from flask_cors import CORS

class Pool(object):
    class Account(object):
        def __init__(self, data):
            self.address = data.get("address")
            self.unpaid = data["unpaid"]
            self.paid = data["paid"]
            self.shares = data["shares"]
        
        def dumpJSON(self):
            return {"paid": self.paid, "unpaid": self.unpaid, "shares": self.shares}

    class PendingBeacon(object):
        def __init__(self, timestamp, lastBlock, poolAddress, w3):
            self.timestamp = int(timestamp)
            self.lastBlock = lastBlock
            self.poolAddress = poolAddress
            self.w3 = w3
            self.hashToMine = self.beaconRoot()
        
        def beaconRoot(self):
            messagesHash = self.w3.soliditySha3(["bytes"], [bytes.fromhex("6e756c6c")])
            bRoot = self.w3.soliditySha3(["bytes32", "uint256", "bytes","address"], [self.lastBlock, self.timestamp, messagesHash, self.poolAddress]) # parent PoW hash (bytes32), beacon's timestamp (uint256), beacon miner (address)
            return bRoot.hex()

        def proofOfWork(self, nonce):
            proof = self.w3.soliditySha3(["bytes32", "uint256"], [self.hashToMine, int(nonce)])
            return proof.hex()
        
        def difficultyMatched(self, nonce, target):
            return (int(self.proofOfWork(nonce), 16) <= int(target, 16))

    def __init__(self, NodeAddress, privkey):
        from importlib import import_module
        from eth_account.account import Account
        self.node = NodeAddress
        self.client = getattr(import_module("miningClient"), "Client")(NodeAddress, privkey=privkey)
        self.w3 = getattr(import_module("web3.auto"), "w3")
        self.json = import_module("json")
        self.time = import_module("time")
        self.signer = getattr(import_module("myCrypto_client"), "SignatureManager")()
        self.minedHashes = []
        
        
        self.shares = []
        self.accounts = {}
        self.difficulty = 100000 # 1M, aka 50 seconds at 20kH/s
        self.target = hex(int(min(int((2**256-1)/self.difficulty),0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)))
        
        self.priv_key = privkey
        self.address = Account().from_key(privkey).address
        
        self.toMineBlockData = {}
        
        self.loadDB()
        self.client.refresh()
        self.pendingBeacon = self.PendingBeacon(self.time.time(), self.client.lastBlock, self.address, self.w3)  
            
        print(f"SiriCoin pool started and connecting to node {self.node}\nSiriCoin address : {self.address}")
        
    
    def ensureExistence(self, account):
        _address = self.w3.toChecksumAddress(account)
        if not self.accounts.get(_address):
            self.accounts[_address] = self.Account({"address": _address, "paid": 0, "unpaid": 0, "shares": []})
    
    
    def dumpAccounts(self):
        acctsJSON = {}
        for key, value in self.accounts.items():
            acctsJSON[key] = value.dumpJSON()
        return acctsJSON
    
    def saveDB(self):
        file = open("SiriCoinPool.json", "w")
        file.write(self.json.dumps({"shares": self.shares, "accounts": self.dumpAccounts(), "difficulty": self.difficulty, "minedHashes": self.minedHashes}))
        file.close()
    
    def loadDB(self):
        try:
            file = open("SiriCoinPool.json", "r")
            data = self.json.load(file)
            file.close()
        except:
            data = {"accounts": {}, "difficulty": self.difficulty, "shares": [], "minedHashes": []}
        for key, value in data.get("accounts").items():
            self.accounts[key] = self.Account(value)
        self.difficulty = data.get("difficulty")
        self.shares = data.get("shares")
        self.minedHashes = data.get("minedHashes")
    
    def calcReward(self):
        self.client.refresh()
        return ((min(((50*self.difficulty)/(self.client.difficulty)), 50))*0.9)
        
    def refresh(self):
        self.client.refresh()
        if self.client.lastBlock != self.pendingBeacon.lastBlock:
            self.pendingBeacon = self.PendingBeacon(self.time.time(), self.client.lastBlock, self.address, self.w3)            
            
        
    def submitShare(self, miner, nonce):
        self.refresh()
        _address = self.w3.toChecksumAddress(miner)
        self.ensureExistence(_address)
        calculatedHash = self.pendingBeacon.proofOfWork(nonce)
        if calculatedHash in self.minedHashes:
            return False
        else:
            self.minedHashes.append(calculatedHash)
            
        shareDiffMatched = self.pendingBeacon.difficultyMatched(nonce, self.target)
        blockDiffMatched = self.pendingBeacon.difficultyMatched(nonce, self.client.target)
        if blockDiffMatched:
            builtBlock = self.client.buildBlock(self.address, nonce, self.pendingBeacon.timestamp, calculatedHash)
            self.client.submitBlock(builtBlock)
            
        if shareDiffMatched:
            self.accounts[_address].unpaid += self.calcReward()
            self.accounts[_address].shares.append(calculatedHash)
            self.shares.append(calculatedHash)
        self.saveDB()
        return shareDiffMatched
    
    def withdraw(self, miner):
        _to = self.w3.toChecksumAddress(miner)
        self.ensureExistence(_to)
        tokens = self.accounts.get(_to).unpaid
        self.accounts.get(_to).unpaid = 0
        self.accounts.get(_to).paid += tokens
        self.saveDB()
        return (tokens, self.requests.get(f"{self.node}/send/buildtransaction/?privkey={self.privkey}&from={self.address}&to={_to}&value={tokens}").json().get("result"))
        

pool = Pool(sys.argv[1], sys.argv[2])
app = flask.Flask(__name__)
app.config["DEBUG"] = False
CORS(app)

@app.route("/")
def httpRoot():
    return "SiriCoin pool running on port 5006"

@app.route("/submitShare/<miner>/<nonce>")
def submit(miner, nonce):
    submitted = pool.submitShare(miner, nonce)
    return flask.jsonify(result=submitted, success=submitted)

@app.route("/withdraw/<miner>")
def askWithdrawal(miner):
    return flask.jsonify(result=pool.withdraw(miner)[0], success=True)

@app.route("/account/<miner>")
def accountInfo(miner):
    return flask.jsonify(result=pool.accounts.get(pool.w3.toChecksumAddress(miner)).dumpJSON(), success=True)

@app.route("/miningData")
def getMiningData():
    return flask.jsonify(result={"hashtomine": pool.pendingBeacon.hashToMine, "difficulty": pool.difficulty, "target": pool.target}, success=True)

if __name__ == "__main__":
    # app.run(host="0.0.0.0", port=5006, ssl_context=ssl_context)
    app.run(host="0.0.0.0", port=5006, ssl_context=None)