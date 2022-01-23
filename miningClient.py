class Client:
    def __init__(self, NodeAddr):
        # self.chain = BeaconChain()
        import importlib
        import hashlib
        self.requests = importlib.import_module("requests")
        self.json = importlib.import_module("json")
        from myCrypto_client import SignatureManager
        from eth_account.account import Account
        self.Beacon = getattr(importlib.import_module("myCrypto_client"), "Beacon")
        
        
        self.node = NodeAddr
        self.signer = SignatureManager()
        self.difficulty = 1
        self.target = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        self.lastBlock = ""
        self.priv_key = hashlib.sha256(b"SiriCoin Will go to MOON - Just a disposable key").hexdigest()
        self.address = Account().from_key(self.priv_key).address
        _txs = self.requests.get(f"{self.node}/accounts/accountInfo/{self.address}").json().get("result").get("transactions")
        self.lastSentTx = _txs[len(_txs)-1]
        self.refresh()
    
    def refresh(self):
        info = self.requests.get(f"{self.node}/chain/miningInfo").json().get("result")
        self.target = info["target"]
        self.difficulty = info["difficulty"]
        self.lastBlock = info["lastBlockHash"]
        _txs = self.requests.get(f"{self.node}/accounts/accountInfo/{self.address}").json().get("result").get("transactions")
        self.lastSentTx = _txs[len(_txs)-1]
    
    def submitBlock(self, blockData):
        self.refresh()
        data = json.dumps({"from": self.address, "to": self.address, "tokens": 0, "parent": self.lastSentTx, "blockData": blockData, "epoch": self.lastBlock, "type": 1})
        tx = {"data": data}
        tx = signer.signTransaction(self.priv_key, tx)
#        print(tx)
        return self.requests.get(f"{self.node}/send/rawtransaction/?tx={json.dumps(tx).encode().hex()}").json().get("result")[0]
        

    def isBeaconValid(self, beacon):
        _lastBeacon = self.Beacon(self.requests.get(f"{self.node}/chain/blockByHash/{self.lastBlock}"))
        if _lastBeacon.proof != beacon.parent:
            return (False, "UNMATCHED_BEACON_PARENT")
        if not beacon.difficultyMatched():
            return (False, "UNMATCHED_DIFFICULTY")
        if ((int(beacon.timestamp) < _lastBeacon.timestamp) or (beacon.timestamp > time.time())):
            return (False, "INVALID_TIMESTAMP")
        return (True, "GOOD")
        
    def verifyProof(self, blockData):
        if not (type(blockData) in [str, dict]):
            return
        if (type(blockData) == str):
            blockData = self.json.loads(blockData)
        try:
            return self.isBeaconValid(self.Beacon(blockData))
        except Exception as e:
            print(type(e), e)
            return False
    
    def buildBlock(self, miner, nonce, timestamp, proof):
        return {"transactions": [],"messages": "6e756c6c","parent": self.lastBlock,"son": None,"timestamp": timestamp,"miningData": {"miner": miner,"nonce": nonce,"difficulty": self.difficulty,"miningTarget": self.miningTarget,"proof": proof}}
        
        
