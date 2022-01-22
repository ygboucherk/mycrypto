from myCrypto_client import BeaconChain, Beacon, GenesisBeacon

class MiningClient {
    def __init__(self, NodeAddr):
        # self.chain = BeaconChain()
        self.node = NodeAddr
        self.difficulty = 1
        self.target = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        self.lastBlock = ""
    
    def refresh(self):
        info = requests.get(f"{self.node}/chain/miningInfo").json().get("result")
        self.target = info["target"]
        self.difficulty = info["difficulty"]
        self.lastBlock = info["lastBlockHash"]
        
        
