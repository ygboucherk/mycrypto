import requests, time, json, threading, hashlib, flask, rlp
global config
from web3.auto import w3
from eth_account.messages import encode_defunct
from flask_cors import CORS
from dataclasses import asdict, dataclass
from typing import Optional
from eth_utils import keccak
from rlp.sedes import Binary, big_endian_int, binary


transactions = {}
try:
    configFile = open("myCryptoConfig.json", "r")
    config = json.load(configFile)
    configFile.close()
except:
    config = {"dataBaseFile": "testmycrypto-2.json", "nodePrivKey": "20735cc14fd4a86a2516d12d880b3fa27f183a381c5c167f6ff009554c1edc69", "peers":["https://siricoin-node-1.dynamic-dns.net:5005/"], "InitTxID": "none"}

try:
    ssl_context = tuple(config["ssl"])
except:
    ssl_context = None

class SignatureManager(object):
    def __init__(self):
        self.verified = 0
        self.signed = 0
    
    def signTransaction(self, private_key, transaction):
        message = encode_defunct(text=transaction["data"])
        transaction["hash"] = w3.soliditySha3(["string"], [transaction["data"]]).hex()
        _signature = w3.eth.account.sign_message(message, private_key=private_key).signature.hex()
        signer = w3.eth.account.recover_message(message, signature=_signature)
        sender = w3.toChecksumAddress(json.loads(transaction["data"])["from"])
        if (signer == sender):
            transaction["sig"] = _signature
            self.signed += 1
        return transaction
        
    def verifyTransaction(self, transaction):
        message = encode_defunct(text=transaction["data"])
        _hash = w3.soliditySha3(["string"], [transaction["data"]]).hex()
        _hashInTransaction = transaction["hash"]
        signer = w3.eth.account.recover_message(message, signature=transaction["sig"])
        sender = w3.toChecksumAddress(json.loads(transaction["data"])["from"])
        result = ((signer == sender) and (_hash == _hashInTransaction))
        self.verified += int(result)
        return result

class ETHTransactionDecoder(object):
    class Transaction(rlp.Serializable):
        fields = [
            ("nonce", big_endian_int),
            ("gas_price", big_endian_int),
            ("gas", big_endian_int),
            ("to", Binary.fixed_length(20, allow_empty=True)),
            ("value", big_endian_int),
            ("data", binary),
            ("v", big_endian_int),
            ("r", big_endian_int),
            ("s", big_endian_int),
        ]


    @dataclass
    class DecodedTx:
        hash_tx: str
        from_: str
        to: Optional[str]
        nonce: int
        gas: int
        gas_price: int
        value: int
        data: str
        chain_id: int
        r: str
        s: str
        v: int


    def decode_raw_tx(self, raw_tx: str):
        bytesTx = bytes.fromhex(raw_tx.replace("0x", ""))
        tx = rlp.decode(bytesTx, self.Transaction)
        hash_tx = w3.toHex(keccak(bytesTx))
        from_ = w3.eth.account.recover_transaction(raw_tx)
        to = w3.toChecksumAddress(tx.to) if tx.to else None
        data = w3.toHex(tx.data)
        r = hex(tx.r)
        s = hex(tx.s)
        chain_id = (tx.v - 35) // 2 if tx.v % 2 else (tx.v - 36) // 2
        return self.DecodedTx(hash_tx, from_, to, tx.nonce, tx.gas, tx.gas_price, tx.value, data, chain_id, r, s, tx.v)



class Message(object):
    def __init__(self, _from, _to, msg):
        self.sender = _from
        self.recipient = _to
        self.msg = msg

class Transaction(object):
    def __init__(self, tx):
        txData = json.loads(tx["data"])
        self.txtype = (txData.get("type") or 0)
        if (self.txtype == 0):
            self.sender = w3.toChecksumAddress(txData.get("from"))
            self.recipient = w3.toChecksumAddress(txData.get("to"))
            self.value = float(txData.get("tokens"))
        if (self.txtype == 1):
            self.sender = w3.toChecksumAddress(txData.get("from"))
            self.blockData = txData.get("blockData")
            # print(self.blockData)
            self.recipient = "0x0000000000000000000000000000000000000000"
            self.value = 0.0
        elif self.txtype == 2:
            decoder = ETHTransactionDecoder()
            ethDecoded = decoder.decode_raw_tx(txData.get("rawTx"))
            self.sender = ethDecoded.from_
            self.recipient = ethDecoded.to
            self.value = float(ethDecoded.value/(10**18))
            self.nonce = ethDecoded.nonce
            self.ethData = ethDecoded.data
            self.ethTxid = ethDecoded.hash_tx
            
        
        self.epoch = txData.get("epoch")
        self.bio = txData.get("bio")
        self.parent = txData.get("parent")
        self.message = txData.get("message")
        self.txid = tx.get("hash")
        
        # self.PoW = ""
        # self.endTimeStamp = 0



class GenesisBeacon(object):
    def __init__(self):
        self.timestamp = 1641738403
        self.miner = "0x0000000000000000000000000000000000000000"
        self.parent = "Blahblah initializing the chain".encode()
        self.difficulty = 1
        self.messages = "Hello world, I dont have anything to put here so just saying random shit lol".encode()
        self.nonce = 0
        self.miningTarget = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        self.proof = self.proofOfWork()
        self.transactions = []
        self.number = 0
        
    def beaconRoot(self):
        messagesHash = w3.soliditySha3(["bytes"], [self.messages])
        bRoot = w3.soliditySha3(["bytes32", "uint256", "bytes","address"], [self.parent, self.timestamp, messagesHash, self.miner]) # parent PoW hash (bytes32), beacon's timestamp (uint256), beacon miner (address)
        return bRoot.hex()

    def proofOfWork(self):
        bRoot = self.beaconRoot()
        proof = w3.soliditySha3(["bytes32", "uint256"], [bRoot, int(self.nonce)])
        return proof.hex()

    def difficultyMatched(self):
        return int(self.proofOfWork(), 16) < self.miningTarget

    def exportJson(self):
        return {"transactions": self.transactions, "messages": self.messages.hex(), "parent": self.parent.hex(), "timestamp": self.timestamp, "height": self.number, "miningData": {"miner": self.miner, "nonce": self.nonce, "difficulty": self.difficulty, "miningTarget": self.miningTarget, "proof": self.proof}}


class Beacon(object):
    # def __init__(self, parent, difficulty, timestamp, miner, logsBloom):
        # self.miner = ""
        # self.timestamp = timestamp
        # self.parent = parent
        # self.nonce = nonce
        # self.logsBloom = logsBloom
        # self.miner = w3.toChecksumAddress(miner)
        # self.difficulty = difficulty
        # self.miningTarget = int((2**256)/self.difficulty)
        # self.proof = self.proofOfWork()
    
    def __init__(self, data, difficulty):
        miningData = data["miningData"]
        self.miner = w3.toChecksumAddress(miningData["miner"])
        self.nonce = miningData["nonce"]
        self.difficulty = difficulty
        self.messages = bytes.fromhex(data["messages"])
        self.miningTarget = hex(int(min(int((2**256-1)/self.difficulty),0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)))
        self.timestamp = int(data["timestamp"])
        self.parent = data["parent"]
        self.transactions = []
        self.proof = self.proofOfWork()
        self.number = 0
        self.son = ""
    
              
    def beaconRoot(self):
        messagesHash = w3.soliditySha3(["bytes"], [self.messages])
        bRoot = w3.soliditySha3(["bytes32", "uint256", "bytes32","address"], [self.parent, int(self.timestamp), messagesHash, self.miner]) # parent PoW hash (bytes32), beacon's timestamp (uint256), hash of messages (bytes32), beacon miner (address)
        return bRoot.hex()

    def proofOfWork(self):
        bRoot = self.beaconRoot()
#        print(f"Beacon root : {bRoot}")
        proof = w3.soliditySha3(["bytes32", "uint256"], [bRoot, int(self.nonce)])
        return proof.hex()

    def difficultyMatched(self):
#        print(self.proofOfWork())
#        print(self.miningTarget)
        return int(self.proofOfWork(), 16) < int(self.miningTarget, 16)

    def exportJson(self):
        return {"transactions": self.transactions, "messages": self.messages.hex(), "parent": self.parent, "son": self.son, "timestamp": self.timestamp, "height": self.number, "miningData": {"miner": self.miner, "nonce": self.nonce, "difficulty": self.difficulty, "miningTarget": self.miningTarget, "proof": self.proof}}

class BeaconChain(object):
    def __init__(self):
        self.difficulty = 1
        self.miningTarget = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        self.blocks = [GenesisBeacon()]
        self.blocksByHash = {self.blocks[0].proof: self.blocks[0]}
        self.pendingMessages = []
        self.blockTime = 1200 # in seconds, about 20 minutes

    def checkBeaconMessages(self, beacon):
        _messages = beacon.messages.decode().split(",")
        for msg in _messages:
            if (not msg in self.pendingMessages) and (msg != "null"):
                return False
        return True
    
    def calcDifficulty(self, expectedDelay, timestamp1, timestamp2, currentDiff):
        return min(max((currentDiff * expectedDelay)/max((timestamp2 - timestamp1), 1), currentDiff * 0.9, 1), currentDiff*1.1)
    
    def isBeaconValid(self, beacon):
        _lastBeacon = self.getLastBeacon()
        if _lastBeacon.proof != beacon.parent:
            return (False, "UNMATCHED_BEACON_PARENT")
        if not self.checkBeaconMessages(beacon):
            return (False, "INVALID_MESSAGE")
        if not beacon.difficultyMatched():
            return (False, "UNMATCHED_DIFFICULTY")
        if ((int(beacon.timestamp) < _lastBeacon.timestamp) or (beacon.timestamp > time.time())):
            return (False, "INVALID_TIMESTAMP")
        return (True, "GOOD")
    
    
    def isBlockValid(self, blockData):
        try:
            return self.isBeaconValid(Beacon(blockData, self.difficulty))
        except Exception as e:
            return (False, e)
    
    def getLastBeacon(self):
        return self.blocks[len(self.blocks) - 1]
    
    
    def addBeaconToChain(self, beacon):
        _messages = beacon.messages.decode()
        if _messages != "null":
            self.pendingMessages.remove(msg)
        currentChainLength = len(self.blocks)
        self.getLastBeacon().son = beacon.proof
        _oldtimestamp = self.getLastBeacon().timestamp
        beacon.number = currentChainLength
        self.blocks.append(beacon)
        self.blocksByHash[beacon.proof] = beacon
        self.difficulty = self.calcDifficulty(self.blockTime, _oldtimestamp, int(beacon.timestamp), self.difficulty)
        self.miningTarget = hex(int(min(int((2**256-1)/self.difficulty),0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)))
        return True
    
    def submitBlock(self, block):
        # print(block)
        try:
            _beacon = Beacon(block, self.difficulty)
        except Exception as e:
            print(e)
            return False
        beaconValidity = self.isBeaconValid(_beacon)
        # print(beaconValidity)
        if beaconValidity[0]:
            self.addBeaconToChain(_beacon)
            return _beacon.miner
        return False
    
    def mineEpoch(self, epochDetails):
        isValid = self.isEpochValid(epochDetails)
    
    
    def submitMessage(self, message):
        self.pendingMessages.append(message)
    
    def getBlockByHeightJSON(self, height):
        try:
            return self.blocks[height].exportJson()
        except:
            return None
    
    def getLastBlockJSON(self):
        return self.getLastBeacon().exportJson()
    

class State(object):
    def __init__(self, initTxID):
        self.balances = {"0x611B74e0dFA8085a54e8707c573A588138c9dDba": 10, "0x3f119Cef08480751c47a6f59Af1AD2f90b319d44": 100, "0x0000000000000000000000000000000000000000": 0}
        self.transactions = {"0x0000000000000000000000000000000000000000": []}
        self.received = {"0x0000000000000000000000000000000000000000": []}
        self.sent = {"0x0000000000000000000000000000000000000000": []}
        self.mined = {"0x0000000000000000000000000000000000000000": []}
        self.messages = {}
        self.accountBios = {"0x0000000000000000000000000000000000000000": "Address zero dont have a bio but better to have something here lol"}
        self.initTxID = initTxID
        self.txChilds = {self.initTxID: []}
        self.txIndex = {}
        self.lastTxIndex = 0
        self.beaconChain = BeaconChain()
        self.totalSupply = 110 # initial supply used for testing
        self.type2ToType0Hash = {}
        self.type0ToType2Hash = {}

    def getCurrentEpoch(self):
        return self.beaconChain.getLastBeacon().proof
        
    def getGenesisEpoch(self):
        return self.beaconChain.blocks[0].proof

    def ensureExistence(self, user):
        if not self.balances.get(user):
            self.balances[user] = 0
        if not self.transactions.get(user):
            self.transactions[user] = [self.initTxID]
        if not self.sent.get(user):
            self.sent[user] = [self.initTxID]
        if not self.received.get(user):
            self.received[user] = []
        if not self.received.get(user):
            self.mined[user] = []
        if not self.accountBios.get(user):
            self.accountBios[user] = ""



    def checkParent(self, tx):
        lastTx = self.getLastUserTx(tx.sender)
        if tx.txtype == 2:
            tx.parent = self.sent.get(tx.sender)[tx.nonce - 1]
            return (tx.nonce == len(self.sent.get(tx.sender)))
        else: 
            return (tx.parent == lastTx)

    def checkBalance(self, tx):
        return tx.value > (self.balances.get(tx.sender) or 0)


    def estimateTransferSuccess(self, _tx):
        self.ensureExistence(_tx.sender)
        self.ensureExistence(_tx.recipient)
        if self.checkBalance(_tx):
            return (False, "Too low balance")
        if not self.checkParent(_tx):
            return (False, "Parent unmatched")
            
        return (True, "It'll succeed")

    def estimateMiningSuccess(self, tx):
        self.ensureExistence(tx.sender)
        return self.beaconChain.isBlockValid(tx.blockData)

    def isBeaconCorrect(self, tx):
        # print(tx.epoch)
        return (not tx.epoch) or (tx.epoch == self.getCurrentEpoch())

    def willTransactionSucceed(self, tx):
        _tx = Transaction(tx)
        underlyingOperationSuccess = False
        correctParent = self.checkParent(_tx)
        correctBeacon = self.isBeaconCorrect(_tx)
        if _tx.txtype == 0 or _tx.txtype == 2:
            underlyingOperationSuccess = self.estimateTransferSuccess(_tx)[0]
        if _tx.txtype == 1:
            underlyingOperationSuccess = self.estimateMiningSuccess(_tx)[0]
        return (underlyingOperationSuccess and correctBeacon and correctParent)
        

    # def mineBlock(self, blockData):
        # self.beaconChain.submitBlock(blockData)



    def applyParentStuff(self, tx):
        self.txChilds[tx.txid] = []
        if tx.txtype == 2:
            tx.parent = self.sent.get(tx.sender)[tx.nonce - 1]
            self.type2ToType0Hash[tx.ethTxid] = tx.txid
            self.type0ToType2Hash[tx.txid] = tx.ethTxid
            
        self.txChilds[tx.parent].append(tx.txid)
        self.txIndex[tx.txid] = self.lastTxIndex
        self.lastTxIndex += 1
        self.transactions[tx.sender].append(tx.txid)
        if (tx.sender != tx.recipient):
            self.transactions[tx.recipient].append(tx.txid)
        if tx.txtype == 1:
            miner = tx.blockData.get("miningData").get("miner")
            self.ensureExistence(miner)
            self.mined[miner].append(tx.txid)
            self.transactions[miner].append(tx.txid)
        _txepoch = tx.epoch or self.getGenesisEpoch()
        if self.beaconChain.blocksByHash.get(_txepoch):
            self.beaconChain.blocksByHash[_txepoch].transactions.append(tx.txid)
        else:
            self.beaconChain.blocksByHash[self.getGenesisEpoch()].transactions.append(tx.txid)
        
        self.sent[tx.sender].append(tx.txid)
        self.received[tx.recipient].append(tx.txid)

    def executeTransfer(self, tx, showMessage):
        willSucceed = self.estimateTransferSuccess(tx)
        if not willSucceed[0]:
            return willSucceed
        self.applyParentStuff(tx)
        
        
        self.balances[tx.sender] -= tx.value
        self.balances[tx.recipient] += tx.value
        
        if (showMessage):
            print(f"Transfer executed !\nAmount transferred : {tx.value}\nFrom: {tx.sender}\nTo: {tx.recipient}")
        return (True, "Transfer succeeded")

    def postMessage(self, msg, showMessage):
        pass # still under development

    def mineBlock(self, tx):
        try:
            self.ensureExistence(tx.sender)
            feedback = self.beaconChain.submitBlock(tx.blockData);
            self.applyParentStuff(tx)
            # print(feedback)
            if feedback:
#                self.ensureExistence(feedback)
                self.balances[feedback] += 50
                self.totalSupply += 50
                return True
            return False
        except:
            raise
            return False


    def playTransaction(self, tx, showMessage):
        _tx = Transaction(tx)
        feedback = False
        if _tx.txtype == 0:
            feedback = self.executeTransfer(_tx, showMessage)
        if _tx.txtype == 1:
            feedback = self.mineBlock(_tx)
        if _tx.txtype == 2:
            feedback = self.executeTransfer(_tx, showMessage)
        
        
        if (_tx.bio):
            self.accountBios[_tx.sender] = _tx.bio.replace("%20", " ")
        # if _tx.message:
            # self.leaveMessage(_from, _to, msg, showMessage)
        return feedback

    def getLastUserTx(self, _user):
        user = w3.toChecksumAddress(_user)
        self.ensureExistence(user)
        if (len(self.transactions[user]))>0:
            return self.transactions[user][len(self.transactions[user])-1]
        else:
            return self.initTxID
            
    def getLastSentTx(self, _user):
        user = w3.toChecksumAddress(_user)
        self.ensureExistence(user)
        if (len(self.sent[user]))>0:
            return self.sent[user][len(self.sent[user])-1]
        else:
            return self.initTxID
            
    def getLastReceivedTx(self, _user):
        user = w3.toChecksumAddress(_user)
        self.ensureExistence(user)
        if (len(self.received[user]))>0:
            return self.received[user][len(self.received[user])-1]
        else:
            return None
    

class Peer(object):
    def __init__(self, url):
        self.url = url

class Node(object):
    def __init__(self, config):
        self.transactions = {}
        self.txsOrder = []
        self.mempool = []
        self.sigmanager = SignatureManager()
        self.state = State(config["InitTxID"])
        self.config = config
        self.peers = config["peers"]
        self.bestBlockChecked = 0
        self.goodPeers = []
        self.checkGuys()
        self.initNode()


    def canBePlayed(self, tx):
        sigVerified = False
        playableByState = False
        if json.loads(tx.get("data")).get("type") != 2:
            sigVerified = self.sigmanager.verifyTransaction(tx)
        else:
            sigVerified = True
        playableByState = self.state.willTransactionSucceed(tx)
        return (sigVerified and playableByState, sigVerified, playableByState)
        

    def addTxToMempool(self, tx):
        if (self.canBePlayed(tx)[1]):
            self.mempool.append(tx)


    def initNode(self):
        try:
            self.loadDB()
            print("Successfully loaded node DB !")
        except:
            print("Error loading DB, starting from zero :/")
        self.upgradeTxs()
        for txHash in self.txsOrder:
            tx = self.transactions[txHash]
            self.state.playTransaction(tx, False)
            self.propagateTransactions([tx])
        self.saveDB()
        self.syncByBlock()
        self.saveDB()

    def checkTxs(self, txs):
        # print("Pulling DUCO txs...")
        # txs = requests.get(self.config["endpoint"]).json()["result"]
        # print("Successfully pulled transactions !")
#        print("Saving transactions to DB...")
        _counter = 0
        for tx in txs:
            playable = self.canBePlayed(tx)
            # print(f"Result of canBePlayed: {playable}")
            if (not self.transactions.get(tx["hash"]) and playable[0]):
                self.transactions[tx["hash"]] = tx
                self.txsOrder.append(tx["hash"])
                self.state.playTransaction(tx, True)
                _counter += 1
                print(f"Successfully saved transaction {tx['hash']}")
        if _counter > 0:
            print(f"Successfully saved {_counter} transactions !")
        self.saveDB()

    def saveDB(self):
        toSave = json.dumps({"transactions": self.transactions, "txsOrder": self.txsOrder})
        file = open(self.config["dataBaseFile"], "w")
        file.write(toSave)
        file.close()

    def loadDB(self):
#        print(self.config["dataBaseFile"])
        file = open(self.config["dataBaseFile"], "r")
        file.seek(0)
        db = json.load(file)
#        print(db)
        self.transactions = db["transactions"]
        self.txsOrder = db["txsOrder"]
        file.close()
    
    # def backgroundRoutine(self):
        # while True:
            # self.checkTxs()
            # self.saveDB()
            # time.sleep(float(self.config["delay"]))
    
    def upgradeTxs(self):
        for txid in self.txsOrder:
            if type(self.transactions[txid]["data"]) == dict:
                self.transactions[txid]["data"] = json.dumps(self.transactions[txid]["data"]).replace(" ", "")
    
    
    
    
    # REQUESTING DATA FROM PEERS    
    def checkGuys(self):
        for peer in self.peers:
            self.goodPeers = []
            try:
                if (requests.get(f"{peer}/ping").json()["success"]):
                    self.goodPeers.append(peer)
            except:
                pass
    
    def pullSetOfTxs(self, txids):
        txs = []
        for txid in txids:
            localTx = self.transactions.get(txid)
            if not localTx:
                for peer in self.goodPeers:
                    try:
                        tx = requests.get(f"{peer}/get/transactions/{txid}").json()["result"][0]
                        txs.append(tx)
                        break
                    except:
                        raise
            else:
                txs.append(localTx)
        return txs

    def pullChildsOfATx(self, txid):
        vwjnvfeuuqubb = self.state.txChilds.get(txid) or []
        children = vwjnvfeuuqubb.copy()
        for peer in self.goodPeers:
            try:
                _childs = requests.get(f"{peer}/accounts/txChilds/{txid}").json()["result"]
                for child in _childs:
                    if not (child in children):
                        parent = json.loads(self.pullSetOfTxs([child])[0]["data"])["parent"]
                        if (parent == txid):
                            children.append(child)
                break
            except:
                pass
        return children
        
    def pullTxsByBlockNumber(self, blockNumber):
        txs = []
        try:
            txs = self.state.beaconChain.blocks[blockNumber].transactions.copy()
        except:
            txs = []
        for peer in self.goodPeers:
            try:
                _txs = requests.get(f"{peer}/accounts/txChilds/{txid}").json()["result"]
                for _tx in _txs:
                    if not (_tx in txs):
                        parent = json.loads(self.pullSetOfTxs([_tx])[0]["data"])["parent"]
                        if (parent == txid):
                            txs.append(_tx)
                break
            except:
                pass
        return txs
    
    def execTxAndRetryWithChilds(self, txid):
#        print(f"Loading tx {txid}")
        tx = self.pullSetOfTxs([txid])
#        print(tx)
        self.checkTxs(tx)
        _childs = self.pullChildsOfATx(txid)
        for txid in _childs:
            self.execTxAndRetryWithChilds(txid)
    
    def syncDB(self):
        self.checkGuys()
        toCheck = self.pullChildsOfATx(self.config["InitTxID"])
#        print(toCheck)
        for txid in toCheck:
            _childs = self.execTxAndRetryWithChilds(txid)
    
    def getChainLength(self):
        self.checkGuys()
        length = 0
        for peer in self.goodPeers:
            length = max(requests.get(f"{peer}/chain/length").json()["result"], length)
        return length
    
    def syncByBlock(self):
        self.checkTxs(self.pullSetOfTxs(self.pullTxsByBlockNumber(0)))
        for blockNumber in range(self.bestBlockChecked,self.getChainLength()):
            self.checkTxs(self.pullSetOfTxs(self.pullTxsByBlockNumber(blockNumber)))
            self.bestBlockChecked = blockNumber
    
    
    def propagateTransactions(self,txs):
        toPush = []
        for tx in txs:
            txString = json.dumps(tx).replace(" ", "")
            txHex = txString.encode().hex()
            toPush.append(txHex)
        toPush = ",".join(toPush)
        for node in self.goodPeers:
            requests.get(f"{node}/send/rawtransaction/?tx={toPush}")
    
    def networkBackgroundRoutine(self):
        while True:
#            print("Refreshing transactions from other nodes")
            self.checkGuys()
            self.syncByBlock()
            time.sleep(60)

    def txReceipt(self, txid):
        _txid = txid
        if self.state.type2ToType0Hash.get(txid):
            _txid = self.state.type2ToType0Hash.get(txid)
        _tx_ = Transaction(self.transactions.get(_txid))
        _blockHash = _tx_.epoch or self.state.getGenesisEpoch()
        _beacon_ = self.state.beaconChain.blocksByHash.get(_blockHash)
        return {"transactionHash": _txid,"transactionIndex":  '0x1',"blockNumber": _beacon_.number, "blockHash": _blockHash, "cumulativeGasUsed": '0x5208', "gasUsed": '0x5208',"contractAddress": None,"logs": [], "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","status": '0x1'}
    
    
    
    

    def integrateETHTransaction(self, ethTx):
        data = json.dumps({"rawTx": ethTx, "epoch": self.state.getCurrentEpoch(), "type": 2}).replace(" ", "")
        _txid_ = w3.soliditySha3(["string"], [data]).hex()
        self.checkTxs([{"data": data, "hash": _txid_}])
        return _txid_


# thread = threading.Thread(target=node.backgroundRoutine)
# thread.start()

class TxBuilder(object):
    def __init__(self, node):
        self.signer = SignatureManager()
        self.node = node

    def buildTransaction(self, priv_key, _from, _to, tokens):
        from_ = w3.toChecksumAddress(_from)
        to_ = w3.toChecksumAddress(_to)
        data = json.dumps({"from": from_, "to": to_, "tokens": tokens, "parent": self.state.getLastSentTx(_from), "type": 0})
        tx = {"data": data}
        tx = self.signer.signTransaction(priv_key, tx)
#        print(tx)
        playable = self.node.canBePlayed(tx)
        self.checkTxs([tx])
        return (tx, playable)


node = Node(config)
print(node.config)
maker = TxBuilder(node)
thread = threading.Thread(target=node.networkBackgroundRoutine)
thread.start()






# HTTP INBOUND PARAMS
app = flask.Flask(__name__)
app.config["DEBUG"] = False
CORS(app)


@app.route("/")
def basicInfoHttp():
    return "SiriCoin cryptocurrency node running on port 5005"

@app.route("/ping")
def getping():
    return json.dumps({"result": "Pong !", "success": True})

# HTTP GENERAL GETTERS - pulled from `Node` class
@app.route("/get/transactions", methods=["GET"]) # get all transactions in node
def getTransactions():
    return flask.jsonify(result=node.transactions, success=True)

@app.route("/get/nFirstTxs/<n>", methods=["GET"]) # GET N first transactions
def nFirstTxs(n):
    _n = min(len(node.txsOrder), n)
    txs = []
    for txid in txsOrder[0,n-1]:
        txs.append(node.transactions.get(txid))
    return flask.jsonify(result=txs, success=True)
    
@app.route("/get/nLastTxs/<n>", methods=["GET"]) # GET N last transactions
def nLastTxs(n):
    _n = min(len(node.txsOrder), n)
    _n = len(node.txsOrder)-_n
    txs = []
    for txid in txsOrder[_n,len(node.txsOrder)]:
        txs.append(node.transactions.get(txid))
        
    return flask.jsonify(result=txs, success=True)

@app.route("/get/txsByBounds/<upperBound>/<lowerBound>", methods=["GET"]) # get txs from upperBound to lowerBound (in index)
def getTxsByBound(upperBound, lowerBound):
    upperBound = min(upperBound, len(node.txsOrder)-1)
    lowerBound = max(lowerBound, 0)
    for txid in txsOrder[lowerBound,upperBound]:
        txs.append(node.transactions.get(txid))
    return flask.jsonify(result=txs, success=True)

@app.route("/get/txIndex/<index>")
def getTxIndex(txid):
    _index = node.state.txIndex.get(tx)
    if _index:
        return flask.jsonify(result=_index, success=True)
    else:
        return (flask.jsonify(message="TX_NOT_FOUND", success=False), 404)

@app.route("/get/transaction/<txhash>", methods=["GET"]) # get specific tx by hash
def getTransactionByHash(txhash):
    tx = node.transactions.get(txhash)
    if (tx):
        return flask.jsonify(result=tx, success=True)
    else:
        return (flask.jsonify(message="TX_NOT_FOUND", success=False), 404)

@app.route("/get/transactions/<txhashes>", methods=["GET"]) # get specific tx by hash
def getMultipleTransactionsByHashes(txhashes):
    txs = []
    oneSucceeded = False
    _txhashes = txhashes.split(",")
    for txhash in _txhashes:
        tx = node.transactions.get(txhash)
        if (tx):
            txs.append(tx)
            oneSucceeded = True
    return flask.jsonify(result=txs, success=oneSucceeded)

@app.route("/get/numberOfReferencedTxs") # get number of referenced transactions
def numberOfTxs():
    return flask.jsonify(result=len(node.txsOrder), success=True)



# ACCOUNT-BASED GETTERS (obtained from `State` class)
@app.route("/accounts/accountInfo/<account>") # Get account info (balance and transaction hashes)
def accountInfo(account):
    _address = w3.toChecksumAddress(account)
    balance = node.state.balances.get(_address)
    transactions = node.state.transactions.get(_address) or [node.config["InitTxID"]]
    bio = node.state.accountBios.get(_address)
    nonce = len(node.state.sent.get(_address) or ["init"])
    return flask.jsonify(result={"balance": (balance or 0), "nonce": nonce, "transactions": transactions, "bio": bio}, success= True)

@app.route("/accounts/accountBalance/<account>")
def accountBalance(account):
    _address = w3.toChecksumAddress(account)
    balance = node.state.balances.get(_address)
    return flask.jsonify(result={"balance": (balance or 0)}, success=True)

@app.route("/accounts/txChilds/<tx>")
def txParent(tx):
    _kids = node.state.txChilds.get(tx)
    if _kids:
        return flask.jsonify(result=_kids, success=True)
    else:
        return flask.jsonify(message="TX_NOT_FOUND", success=False)

# SEND TRANSACTION STUFF (redirected to `Node` class)
@app.route("/send/rawtransaction/") # allows sending a raw (signed) transaction
def sendRawTransactions():
    rawtxs = str(flask.request.args.get('tx', None))
    rawtxs = rawtxs.split(",")
    txs = []
    hashes = []
    for rawtx in rawtxs:
        tx = json.loads(bytes.fromhex(rawtx).decode())
        print(tx)
        if (type(tx["data"]) == dict):
            tx["data"] = json.dumps(tx["data"]).replace(" ", "")
        txs.append(tx)
        hashes.append(tx["hash"])
    node.checkTxs(txs)
    return flask.jsonify(result=hashes, success=True)

@app.route("/send/buildtransaction/")
def buildTransactionAndSend():
    privkey = str(flask.request.args.get('privkey', None))
    _from = str(flask.request.args.get('from', None))
    _to = str(flask.request.args.get('to', None))
    tokens = str(flask.request.args.get('value', None))
    result = buildTransaction(self, privkey, _from, _to, tokens)[0]
    return flask.jsonify(result=result[0], success=result[1])


# BEACON RELATED DATA (loaded from node/state/beaconChain)
@app.route("/chain/block/<block>")
def getBlock(block):
    _block = node.state.beaconChain.getBlockByHeightJSON(int(block))
    return flask.jsonify(result=_block, success=not not _block)

@app.route("/chain/blockByHash/<blockhash>")
def blockByHash(blockhash):
    _block = node.state.beaconChain.blocksByHash.get(blockhash)
    if _block:
        _block = _block.exportJson()
    return flask.jsonify(result=_block, success=not not _block)

@app.route("/chain/getlastblock")
def getlastblock():
    return flask.jsonify(result=node.state.beaconChain.getLastBlockJSON(), success=True)    

@app.route("/chain/miningInfo")
def getMiningInfo():
    _result = {"difficulty" : node.state.beaconChain.difficulty, "target": node.state.beaconChain.miningTarget, "lastBlockHash": node.state.beaconChain.getLastBeacon().proof}
    print(_result)
    return flask.jsonify(result=_result, success=True)

@app.route("/chain/length")
def getChainLength():
    return flask.jsonify(result=len(node.state.beaconChain.blocks), success=True)

# SHARE PEERS (from `Node` class)
@app.route("/net/getPeers")
def shareMyPeers():
    return flask.jsonify(result=node.peers, success=True)
    
@app.route("/net/getOnlinePeers")
def shareOnlinePeers():
    return flask.jsonify(result=node.goodPeers, success=True)



# WEB3 COMPATIBLE RPC
@app.route("/web3", methods=["POST"])
def handleWeb3Request():
    data = flask.request.get_json()
    _id = data.get("_id")
    print(data)
    method = data.get("method")
    params = data.get("params")
    result = hex(5005)
    if method == "eth_getBalance":
        result = hex(int((node.state.balances.get(w3.toChecksumAddress(params[0])) or 0)*10**18))
    if method == "net_version":
        result = str(5005)
    if method == "eth_coinbase":
        result = node.state.beaconChain.getLastBeacon().miner
    if method == "eth_mining":
        result = False
    if method == "eth_gasPrice":
        result = "0x1"
    if method == "eth_blockNumber":
        result = hex(len(node.state.beaconChain.blocks) - 1)
    if method == "eth_getTransactionCount":
        result = hex(len(node.state.sent.get(w3.toChecksumAddress(params[0])) or []))
    if method == "eth_getCode":
        result = "0x"
    if method == "eth_estimateGas":
        result = '0x5208'
    # if method == "eth_sign":
        # result = w3.eth.account.sign_message(encode_defunct(text=), private_key="").signature.hex()
    if method == "eth_call":
        result = "0x"
    if method == "eth_getCompilers":
        result = []
    if method == "eth_sendRawTransaction":
        result = node.integrateETHTransaction(params[0])
        print(result)
    if method == "eth_getTransactionReceipt":
        result = node.txReceipt(params[0])
    
        
    return flask.Response(json.dumps({"id": _id, "jsonrpc": "2.0", "result": result}), mimetype='application/json');
    


print(ssl_context)
app.run(host="0.0.0.0", port=5005, ssl_context=ssl_context)