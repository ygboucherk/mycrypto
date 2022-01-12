import requests, time, json, threading, hashlib, flask
global config
from web3.auto import w3
from eth_account.messages import encode_defunct
from flask_cors import CORS

transactions = {}
config = {"dataBaseFile": "testmycrypto.json", "nodePrivKey": "20735cc14fd4a86a2516d12d880b3fa27f183a381c5c167f6ff009554c1edc69", "peers":["http://136.244.119.124:5005/"], "InitTxID": "none"}


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

class Message(object):
    def __init__(self, _from, _to, msg):
        self.sender = _from
        self.recipient = _to
        self.msg = msg

class Transaction(object):
    def __init__(self, tx):
        txData = json.loads(tx["data"])
        self.sender = w3.toChecksumAddress(txData.get("from"))
        self.recipient = w3.toChecksumAddress(txData.get("to"))
        self.value = float(txData.get("tokens"))
        self.bio = txData.get("bio")
        self.parent = txData.get("parent")
        self.message = txData.get("message")
        self.txid = tx.get("hash")
        self.txtype = (txData.get("type") or 0)
        if (self.txtype == 1):
            self.blockData = tx.get("blockData")
        
        self.PoW = ""
        self.endTimeStamp = 0



class GenesisBeacon(object):
    def __init__(self):
        self.timestamp = 1641738403
        self.miner = "0x0000000000000000000000000000000000000000"
        self.parent = "Blahblah initializing the chain".encode()
        self.difficulty = 1
        self.logsBloom = "Hello world, I dont have anything to put here so just saying random shit lol".encode()
        self.nonce = 0
        self.miningTarget = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        self.proof = self.proofOfWork()
        
    def beaconRoot(self):
        logsBloomHash = w3.soliditySha3(["bytes"], [self.logsBloom])
        bRoot = w3.soliditySha3(["bytes32","bytes32", "uint256", "bytes","address"], [self.miningTarget, self.parent, self.timestamp, logsBloomHash, self.miner]) # beacon mining target (uint256), parent PoW hash (bytes32), beacon's timestamp (uint256), beacon miner (address)
        return bRoot.hex()

    def proofOfWork(self):
        bRoot = self.beaconRoot()
        proof = w3.soliditySha3(["bytes32", "bytes32"], [bRoot, hex(self.nonce)])
        return proof.hex()

    def difficultyMatched(self, nonce, miner, timestamp):
        return (2**256 / int(self.proofOfWork(nonce, miner), 16)) >= self.difficulty

    def exportJson(self):
        return {"logsBloom": self.logsBloom.hex(), "parent": self.parent.hex(), "timestamp": self.timestamp, "miningData": {"miner": self.miner, "nonce": self.nonce, "difficulty": self.difficulty, "miningTarget": self.miningTarget}}


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
    
    def __init__(self, data):
        _data = json.loads(data)
        miningData = _data["miningData"]
        self.miner = web3.toChecksumAddress(miningData["miner"])
        self.nonce = miningData["nonce"]
        self.difficulty = difficulty
        self.miningTarget = int((2**256)/self.difficulty)
        self.logsBloom = data["logsBloom"]
        
        self.timestamp = data["timestamp"]
        self.parent = data["parent"]

        self.proof = self.proofOfWork()
        self.son = ""
    
              
    def beaconRoot(self):
        logsBloomHash = w3.soliditySha3(["bytes"], [self.logsBloom])
        bRoot = w3.soliditySha3(["bytes32","bytes32", "uint256", "bytes","address"], [hex(self.miningTarget), self.parent, self.timestamp, logsBloomHash, self.miner]) # beacon mining target (uint256), parent PoW hash (bytes32), beacon's timestamp (uint256), beacon miner (address)
        return bRoot.hex()

    def proofOfWork(self):
        bRoot = self.beaconRoot()
        proof = w3.soliditySha3(["bytes32", "bytes32"], [bRoot, hex(self.nonce)])
        return proof.hex()

    def difficultyMatched(self, nonce):
        return (2**256 / int(self.proofOfWork(nonce, miner), 16)) >= self.difficulty

    def exportJson(self):
        return {"logsBloom": self.logsBloom.hex(), "parent": self.parent.hex(), "son": self.son, "timestamp": self.timestamp, "miningData": {"miner": self.miner, "nonce": self.nonce, "difficulty": self.difficulty, "miningTarget": self.miningTarget}}

class BeaconChain(object):
    def __init__(self):
        self.difficuly = 0
        self.difficulty = 1
        self.blocks = [GenesisBeacon()]
        self.blocksByHash = {self.blocks[0].proof: self.blocks[0]}
        self.pendingLogsBloom = []

    def checkBeaconLogsBloom(self, beacon):
        _logsBloom = bytes.fromhex(beacon.logsBloom).decode().split(",")
        for msg in _logsBloom:
            if not msg in self.pendingLogsBloom:
                return False
        return True
    
    def calcDifficulty(self, expectedDelay, timestamp1, timestamp2, currentDiff):
        return min((currentDiff * expectedDelay)/(timestamp2 - timestamp1), currentDiff * 0.9)
    
    def isBeaconValid(self, beacon):
        _lastBeacon = self.getLastBeacon()
        if _lastBeacon.proof != beacon.parent:
            return (False, "UNMATCHED_BEACON_PARENT")
        if not self.checkBeaconLogsBloom(beacon):
            return (False, "INVALID_LOGS_BLOOM")
        if not beacon.difficultyMatched():
            return (False, "UNMATCHED_DIFFICULTY")
        if ((beacon.timestamp < _lastBeacon.timestamp) or (beacon.timestamp > time.time())):
            return (False, "INVALID_TIMESTAMP")
        return (True, "GOOD")
    
    
    def isBlockValid(self, blockData):
        try:
            return self.isBeaconValid(Beacon(blockData))
        except Exception as e:
            return (False, e)
    
    def getLastBeacon(self):
        return self.blocks[len(self.blocks) - 1]
    
    
    def addBeaconToChain(self, beacon):
        _logsBloom = bytes.fromhex(beacon.logsBloom).decode().split(",")
        for msg in _logsBloom:
            self.pendingLogsBloom.remove(msg)
        self.getLastBeacon().son = beacon.proof
        self.blocks.append(beacon)
        self.blocksByHash[beacon.proof] = beacon
        return True
    
    def submitBlock(self, block):
        try:
            _beacon = Beacon(block)
        except:
            return False
        if self.isBeaconValid(_beacon):
            self.addBeaconToChain(beacon)
            return True
        return False
    
    def difficultyForElapsedTime(self, _time):
        return min((self.difficulty / time), 1)
    
    def mineEpoch(self, epochDetails):
        isValid = self.isEpochValid(epochDetails)
    
    def submitMessage(self, message):
        self.logsBloom.append("message")
    
    def getBlockHeightJSON(self, height):
        try:
            return self.blocks[height].exportJson()
        except:
            raise
            return None
    

class State(object):
    def __init__(self, initTxID):
        self.balances = {"0x611B74e0dFA8085a54e8707c573A588138c9dDba": 10, "0x3f119Cef08480751c47a6f59Af1AD2f90b319d44": 100}
        self.transactions = {}
        self.received = {}
        self.sent = {}
        self.messages = {}
        self.accountBios = {}
        self.initTxID = initTxID
        self.txChilds = {self.initTxID: []}
        self.txIndex = {}
        self.lastTxIndex = 0
        self.beaconChain = BeaconChain()

    def ensureExistence(self, user):
        if not self.balances.get(user):
            self.balances[user] = 0
        if not self.transactions.get(user):
            self.transactions[user] = [self.initTxID]
        if not self.sent.get(user):
            self.sent[user] = [self.initTxID]
        if not self.received.get(user):
            self.received[user] = []
        if not self.accountBios.get(user):
            self.accountBios[user] = ""



    def checkParent(self, tx):
        lastTx = self.getLastUserTx(tx.sender)
        if (tx.parent != lastTx):
            return False
        return True

    def checkBalance(self, tx):
        return tx.value >= (self.balances.get(tx.sender) or 0)



    def estimateTransferSuccess(self, _tx):
        self.ensureExistence(_tx.sender)
        self.ensureExistence(_tx.recipient)
        if self.checkBalance(_tx):
            return (False, "Too low balance")
        if not self.checkParent(_tx):
            return (False, "Parent unmatched")
            
        return (True, "It'll succeed")

    def willTransactionSucceed(self, tx):
        _tx = Transaction(tx)
        return self.estimateTransferSuccess(_tx)




    # def mineBlock(self, blockData):
        # self.beaconChain.submitBlock(blockData)



    def executeTransfer(self, tx, showMessage):
        willSucceed = self.estimateTransferSuccess(tx)
        if not willSucceed[0]:
            return willSucceed
        self.txChilds[tx.txid] = []
        self.txChilds[tx.parent].append(tx.txid)
        self.txIndex[tx.txid] = self.lastTxIndex
        self.lastTxIndex += 1
        
        
        
        self.balances[tx.sender] -= tx.value
        self.balances[tx.recipient] += tx.value
        
        
        self.transactions[tx.sender].append(tx.txid)
        if (tx.sender != tx.recipient):
            self.transactions[tx.recipient].append(tx.txid)
        
        self.sent[tx.sender].append(tx.txid)
        self.received[tx.recipient].append(tx.txid)
        if (showMessage):
            print(f"Transfer executed !\nAmount transferred : {tx.value}\nFrom: {tx.sender}\nTo: {tx.recipient}")
        return (True, "Transfer succeeded")

    def postMessage(self, msg, showMessage):
        pass # still under development

    def playTransaction(self, tx, showMessage):
        _tx = Transaction(tx)
        
        if _tx.txtype == 0:
            transferFeedback = self.executeTransfer(_tx, showMessage)
        if _tx.txtype == 1:
            self.beaconChain.submitBlock(_tx.blockData)
        
        
        
        if (_tx.bio):
            self.accountBios[_tx.sender] = _tx.bio.replace("%20", " ")
        # if _tx.message:
            # self.leaveMessage(_from, _to, msg, showMessage)
        return transferFeedback

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
        self.goodPeers = []
        self.checkGuys()
        self.initNode()


    def canBePlayed(self, tx):
        sigVerified = False
        playableByState = False
        sigVerified = self.sigmanager.verifyTransaction(tx)
        playableByState = self.state.willTransactionSucceed(tx)
        return (sigVerified and playableByState[0], sigVerified, playableByState)
        

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
        self.syncDB()
        self.saveDB()

    def checkTxs(self, txs):
        # print("Pulling DUCO txs...")
        # txs = requests.get(self.config["endpoint"]).json()["result"]
        # print("Successfully pulled transactions !")
#        print("Saving transactions to DB...")
        _counter = 0
        for tx in txs:
            playable = self.canBePlayed(tx)
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
        children = self.state.txChilds.get(txid) or []
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
            self.syncDB()
            time.sleep(60)



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
    return "*ah shit I shall still name it* cryptocurrency node running on port 5005"

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
    transactions = node.state.transactions.get(_address)
    bio = node.state.accountBios.get(_address)
    return flask.jsonify(result={"balance": (balance or 0), "transactions": transactions, "bio": bio}, success= True)

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
    _block = node.state.beaconChain.getBlockHeightJSON(int(block))
    print(_block)
    return flask.jsonify(result=_block, success=not not _block)
    


# SHARE PEERS (from `Node` class)
@app.route("/net/getPeers")
def shareMyPeers():
    return flask.jsonify(result=node.peers, success=True)
    
@app.route("/net/getOnlinePeers")
def shareOnlinePeers():
    return flask.jsonify(result=node.goodPeers, success=True)
app.run(host="0.0.0.0", port=5005)