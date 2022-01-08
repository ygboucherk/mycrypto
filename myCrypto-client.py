import requests, time, json, threading, hashlib, flask
global config
from web3.auto import w3
from eth_account.messages import encode_defunct

transactions = {}
config = {"dataBaseFile": "testmycrypto.json", "nodePrivKey": "20735cc14fd4a86a2516d12d880b3fa27f183a381c5c167f6ff009554c1edc69", "peers":["http://149.28.231.249:5005/"], "InitTxID": "none"}


class SignatureManager(object):
    def __init__(self):
        self.verified = 0
        self.signed = 0
    
    def signTransaction(self, private_key, transaction):
        message = encode_defunct(text=json.dumps(transaction["data"]).replace(" ", ""))
        transaction["hash"] = "0x" + w3.soliditySha3(["string"], [json.dumps(transaction["data"]).replace(" ", "")]).hex()
        _signature = w3.eth.account.sign_message(message, private_key=private_key).signature.hex()
        signer = w3.eth.account.recover_message(message, signature=_signature)
        sender = w3.toChecksumAddress(transaction["data"]["from"])
        if (signer == sender):
            transaction["sig"] = _signature
            self.signed += 1
        return transaction
        
    def verifyTransaction(self, transaction):
        print(json.dumps(transaction["data"]))
        message = encode_defunct(text=json.dumps(transaction["data"]).replace(" ", ""))
        _hash = w3.soliditySha3(["string"], [json.dumps(transaction["data"]).replace(" ", "")]).hex()
        _hashInTransaction = transaction["hash"]
        signer = w3.eth.account.recover_message(message, signature=transaction["sig"])
        sender = w3.toChecksumAddress(transaction["data"]["from"])
        result = ((signer == sender) and (_hash == _hashInTransaction))
        print(f"signer: {signer}\nsender: {sender}\ncalculated hash: {_hash}\nhash in tx: {_hashInTransaction}")
        self.verified += int(result)
        return result

    def giveNodeSig(self, private_key, transaction):
        message = encode_defunct(text=json.dumps({"data":transaction["data"], "sig": transaction["sig"]}).replace(" ", ""))
        _signature = w3.eth.account.sign_message(message, private_key=private_key).signature.hex()
        signer = w3.eth.account.recover_message(message, signature=_signature)
        transaction["nodeSigs"][signer] = _signature
        return transaction

    def checkNodeSig(self, node_pub_key, transaction):
        pub = w3.toChecksumAddress(node_pub_key)
        message = encode_defunct(text=json.dumps({"data":transaction["data"], "sig": transaction["sig"]}).replace(" ", ""))
        signer = w3.eth.account.recover_message(message, signature=transaction["nodeSigs"].get(pub))
        return (signer == pub)

class Message(object):
    def __init__(self, _from, _to, msg):
        self.sender = _from
        self.recipient = _to
        self.msg = msg

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

    def checkParent(self, tx, isExecuting):
        if (((tx["data"].get("parent")) != self.getLastSentTx(_from)) and (self.getLastSentTx(_from) != None)):
            if isExecuting:
                print(f"Error executing tx {tx['hash']}, error: PARENT UNMATCHED")
            return (False, "Parent unmatched")

    def willTransactionSucceed(self, tx):
        _from = w3.toChecksumAddress(tx["data"]["from"])
        _to = w3.toChecksumAddress(tx["data"]["from"])
        self.ensureExistence(_from)
        self.ensureExistence(_to)
        _tokens = int(tx["data"]["tokens"])
        if (_tokens > self.balances.get(_from)):
            return (False, "Too low balance")
        lastTx = self.getLastUserTx(_from)
        if ((tx["data"].get("parent")) != lastTx):
            return (False, "Parent unmatched")
        return (True, "It'll succeed")

    def executeTransfer(self, tx, _from, _to, _tokens, showMessage):
        if (_tokens > self.balances.get(_from)):
            print(f"Error executing tx {tx['hash']}, error: BALANCE TOO LOW")
            return (False, "Too low balance")
        lastTx = self.getLastUserTx(_from)
        if ((tx["data"].get("parent")) != lastTx):
            print(f"Error executing tx {tx['hash']}, error: PARENT UNMATCHED")
            return (False, "Parent unmatched")
            
        
        self.txChilds[tx["hash"]] = []
        self.txChilds[tx["data"].get("parent")].append(tx["hash"])
        self.txIndex[tx["hash"]] = self.lastTxIndex
        self.lastTxIndex += 1
        
        
        
        self.balances[_from] -= _tokens
        self.balances[_to] += _tokens
        self.transactions[_from].append(tx["hash"])
        self.sent[_from].append(tx["hash"])
        self.transactions[_to].append(tx["hash"])
        self.received[_to].append(tx["hash"])
        if (showMessage):
            print(f"Transfer executed !\nAmount transferred : {_tokens}\nFrom: {_from}\nTo: {_to}")
        return (True, "Transfer succeeded")

    def postMessage(self, msg, showMessage):
        pass # still under development

    def playTransaction(self, tx, showMessage):
        _from = w3.toChecksumAddress(tx["data"]["from"])
        _to = w3.toChecksumAddress(tx["data"]["to"])
        self.ensureExistence(_from)
        self.ensureExistence(_to)
        _tokens = int(tx["data"]["tokens"])
        transferFeedback = self.executeTransfer(tx, _from, _to, _tokens, showMessage)
        msg = tx["data"].get("message")
        accountBio = tx["data"].get("bio")
        if (accountBio):
            self.accountBios[_from] = accountBio.replace("%20", " ")
        if msg:
            self.leaveMessage(_from, _to, msg, showMessage)
        return transferFeedback

    def getLastUserTx(self, _user):
        user = w3.toChecksumAddress(_user)
        self.ensureExistence(user)
        if (len(self.transactions[user]))>0:
            return self.transactions[user][len(self.transactions[user])-1]
        else:
            return None
            
    def getLastSentTx(self, _user):
        user = w3.toChecksumAddress(_user)
        self.ensureExistence(user)
        if (len(self.sent[user]))>0:
            return self.sent[user][len(self.sent[user])-1]
        else:
            return None
            
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
        playableByState = self.state.willTransactionSucceed(tx)[0]
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
        for txHash in self.txsOrder:
            tx = self.transactions[txHash]
            print(f"Result of canBePlayed : {self.canBePlayed(tx)}")
            self.state.playTransaction(tx, False)
            self.propagateTransactions([tx])
        self.saveDB()
        self.syncDB()
        self.saveDB()

    def checkTxs(self, txs):
        # print("Pulling DUCO txs...")
        # txs = requests.get(self.config["endpoint"]).json()["result"]
        # print("Successfully pulled transactions !")
        print("Saving transactions to DB...")
        _counter = 0
        for tx in txs:
            playable = self.canBePlayed(tx)
            print(f"Result of canBePlayed: {playable}")
            if (not self.transactions.get(tx["hash"]) and playable[0]):
                tx = self.sigmanager.giveNodeSig(config["nodePrivKey"], tx)
                self.transactions[tx["hash"]] = tx
                self.txsOrder.append(tx["hash"])
                self.state.playTransaction(tx, True)
                _counter += 1
                print(f"Successfully saved transaction {tx['hash']}")
        print(f"Successfully saved {_counter} transactions !")
        self.saveDB()

    def saveDB(self):
        toSave = json.dumps({"transactions": self.transactions, "txsOrder": self.txsOrder})
        file = open(self.config["dataBaseFile"], "w")
        file.write(toSave)
        file.close()

    def loadDB(self):
        print(self.config["dataBaseFile"])
        file = open(self.config["dataBaseFile"], "r")
        file.seek(0)
        db = json.load(file)
        print(db)
        self.transactions = db["transactions"]
        self.txsOrder = db["txsOrder"]
        file.close()
    
    # def backgroundRoutine(self):
        # while True:
            # self.checkTxs()
            # self.saveDB()
            # time.sleep(float(self.config["delay"]))
            
    def txsForUser(self, user):
        txs = self.transactions
        _txs = []
        for key, value in txs.items():
            if (value["data"]["from"] == user) or (value["data"]["to"] == user):
                _txs.append(value)
        return _txs
    
    
    
    
    
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
                        pass
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
                        parent = self.pullSetOfTxs([child])[0]["data"]["parent"]
                        print(parent)
                        if (parent == txid):
                            children.append(child)
                break
            except:
                pass
        return children
    
    def execTxAndRetryWithChilds(self, txid):
        print(f"Loading tx {txid}")
        tx = self.pullSetOfTxs([txid])
        self.checkTxs(tx)
        _childs = self.pullChildsOfATx(txid)
        for txid in _childs:
            self.execTxAndRetryWithChilds(txid)
    
    def syncDB(self):
        toCheck = self.pullChildsOfATx(self.config["InitTxID"])
        print(toCheck)
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
            print("Refreshing transactions from other nodes")
            self.checkGuys()
            self.pullTransactions()
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
        data = {"from": from_, "to": to_, "tokens": tokens, "parent": self.state.getLastSentTx(_from), "type": 0}
        tx = {"data": data, "nodeSigs": {}}
        tx = self.signer.signTransaction(priv_key, tx)
        print(tx)
        playable = self.node.canBePlayed(tx)
        self.checkTxs([tx])
        return (tx, playable)


node = Node(config)
print(node.config)
maker = TxBuilder(node)
thread = threading.Thread(target=node.networkBackgroundRoutine)







# HTTP INBOUND PARAMS
app = flask.Flask(__name__)
app.config["DEBUG"] = False




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

# SHARE PEERS (from `Node` class)
@app.route("/net/getPeers")
def shareMyPeers():
    return flask.jsonify(result=node.peers, success=True)
    
@app.route("/net/getOnlinePeers")
def shareOnlinePeers():
    return flask.jsonify(result=node.goodPeers, success=True)


app.run(host="0.0.0.0", port=5005)