class NetworkAccess {
	constructor(web3Instance) {
		this.web3Instance = web3Instance;
	}
	
	convertFromHex(hex) {
		var hex = hex.toString();//force conversion
		var str = '';
		for (var i = 0; i < hex.length; i += 2)
			str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
		return str;
	}

	convertToHex(str) {
		var hex = '';
		for(var i=0;i<str.length;i++) {
			hex += ''+str.charCodeAt(i).toString(16);
		}
		return hex;
	}
	
	async getAccountInfo(account) {
		return (await (await fetch(`http://136.244.119.124:5005/accounts/accountInfo/${account}`)).json()).result;
	}

	async getHeadTx(account) {
		let accountInfo = (await getAccountInfo(account));
		return accountInfo.transactions[accountInfo.transactions.length-1];
	}

	async buildTransaction(to, tokens) {
		account = (await this.web3Instance.eth.getAccounts())[0];
		parent = (await getHeadTx(account));
		data = {"from":account, "to":this.web3Instance.utils.toChecksumAddress(to), "tokens":tokens, "parent": parent, "type": 0};
		strdata = JSON.stringify(data);
		hash = this.web3Instance.utils.soliditySha3(strdata);
		signature = await this.web3Instance.eth.personal.sign(strdata, account);
		tx = {"data": data, "sig": signature, "hash": hash, "nodeSigs": {}};
		toSend = this.convertToHex(JSON.stringify(tx));
		return toSend;
	}
	
	async buildMiningTransaction(submittedBlock) {
		account = (await this.web3Instance.eth.getAccounts())[0];
		parent = (await getHeadTx(account));
		data = {"from":account, "to":account, "tokens":0, "blockData": submittedBlock, "parent": parent, "type": 1};
		strdata = JSON.stringify(data);
		hash = this.web3Instance.utils.soliditySha3(strdata);
		signature = await this.web3Instance.eth.personal.sign(strdata, account);
		tx = {"data": data, "sig": signature, "hash": hash, "nodeSigs": {}};
		toSend = this.convertToHex(JSON.stringify(tx));
		return toSend;
	}

	async sendTransaction(signedTx) {
		return (await (await fetch(`http://136.244.119.124:5005/send/rawtransaction/?tx=${signedTx}`)).json()).result;
	}
	
	getVrs(sig) {
		return (('0x' + sig.substring(2).substring(128, 130)), ('0x' + sig.substring(2).substring(0, 64)), ('0x' + sig.substring(2).substring(64, 128)))
	}
}

class Miner {
	constructor(node) {
		this.node = node;
		this.clock = (new Date());
		this.web3 = new Web3(window.ethereum);
		this.account = window.ethereum.enable()[0];
		// "localhost:5005"
	}
	
	convertToHex(str) {
		var hex = '';
		for(var i=0;i<str.length;i++) {
			hex += ''+str.charCodeAt(i).toString(16);
		}
		return hex;
	}
	
	getHashToMine(miningTarget, parent, timestamp, messages, miner) {
		messagesHash = web3.utils.soliditySha3({"t": "bytes", "v": toHex(messages)});
		return web3.utils.soliditySha3({"t": "bytes32", "v": miningTarget}, {"t": "bytes32", "v": parent}, {"t": "uint256", "v": timestamp}, {"t": "bytes32", "v": messagesHash}, {"t": "address", "v": miner});
	}

	async getLastBlockHash() {
		return (await (await fetch(`${this.node}/chain/getlastblock`)).json()).result.miningData.proof;
	}
	
	async getMiningInfo() {
		console.log(`${this.node}/chain/miningInfo`);
		return (await (await fetch(`${this.node}/chain/miningInfo`)).json()).result;
	}
	
	async mine(miningInfo) {
//		miningInfo = await this.getMiningInfo();
		hashToMine = this.getHashToMine(miningInfo.target, miningInfo.lastBlockHash, (this.clock.getTime()/1000).toFixed(), this.convertToHex("null"), this.account);
		console.log(`Hash to mine with : ${hashToMine}`);
		hash = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
		nonce = 0;
		while (hash >= miningInfo.miningTarget) {
			hash = this.web3.utils.soliditySha3({"t": "bytes32", "v": hashToMine}, {"t": "bytes32", "v": nonce})
			nonce += 1;
		}
		return {"proof": hash, "nonce": nonce};
	}
}

getHashToMine("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0x5575a56d1a14e45af6982ca03adfbe26b8af36b509ee1add4ac800e9617ea7d7", 1642008475, "0", "0x3f119cef08480751c47a6f59af1ad2f90b319d44")