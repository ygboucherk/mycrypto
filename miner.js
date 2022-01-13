class Wallet {
	constructor(web3Instance) {
		this.web3Instance = web3Instance;
		this.miningAccount = web3.eth.accounts.privateKeyToAccount(web3.utils.soliditySha3((Math.random()*10**17).toFixed()));
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
		const account = (await this.web3Instance.eth.getAccounts())[0];
		const parent = (await getHeadTx(account));
		let data = {"from":account, "to":this.web3Instance.utils.toChecksumAddress(to), "tokens":tokens, "parent": parent, "type": 0};
		let strdata = JSON.stringify(data);
		const hash = this.web3Instance.utils.soliditySha3(strdata);
		const signature = await this.web3Instance.eth.personal.sign(strdata, account);
		const tx = {"data": data, "sig": signature, "hash": hash, "nodeSigs": {}};
		return this.convertToHex(JSON.stringify(tx));
	}
	
	async buildMiningTransaction(submittedBlock) {
		const account = (await this.web3Instance.eth.getAccounts())[0];
		const parent = (await getHeadTx(this.miningAccount.address));
		let data = {"from":this.miningAccount.address, "to":this.miningAccount.address, "tokens":0, "blockData": submittedBlock, "parent": parent, "type": 1};
		let strdata = JSON.stringify(data);
		const hash = this.web3Instance.utils.soliditySha3(strdata);
		const signature = await this.miningAccount.sign(strdata).signature;
		const tx = {"data": data, "sig": signature, "hash": hash, "nodeSigs": {}};
		return this.convertToHex(JSON.stringify(tx));
	}

	async sendTransaction(signedTx) {
		console.log(signedTx);
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
		this.wallet = new Wallet(this.web3);
		this.accounts = window.ethereum.enable();
		// "localhost:5005"
	}
	
	convertToHex(str) {
		var hex = '';
		for(var i=0;i<str.length;i++) {
			hex += ''+str.charCodeAt(i).toString(16);
		}
		return hex;
	}
	
	getHashToMine(context) {
		let messagesHash = web3.utils.soliditySha3({"t": "bytes", "v": context.messages});
		return web3.utils.soliditySha3({"t": "bytes32", "v": context.parent}, {"t": "uint256", "v": context.timestamp}, {"t": "bytes32", "v": messagesHash}, {"t": "address", "v": context.miningData.miner});
		// target (uint256), parent (bytes32), timestamp (uint256)
	}

	async getLastBlockHash() {
		return (await (await fetch(`${this.node}/chain/getlastblock`)).json()).result.miningData.proof;
	}
	
	async getMiningInfo() {
		console.log(`${this.node}/chain/miningInfo`);
		return (await (await fetch(`${this.node}/chain/miningInfo`)).json()).result;
	}
	
	async mine() {
		const miningInfo = await this.getMiningInfo();
		let miningData = {"difficulty": miningInfo.difficulty, "miningTarget": miningInfo.target, "miner": (await this.web3.eth.getAccounts())[0], "nonce": (0).toFixed(), "proof": ""}
		let context = {"messages": this.convertToHex("null"), "target": miningInfo.target, "parent": miningInfo.lastBlockHash, "timestamp": (this.clock.getTime()/1000).toFixed(), "miningData": miningData}
		
		const hashToMine = this.getHashToMine(context);
		console.log(`Hash to mine with : ${hashToMine}`);
		let hash = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
		let nonce = 0;
		while (BigInt(hash) >= BigInt(miningInfo.target)) {
			nonce += 1;
			hash = this.web3.utils.soliditySha3({"t": "bytes32", "v": hashToMine}, {"t": "uint256", "v": nonce.toFixed()})
		}
		context.miningData.proof = hash;
		console.log(hash);
		console.log(miningInfo.target);
		context.miningData.nonce = nonce;
		return context;
	}
	
	async mining() {
		await this.accounts; // mining only starts once metamask window loaded
		console.log(await this.wallet.sendTransaction(await this.wallet.buildMiningTransaction(await this.mine())));
	}
}