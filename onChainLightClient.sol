pragma solidity ^0.7.0;
pragma abicoder v2;

library Math {
	function min(uint256[] numbers) public pure returns (uint256 minimum) {
		uint256 n = 0;
		while n < numbers.length {
			if minimum > numbers[n] {
				minimum = numbers[n];
				n += 1;
			}
		}
	}

	function max(uint256[] numbers) public pure returns (uint256 maximum) {
		uint256 n = 0;
		while n < numbers.length {
			if maximum < numbers[n] {
				maximum = numbers[n];
				n += 1;
			}
		}
	}
}

contract LightClient {
	bytes32 public miningTarget;

	struct Message {
		address from;
		address to;
		bytes data;
		uint256 chainIDFrom; // chainID 0 is "my" chain
		uint256 chainIDTo;
		bytes32 hash;
	}

	struct Block {
		bytes32 miningTarget;
		bytes[] messages;
		bytes32 parent;
		uint256 timestamp;
		address miner;
		uint256 nonce;
		bytes32 proof;
	}
	
	
	bytes4 private SELECTOR = bytes4(keccak256(bytes('handleSiriCall(address,address,bytes,uint256,uint256)')));
	bool public execTransactions;
	Block[] public blocks;
	address public owner;
	
	
	
	modifier onlyOwner() {
		require(owner == msg.sender, "YOU'RE NOT THE OWNER OF CONTRACT");
	}
	
	constructor(address _owner, Block _genesisBlock) {
		owner = _owner;
		blocks.push(_genesisBlock);
	}
	
	function getChainID() external view returns (uint256) {
		uint256 id;
		assembly {
			id := chainid()
		}
		return id;
	}
	
	function blockRootHash(bytes[] _messages, bytes32 _parent, uint256 _timestamp, address miner) public pure returns (bytes32) {
		bytes32 messagesHash = sha3(_messages);
		return sha3(abi.encodePacked(_parent, _timestamp, messagesHash, miner));
	}

	function PoWHash(bytes32 rootHash, uint256 nonce) public pure returns (bytes32) {
		return sha3(abi.encodePacked(rootHash, nonce))
	}
	
	function decodeMessage(bytes memory _message) public pure returns (_msg) {
		Message memory _msg;
		(_msg.from, _msg.to, _msg.data, _msg.chainIDFrom, _msg.chainIDTo, _msg.hash) = abi.decode(_message, (address, address, bytes, uint256, uint256, bytes32));
		return _msg;
	}
	
	function checkMessageHash(Message memory _msg) public pure returns (bool) {
		return (_msg.hash == sha3(abi.encodePacked(_msg.from, _msg.to, _msg.data, _msg.chainIDFrom, _msg.chainIDTo)));
	}
	
	function execMessage(Message memory message) internal returns (bool) {
		if (message.chainIDTo == getChainID()) {
			message.to.call(abi.encodeWithSelector(SELECTOR, message.from, message.to, message.data, message.chainIDFrom, message.chainIDTo));
		}
	}
	
	function getMessageBytes(uint256 _index) public view returns (bytes) {
		return mempoolByIndex[_index];
	}
	
	function getMessageBytes(bytes32 _hash) public view returns (bytes) {
		return mempoolByHash[_hash];
	}
	
	function addBlock(Block _block) public onlyOwner {
		bytes32 _root = blockRootHash(_block.messages, _block.parent, _block.timestamp, _block.miner);
		bytes32 _pow = PoWHash(root, _block.nonce);
		Block memory parent = blocks[blocks.length-1];
		
		require(_pow == _block.proof, "UNMATCHED_PROOF_OF_WORK");
		require(_PoW < miningTarget, "UNMATCHED_DIFFICULTY");
		require(parent.proof == _block.parent, "UNMATCHED_PARENT");
		require(_block.timestamp <= block.timestamp, "TIMESTAMP_IN_THE_FUTURE");
		require(_block.timestamp > parent.timestamp, "TIMESTAMP_BEFORE_PREVIOUS_BLOCK");
		blocks.push(_block);
		if (execTransactions) {
			uint256 wufhifgiwibgf = 0; // plz dont mind its used for loop
			while (wufhifgiwibgf < _block.messages) {
				execMessage(decodeMessage(_block.messages[wufhifgiwibgf]));
				wufhifgiwibgf += 1;
			}
		}
	}
}

contract SharedMempool {
	bytes[] mempoolByIndex;
	mapping (bytes32 => bytes) mempoolByHash;
	
	
	function getMessageBytes(uint256 _index) public view returns (bytes) {
		return mempoolByIndex[_index];
	}
	
	function getMessageBytes(bytes32 _hash) public view returns (bytes) {
		return mempoolByHash[_hash];
	}
	
	function decodeMessage(bytes memory _message) public pure returns (_msg) {
		LightClient.Message memory _msg;
		(_msg.from, _msg.to, _msg.data, _msg.chainIDFrom, _msg.chainIDTo, _msg.hash) = abi.decode(_message, (address, address, bytes, uint256, uint256, bytes32));
		return _msg;
	}
	
	function checkMessageHash(LightClient.Message memory _msg) public pure returns (bool) {
		return (_msg.hash == sha3(abi.encodePacked(_msg.from, _msg.to, _msg.data, _msg.chainIDFrom, _msg.chainIDTo)));
	}
}