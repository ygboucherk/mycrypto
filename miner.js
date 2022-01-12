function getHashToMine(miningTarget, parent, timestamp, messages, miner) {
	messagesHash = web3.utils.soliditySha3({"t": "bytes", "v": toHex(messages)});
	return web3.utils.soliditySha3({"t": "bytes32", "v": miningTarget}, {"t": "bytes32", "v": parent}, {"t": "uint256", "v": timestamp}, {"t": "bytes32", "v": messagesHash}, {"t": "address", "v": miner});
}

getHashToMine("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0x5575a56d1a14e45af6982ca03adfbe26b8af36b509ee1add4ac800e9617ea7d7", 1642008475, "0", "0x3f119cef08480751c47a6f59af1ad2f90b319d44")