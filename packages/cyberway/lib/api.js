import Token from "@walletpack/core/models/Token";
import {Blockchains} from "@walletpack/core/models/Blockchains";


let networks, hosts;

function promiseWithTimeout(timeout, promise) {
	return Promise.race([
		new Promise(resolve => setTimeout(() => resolve(null), timeout)),
		promise
	]);
}

function fetchJsonRpc(endpoint, method, params) {
	return fetch(endpoint, {
		method: 'POST',
		headers: {'Content-type': 'application/json-rpc'},
		body: JSON.stringify({jsonrpc: "2.0", method, params,
			// id: 4,
		})
	}).then(r => r.json()).then(r => r.result);
}

export default class LightAPI {

	static async cacheEndpointsAndNetworks(){
		// to make things simple, just hardcode for now
		const endpoints = {
			"api-endpoints": {
				"https://wallet-api.cyberway.io": {
					country: ["?"],
					continent: "ANY",
					admin: "?@cyberway.io",
					networks: ["cyber", "cybertest"]
				},
				"http://localhost:3030": {
					country: ["?"],
					continent: "ANY",
					admin: "me@zxcat.ru",
					networks: ["cyber", "cybertest"]
				}
			},
			networks: {
				cyber: {
					chainid: "591c8aa5cade588b1ce045d26e5f2a162c52486262bd2d7abcb7fa18247e17ec",
					description: "CyberWay Mainnet",
					systoken: "CYBER",
					decimals: 4,
					production: 1
				},
				cybertest: {
					chainid: "?",
					description: "CyberWay Testnet",
					systoken: "CYBER",
					decimals: 4,
					production: 0
				}
			},
			version: "0.0001"
		};
		// return fetch(`https://endpoints.light.xeos.me/endpoints.json`).catch(() => null).then(x => x.json()).then(x => {
		return (x => {
			hosts = Object.keys(x['api-endpoints']).reduce((acc, host) => {
				x['api-endpoints'][host].networks.map(network => {
					if(!acc[network]) acc[network] = host;
				});
				return acc;
			}, {});
			networks = Object.keys(x['networks']).reduce((acc, network) => {
				acc[x['networks'][network].chainid] = network;
				return acc;
			}, {});
			return true;
		})(endpoints);
	}

	static async getNetworks(){
		if(!networks) await LightAPI.cacheEndpointsAndNetworks();
		return networks;
	}

	static async networkString(network){
		const networks = await this.getNetworks();
		if(!networks) return null;
		return networks[network.chainId];
	}

	static async fetchBalances(account, network, parseResults){
		const networkString = await this.networkString(network);
		if(!networkString) return null;
		if(!hosts[networkString]) return null;

		// if(cache[account.unique()]) return parseResults(cache[account.unique()]);

		return await promiseWithTimeout(8000,
			// fetch(`${hosts[networkString]}/api/balances/${networkString}/${account.name}`).then(r => r.json()).then(res => {
			fetchJsonRpc(hosts[networkString], "getAccountBalances", {account: account.name}).then(res => {
				return parseResults(res.result);
			}).catch(err => {
				console.log('err', err);
				return null;
			})
		);
	}

	static async balancesFor(account, network){
		const parseResults = res => {
			return res.balances.map(balance => {
				return Token.fromJson({
					blockchain:Blockchains.CYBER,
					contract:balance.contract,
					symbol:balance.currency,
					name:balance.currency,
					amount:balance.amount,
					decimals:balance.decimals,
					chainId:network.chainId
				})
			});
		};

		return this.fetchBalances(account, network, parseResults);
	}

	static async getAccountsFromPublicKey(publicKey, network){
		const networkString = await this.networkString(network);
		if(!networkString) return null;
		if(!hosts[networkString]) return null;

		return await promiseWithTimeout(5000,
			// fetch(`${hosts[networkString]}/api/key/${publicKey}`).then(r => r.json()).then(res => {
			fetchJsonRpc(hosts[networkString], "getAccountsByAuth", {key: publicKey}).then(res => {
				if(!res[networkString]) return null;
				const rawAccounts = res[networkString].accounts;
				let accounts = [];
				Object.keys(rawAccounts).map(name => {
					rawAccounts[name]
						.filter(acc => acc.auth.keys.some(({pubkey}) => pubkey === publicKey))
						.map(acc => accounts.push({name, authority: acc.perm}))
				});

				return accounts;
			}).catch(err => {
				console.error('err', err);

				let fake = {cyber:{accounts:{}}};
				if (publicKey === 'GLS56NR492EjELXuQayvnUV945FDZq1CGqsGFTstCjKSxHiaEVdwb') {
					fake = {cyber:{accounts:{"xhdtonx5zvnd":[
						{"perm":"test","auth":{
							"keys":[
								{"weight":1,"pubkey":"GLS56NR492EjELXuQayvnUV945FDZq1CGqsGFTstCjKSxHiaEVdwb"},
								{"weight":1,"pubkey":"GLS6gMPrLguKgDcJBRrE4hXVJgtd2ffvxM2YvkzDdfECWD9caMrTJ"}],
							"accounts":[]},"threshold":2}
					]}}};
				} else if (publicKey === 'GLS61TdJkH5k59LJPBvVSUC2gbfMnGZGz6qoEXfjqSXfhYttwvjWH') {
					fake = {cyber:{accounts:{
						"xhdtonx5zvnd":[{"perm":"posting","auth":{"keys":[{"weight":1,"pubkey":"GLS61TdJkH5k59LJPBvVSUC2gbfMnGZGz6qoEXfjqSXfhYttwvjWH"}],"accounts":[]},"threshold":1}],
						"zzzzzzzzzzzz":[{"perm":"posting","auth":{"keys":[{"weight":1,"pubkey":"GLS61TdJkH5k59LJPBvVSUC2gbfMnGZGz6qoEXfjqSXfhYttwvjWH"}],"accounts":[]},"threshold":1}]
					}}};
				} else if (publicKey === 'GLS7Fv54EXHczc4SkTSZAGRpY96eaw4rxocCt452YatUQBFV62dt4') {
					fake = {cyber:{accounts:{
						"zxcat":[
							{"perm":"active","auth":{
								"keys":[{"weight":1,"pubkey":"GLS5oDRTecn2SNXbYTs3WhXFDQoRLmVXoT6GPPsPndzjaHfUXs41D"}],
								"accounts":[]},"threshold":1}],
						"xhdtonx5zvnd":[
							{"perm":"active","auth":{
								"keys":[{"weight":1,"pubkey":"GLS7Fv54EXHczc4SkTSZAGRpY96eaw4rxocCt452YatUQBFV62dt4"}],
								"accounts":[]},"threshold":1},
							{"perm":"prod","auth":{
								"keys":[{"weight":1,"pubkey":"GLS7Fv54EXHczc4SkTSZAGRpY96eaw4rxocCt452YatUQBFV62dt4"}],
								"accounts":[]},"threshold":1}],
						"zzzzzzzzzzzz":[
							{"perm":"active","auth":{
								"keys":[{"weight":1,"pubkey":"GLS7Fv54EXHczc4SkTSZAGRpY96eaw4rxocCt452YatUQBFV62dt4"}],
								"accounts":[]},"threshold":1}],
						"kkkkkkkkkkkk":[{
							"perm":"active","auth":{
								"keys":[{"weight":1,"pubkey":"GLS7Fv54EXHczc4SkTSZAGRpY96eaw4rxocCt452YatUQBFV62dt4"}],
								"accounts":[{"actor":"zzzzzzzzzzzz","permission":"active","weight":1}]},"threshold":1}],
						"collectibles":[
							{"perm":"active","auth":{
								"keys":[{"weight":1,"pubkey":"GLS7Fv54EXHczc4SkTSZAGRpY96eaw4rxocCt452YatUQBFV62dt4"}],"accounts":[]},"threshold":1}]
					}}};
				}
				console.log('FAKE', fake);
				if(!fake[networkString]) return null;
				const rawAccounts = fake[networkString].accounts;
				let accounts = [];
				Object.keys(rawAccounts).map(name => {
					rawAccounts[name]
						.filter(acc => acc.auth.keys.some(({pubkey}) => pubkey === publicKey))
						.map(acc => accounts.push({name, authority: acc.perm}))
				});
				return accounts;
			})
		);
	}

}
