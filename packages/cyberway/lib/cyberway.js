import Plugin from                  '@walletpack/core/plugins/Plugin';
import * as PluginTypes from        '@walletpack/core/plugins/PluginTypes';
import {Blockchains} from           '@walletpack/core/models/Blockchains'
import Network from                 '@walletpack/core/models/Network'
import Account from                 '@walletpack/core/models/Account'
import KeyPairService from          '@walletpack/core/services/secure/KeyPairService'
import ObjectHelpers from           '@walletpack/core/util/ObjectHelpers'
import * as Actions from            '@walletpack/core/models/api/ApiActions';
import * as StoreActions from       '@walletpack/core/store/constants'
import Token from                   "@walletpack/core/models/Token";
import AccountAction from           "@walletpack/core/models/AccountAction";
import AccountService from          "@walletpack/core/services/blockchain/AccountService";
import HistoricAction from          "@walletpack/core/models/histories/HistoricAction";
import StoreService from            "@walletpack/core/services/utility/StoreService";
import EventService from            "@walletpack/core/services/utility/EventService";
import SigningService from          "@walletpack/core/services/secure/SigningService";
import ecc from 'eosjs-ecc';
import { Api, JsonRpc } from 'cyberwayjs';
import * as numeric from "cyberwayjs/dist/eosjs-numeric";

import LightAPI from './api';

export const TextEncoder = require('util') ? require('util').TextEncoder : require('text-encoding') ? require('text-encoding').TextEncoder : global.TextEncoder;
export const TextDecoder = require('util') ? require('util').TextDecoder : require('text-encoding') ? require('text-encoding').TextDecoder : global.TextDecoder;
export const encoderOptions = TextEncoder ? {textEncoder:new TextEncoder(), textDecoder:new TextDecoder()} : {};

const getCwjsApi = rpc => {
	let params = rpc ? {rpc} : {};
	if(TextEncoder) params = Object.assign(params, encoderOptions)

	return new Api(params)
}

export const cwjsUtil = getCwjsApi();

const MAINNET_CHAIN_ID = '591c8aa5cade588b1ce045d26e5f2a162c52486262bd2d7abcb7fa18247e17ec';
const KEY_PREFIX = 'GLS';



const fetchPostParams = (params) => ({ method:"POST", body:JSON.stringify(params) })
const getChainData = (network, route, params) => fetch(`${network.fullhost()}/v1/chain/${route}`, fetchPostParams(params)).then(x => x.json())
const getTableRows = (network, params) => getChainData(network, 'get_table_rows', params)
const getHistoryData = (network, route, params) => fetch(`${network.fullhost()}/v1/history/${route}`, fetchPostParams(params)).then(x => x.json())




const getAccountsFromPublicKey = async (publicKey, network, fallbackToChain = false) => {
	if(!fallbackToChain && await LightAPI.networkString(network)){
		const accountsFromApi = await LightAPI.getAccountsFromPublicKey(publicKey, network);
		if(!accountsFromApi) return getAccountsFromPublicKey(publicKey, network, true);
		else return accountsFromApi;
	}
	alert('getAccountsFromPublicKey fallback', publicKey, network, fallbackToChain);
	return Promise.race([
		new Promise(resolve => setTimeout(() => resolve([]), 20000)),
		new Promise(async (resolve, reject) => {
			getHistoryData(network, 'get_key_accounts', {public_key:publicKey}).then(res => {
				if(!res || !res.hasOwnProperty('account_names')){ resolve([]); return false; }
				const {account_names} = res;

				Promise.all(account_names.map(async name => {
					return await getChainData(network, 'get_account', {account_name:name}).catch(e => resolve([]));
				})).then(multires => {
					let accounts = [];
					multires.map(account => {
						account.permissions.map(perm => {
							if(!!perm.required_auth.keys.find(x => x.key === publicKey)) {
								accounts.push({name: account.account_name, authority: perm.perm_name})
							}
						});
					});
					resolve(accounts)
				}).catch(e => resolve([]));
			}).catch(e => resolve([]));
		})
	])
};



const parseErrorMessage = (result) => {

	let error;
	try { error = JSON.parse(error).error.details[0].message }
	catch(e){ error = result; }

	const assertErr = 'assertion failure with message:';
	if(error && error.toString().indexOf(assertErr) > -1){
		error = error.toString().replace(assertErr, '').trim()
	}

	return error;
}


const EXPLORER_URL = 'https://explorer.cyberway.io';
const EXPLORER = {
	"name":"CyberWay Block Explorer",
	"account":`${EXPLORER_URL}/account/{x}`,
	"transaction":`${EXPLORER_URL}/trx/{x}`,
	"block":`${EXPLORER_URL}/block/{x}`
};


export default class CYBER extends Plugin {

	constructor(){ super(Blockchains.CYBER, PluginTypes.BLOCKCHAIN_SUPPORT); }

	async createSharedSecret(publicKey, otherPublicKey, privateKey = null){
		if (!privateKey) privateKey = await KeyPairService.publicToPrivate(publicKey);
		if (!privateKey) return;

		return ecc.PrivateKey(privateKey).getSharedSecret(otherPublicKey);
	}

	signatureProvider(accounts, reject, prompt = true){
		console.warn('signatureProvider');
		const isSingleAccount = accounts instanceof Account;
		return {
			getAvailableKeys:async () => (isSingleAccount ? [accounts] : accounts).map(x => x.publicKey),
			sign:async (transaction) => this.signerWithPopup({ transaction }, accounts, reject, prompt).then(signatures => {
				return {signatures, serializedTransaction:transaction.serializedTransaction}
			})
		}
	}

	getSignableApi(accounts, reject, prompt = true, signatureProvider = null){
		console.warn('getSignableApi');
		const isSingleAccount = accounts instanceof Account;
		const rpc = new JsonRpc((isSingleAccount ? accounts.network() : accounts[0].network()).fullhost());
		let params = {rpc, signatureProvider:signatureProvider || this.signatureProvider(accounts, reject, prompt)};
		if(TextEncoder) params = Object.assign(rpc, {textEncoder:new TextEncoder(), textDecoder:new TextDecoder()});
		return new Api(params);
	}












	bip(){ console.log('BIP'); return `44'/194'/7'/7/`}
	bustCache(){  }
	defaultExplorer(){ return EXPLORER; }
	accountFormatter(account){ 		console.warn('accountFormatter', account);
	return `${account.name}@${account.authority}` } // TODO: fetch username
	returnableAccount(account){ return { name:account.name, authority:account.authority, publicKey:account.publicKey, blockchain:Blockchains.CYBER }}

	contractPlaceholder(){ 		console.warn('contractPlaceholder');
	return 'cyber.token'; }

	checkNetwork(network){
		console.warn('checkNetwork', network);
		return Promise.race([
			new Promise(resolve => setTimeout(() => resolve(null), 2000)),
			fetch(`${network.fullhost()}/v1/chain/get_info`).then(() => true).catch(() => false),
		])
	}

	getEndorsedNetwork(){
		return new Network('CyberWay Mainnet', 'https', 'scatter.cyberway.io', 443, Blockchains.CYBER, MAINNET_CHAIN_ID)
	}

	isEndorsedNetwork(network){
		console.warn('isEndorsedNetwork', network);
		return network.blockchain === Blockchains.CYBER && network.chainId === MAINNET_CHAIN_ID;
	}

	async getChainId(network){
		console.warn('getChainId', network);
		return getChainData(network, 'get_info', {}).then(x => x.chain_id || '').catch(() => '');
	}

	usesResources(){ return false; }
	hasAccountActions(){ return false; }

	async proxyVote(account, proxyAccount, prompt = false){
		console.warn('proxyVote', account, proxyAccount, prompt);
		return alert('not implemented');
	}
	// 	return new Promise(async (resolve, reject) => {
	// 		const cw = this.getSignableApi(account, reject, prompt);
	// 		await cw.transact({
	// 			actions:[{
	// 				account: 'cyber',
	// 				name:'voteproducer',
	// 				authorization: [{
	// 					actor: account.sendable(),
	// 					permission: account.authority,
	// 				}],
	// 				data:{
	// 					voter: account.name,
	// 					proxy: proxyAccount,
	// 					producers:[],
	// 				},
	// 			}]
	// 		}, {blocksBehind: 3, expireSeconds: 30})
	// 			.then(trx => {
	// 				const history = new HistoricAction(account, 'proxy', trx.transaction_id);
	// 				StoreService.get().dispatch(StoreActions.DELTA_HISTORY, history);
	// 				resolve(trx.transaction_id)
	// 			})
	// 			.catch(res => {
	// 				reject({error:parseErrorMessage(res)});
	// 			})
	// 	})
	// }

	async changePermissions(account, keys){
		console.warn('changePermissions', account, keys);
		if(!keys) return;
		return new Promise(async (resolve, reject) => {
			const cw = this.getSignableApi(account, reject);
			const actions = Object.keys(keys).map(permission => {
				if(!keys[permission] || !keys[permission].length) return;

				const keyOrAccount = keys[permission];
				let auth = {
					accounts:[],
					keys:[],
					threshold:1,
					waits:[],
				};

				// Public Key
				if(this.validPublicKey(keyOrAccount)) auth.keys.push({
					key:keyOrAccount,
					weight:1
				});

				// Account
				else {
					const [actor, perm] = keyOrAccount.split('@');
					auth.accounts.push({
						actor,
						permission: perm || 'active'
					})
				}

				// const parent = permission === 'owner' ? '' : 'owner'; // !!! why?
				const parent = {owner: '', active: 'owner'}[permission] || 'active';

				return {
					account: 'cyber',
					name:'updateauth',
					authorization: [{
						actor: account.sendable(),
						permission,
					}],
					data:{
						account:account.name,
						permission,
						parent,
						auth,
					},
				}
			}).filter(x => !!x);

			return cw.transact({actions},{blocksBehind: 3, expireSeconds: 30})
				.catch(res => {
					reject({error:parseErrorMessage(res)})
				})
				.then(async res => {

					const authorities = Object.keys(keys).filter(x => keys[x] && keys[x].length);
					const accounts = StoreService.get().state.scatter.keychain.accounts.filter(x => x.identifiable() === account.identifiable() && authorities.includes(x.authority));
					await AccountService.removeAccounts(accounts);

					const addAccount = async (keypair, authority) => {
						const acc = account.clone();
						acc.publicKey = keypair.publicKeys.find(x => x.blockchain === Blockchains.CYBER).key,
							acc.keypairUnique = keypair.unique();
						acc.authority = authority;
						return AccountService.addAccount(acc);
					};

					const activeKeypair = StoreService.get().state.scatter.keychain.getKeyPairByPublicKey(keys.active);
					const ownerKeypair = StoreService.get().state.scatter.keychain.getKeyPairByPublicKey(keys.owner);
					if(activeKeypair) await addAccount(activeKeypair, 'active');
					if(ownerKeypair) await addAccount(ownerKeypair, 'owner');
					// !! TODO: custom permissions
					const history = new HistoricAction(account, 'permissions', res.transaction_id);
					StoreService.get().dispatch(StoreActions.DELTA_HISTORY, history);
					resolve(res.transaction_id)
				});
		})

	}

	accountActions(account, callback){
		console.warn('accountActions', account, callback);
		return [
			new AccountAction("unlink_account", () => callback(account)),
			new AccountAction("change_permissions", () => callback(account), true),
			new AccountAction("proxy_vote", () => callback(account)),
			new AccountAction("create_account", () => () => callback(account)),
		];
	}

	accountsAreImported(){ return true; }

	getImportableAccounts(keypair, network){
		console.warn('getImportableAccounts', keypair, network);
		return new Promise((resolve, reject) => {
			let publicKey = keypair.publicKeys.find(x => x.blockchain === Blockchains.CYBER);
			if(!publicKey) return resolve([]);
			publicKey = publicKey.key;
			getAccountsFromPublicKey(publicKey, network).then(accounts => {
				resolve(accounts.map(account => Account.fromJson({
					name:account.name,
					authority:account.authority,
					publicKey,
					keypairUnique:keypair.unique(),
					networkUnique:network.unique(),
				})))
			}).catch(e => resolve([]));
		})
	}

	isValidRecipient(name){ return /(^[a-z1-5.]{1}([a-z1-5.]{0,10}[a-z1-5])?$)/g.test(name); }

	privateToPublic(privateKey, prefix){ try {
		console.log('privateToPublic', privateKey, prefix, ecc.PrivateKey(privateKey).toPublic().toString(prefix));
		return ecc.PrivateKey(privateKey).toPublic().toString(prefix || KEY_PREFIX);
	} catch(e) { return console.error(e); } }

	validPrivateKey(privateKey){ try {
		return privateKey.length >= 50 && ecc.isValidPrivate(privateKey);
	} catch(e){ return console.error(e); } };

	validPublicKey(publicKey, prefix){
		try {
			return ecc.PublicKey.fromStringOrThrow(publicKey, prefix || KEY_PREFIX);
		} catch(e){
			return false;
		}
	}

	bufferToHexPrivate(buffer){
		return ecc.PrivateKey.fromBuffer(Buffer.from(buffer)).toString()
	}
	hexPrivateToBuffer(privateKey){
		return new ecc.PrivateKey(privateKey).toBuffer();
	}

	bufferToHexPublicKeyOrAddress(buffer){
		return ecc.PublicKey.fromBuffer(Buffer.from(buffer)).toString()
	}

	actionParticipants(payload){
		return ObjectHelpers.flatten(
			payload.messages
				.map(message => message.authorization
					.map(auth => `${auth.actor}@${auth.permission}`))
		);
	}

	async accountData(account, network = null, accountName = null){
		console.warn('accountData', account, network, accountName);
		const getAccount = () => {
			return fetch(`${(network || account.network()).fullhost()}/v1/chain/get_account`, {
				method: 'POST',
				body: JSON.stringify({account_name:accountName || account.name})
			})
				.then(res => res.json())
		};

		return Promise.race([
			new Promise(resolve => setTimeout(() => resolve(null), 2000)),
			getAccount()
		])
	}

	// hasUntouchableTokens(){ return true; }

	// async untouchableBalance(account){
	// 	// TODO: implement safe info
	// 	const getCpuAndNet = async () => {
	// 		const accData = await this.accountData(account).catch(() => null);
	// 		if(!accData || !accData.hasOwnProperty('self_delegated_bandwidth') || !accData.self_delegated_bandwidth) return null;
	// 		const token = account.network().systemToken().clone();
	// 		token.amount = parseFloat(parseFloat(accData.self_delegated_bandwidth.cpu_weight.split(' ')[0]) + parseFloat(accData.self_delegated_bandwidth.net_weight.split(' ')[0])).toFixed(token.decimals);
	// 		token.unusable = 'CPU / NET';
	// 		return token;
	// 	}

	// 	const getRex = async () => {
	// 		if(account.network().chainId !== MAINNET_CHAIN_ID) return null;
	// 		return fetch(`${account.network().fullhost()}/v1/chain/get_table_rows`, {
	// 			method:"POST",
	// 			body:JSON.stringify({
	// 				code: "eosio",
	// 				index_position: 1,
	// 				json: true,
	// 				limit: 1,
	// 				lower_bound: account.name,
	// 				scope: "eosio",
	// 				table: "rexbal",
	// 			})
	// 		}).then(x => x.json()).then(result => {
	// 			if(!result) return null;
	// 			const rex = result.rows[0];
	// 			if(rex.owner !== account.name) return null;
	// 			const token = account.network().systemToken().clone();
	// 			token.symbol = 'REX';
	// 			token.amount = parseFloat(rex.rex_balance.split(' ')[0]).toFixed(4);
	// 			token.unusable = 'REX';
	// 			return token;
	// 		}).catch(() => null)
	// 	}

	// 	const cpunet = await getCpuAndNet();
	// 	const rex = await getRex();
	// 	return [cpunet, rex].filter(x => !!x);
	// }

	async balanceFor(account, token){
		console.warn('balanceFor', account, token);
		const balances = await Promise.race([
			new Promise(resolve => setTimeout(() => resolve([]), 10000)),
			getTableRows(account.network(), {
				json: true,
				code: token.contract,
				scope: account.name,
				table: 'accounts',
				limit: 500,
				index: 'primary'
			}).then(res => res.rows).catch(() => [])
		]);

		const row = balances.find(row => row.balance.split(" ")[1].toLowerCase() === token.symbol.toLowerCase());
		return row ? row.balance.split(" ")[0] : 0;
	}

	async balancesFor(account, tokens, fallback = false){
		console.warn('balancesFor', account, tokens, fallback);
		if(!fallback && await LightAPI.networkString(account.network())){
			const balances = await LightAPI.balancesFor(account, account.network());
			if(!balances) return this.balancesFor(account, tokens, true);
			const blacklist = StoreService.get().state.scatter.settings.blacklistTokens.filter(x => x.blockchain === Blockchains.CYBER).map(x => x.unique());
			return balances.filter(x => !blacklist.includes(x.unique()));
		}


		return (await Promise.all(tokens.map(async token => {
			const t = token.clone();
			t.amount = await this.balanceFor(account, token);
			t.chainId = account.network().chainId;
			return t;
		})));
	}

	defaultDecimals(){ return 4; }
	defaultToken(){ return new Token(Blockchains.CYBER, 'cyber.token', 'CYBER', 'CYBER', this.defaultDecimals(), MAINNET_CHAIN_ID) }

	async createAccount(account, name, owner, active, used){
		return new Promise(async (resolve, reject) => {
			const coreSymbol = account.network().systemToken().symbol;

			// const net = (used/4).toFixed(account.network().systemToken().decimals);
			// const cpu = (used-net).toFixed(account.network().systemToken().decimals);
			// if(net <= 0 || cpu <= 0) return reject("Invalid Resources");
			if (used < 0) return reject("Invalid Resources");
			const delegate = used.toFixed(account.network().systemToken().decimals);

			const cw = this.getSignableApi(account, reject);

			const authorization = [{
				actor: account.sendable(),
				permission: account.authority,
			}];

			const keyPath = key => ({
				threshold: 1,
				keys: [{key, weight: 1}],
				accounts: [],
				waits: []
			});

			const actions = [{
				account: 'cyber',
				name:'newaccount',
				authorization,
				data:{
					creator: account.name,
					name: name,
					owner: keyPath(owner),
					active: keyPath(active)
				},
			}];
			if (used > 0) {
				actions.push({
					account: 'cyber.stake',
					name:'delegateuse',
					authorization,
					data:{
						grantor_name: account.name,
						recipient_name: name,
						quantity: `${delegate} ${coreSymbol}`,
					},
				})
			}
			await cw.transact({actions}, {blocksBehind: 3, expireSeconds: 30})
				.then(trx => resolve(trx.transaction_id))
				.catch(res => {
					reject({error:parseErrorMessage(res)});
				});
		})
	}


	// async stakeOrUnstake(account, cpu, net, staking = true, prompt = true){
	// 	return new Promise(async (resolve, reject) => {
	// 		const cw = this.getSignableApi(account, reject, prompt);

	// 		const name = staking ? 'delegatebw' : 'undelegatebw';
	// 		let data = staking ? {
	// 			from: account.name,
	// 			receiver: account.name,
	// 			stake_net_quantity:net,
	// 			stake_cpu_quantity:cpu,
	// 			transfer:false
	// 		} : {
	// 			from: account.name,
	// 			receiver: account.name,
	// 			unstake_net_quantity:net,
	// 			unstake_cpu_quantity:cpu,
	// 		};

	// 		await cw.transact({
	// 			actions:[{
	// 				account: 'cyber.stake',
	// 				name,
	// 				authorization: [{
	// 					actor: account.sendable(),
	// 					permission: account.authority,
	// 				}],
	// 				data,
	// 			}]
	// 		}, {
	// 			blocksBehind: 3,
	// 			expireSeconds: 30,
	// 		})
	// 			.then(trx => resolve(trx.transaction_id))
	// 			.catch(res => {
	// 				reject({error:parseErrorMessage(res)});
	// 			})
	// 	})
	// }

	async transfer({account, to, amount, token, memo, promptForSignature = true}){
		if(!this.isValidRecipient(to)) return {error:'Invalid recipient account name'};
		amount = parseFloat(amount).toFixed(token.decimals);
		const {contract, symbol} = token;
		const amountWithSymbol = amount.indexOf(symbol) > -1 ? amount : `${amount} ${symbol}`;

		return new Promise(async (resolve, reject) => {
			const cw = this.getSignableApi(account, reject, promptForSignature);

			const result = await cw.transact({
				actions:[{
					account: contract,
					name:'transfer',
					authorization: [{
						actor: account.sendable(),
						permission: account.authority,
					}],
					data:{
						from: account.name,
						to,
						quantity:amountWithSymbol,
						memo:memo,
					},
				}]
			},
			{blocksBehind: 3, expireSeconds: 30}
			)
				.catch(res => resolve({error:parseErrorMessage(res)}))
				.then(result => resolve(result))
		})
	}



	async signerWithPopup(payload, accounts, rejector, prompt = true){
		console.warn('signerWithPopup', payload, accounts, rejector, prompt);
		return new Promise(async resolve => {
			if(accounts instanceof Account){
				accounts = [accounts];
			}

			payload.messages = await this.requestParser(payload, Network.fromJson(accounts[0].network()));
			if(!payload.messages) return rejector({error:'Error re-parsing transaction buffer'});
			payload.identityKey = StoreService.get().state.scatter.keychain.identities[0].publicKey;
			payload.participants = accounts;
			payload.network = accounts[0].network();
			payload.origin = 'Scatter';
			const request = {
				payload,
				origin:payload.origin,
				blockchain:Blockchains.CYBER,
				requiredFields:{},
				type:Actions.SIGN,
				id:1,
			}

			const sign = async () => {
				let signatures = [];
				for(let i = 0; i < accounts.length; i++){
					let account = accounts[i];
					signatures.push(await SigningService.sign(payload.network, KeyPairService.isHardware(account.publicKey) ? payload : {data:payload.buf}, account.publicKey, true, false));

					if(signatures.length !== i+1) return rejector({error:'Could not get signature'});
				}

				signatures = signatures.reduce((acc,x) => {
					if(!acc.includes(x)) acc.push(x);
					return acc;
				}, []);

				return signatures;
			}

			if(!prompt) return resolve(await sign());

			EventService.emit('popout', request).then( async ({result}) => {
				if(!result || (!result.accepted || false)) return rejector({error:'Could not get signature'});

				resolve(await sign());
			}, true);
		})
	}

	async signer(payload, publicKey, arbitrary = false, isHash = false, privateKey = null){
		if (!privateKey) privateKey = await KeyPairService.publicToPrivate(publicKey);
		if (!privateKey) return;

		if (typeof privateKey !== 'string') privateKey = this.bufferToHexPrivate(privateKey);

		if (arbitrary && isHash) return ecc.Signature.signHash(payload.data, privateKey).toString();
		return ecc.sign(Buffer.from(arbitrary ? payload.data : payload.buf, 'utf8'), privateKey);
	}




	transactionContracts(transaction){
		console.warn('transactionContracts', transaction);
		return transaction.hasOwnProperty('actions')
			? ObjectHelpers.distinct(transaction.actions.map(action => action.account))
			: ObjectHelpers.distinct(transaction.abis.map(x => {
				if(x.hasOwnProperty('account_name')) return x.account_name;
				return x.accountName;
			}));
	}

	async fetchAbis(network, contracts, fallbackToChain = false){
		console.warn('fetchAbis', network, contracts, fallbackToChain);
		try {
			return await Promise.all(contracts.map(async account => {
				const chainAbi = await getChainData(network, `get_raw_abi`, {account_name:account}).catch(() => null).then(x => x.abi);
				if(!chainAbi) return console.error(`Could not fetch ABIs for ${account}`);
				const rawAbi = numeric.base64ToBinary(chainAbi);
				const abi = cwjsUtil.rawAbiToJson(rawAbi);
				return {account, rawAbi, abi};
			}));
		} catch(e){
			console.error(e);
			return null;
		}
	}

	async requestParser(payload, network){
		console.warn('requestParser', payload, network);
		try {
			const {transaction} = payload;
			const api = getCwjsApi();
			const contracts = this.transactionContracts(transaction);
			const abis = await this.fetchAbis(network, contracts);
			abis.map(({account, rawAbi, abi}) => api.cachedAbis.set(account, { rawAbi, abi }));

			const buffer = Buffer.from(transaction.serializedTransaction, 'hex');
			const parsed = await api.deserializeTransactionWithActions(buffer);
			parsed.actions.map(x => {
				x.code = x.account;
				x.type = x.name;
			});

			payload.buf = Buffer.concat([
				Buffer.from(transaction.chainId, "hex"),         // Chain ID
				buffer,                                          // Transaction
				Buffer.from(new Uint8Array(32)),                 // Context free actions
			]);

			payload.transaction.parsed = Object.assign({}, parsed);
			payload.transaction.parsed.actions = await api.serializeActions(parsed.actions);
			delete payload.transaction.abis;

			return parsed.actions;
		} catch(e){
			console.error(e);
			return null;
		}

	}
}
