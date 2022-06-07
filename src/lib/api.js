import UnichainJS from 'index';
import utils from 'utils';
import {keccak256, toUtf8Bytes, recoverAddress, SigningKey} from 'utils/ethersUtils';
import {ADDRESS_PREFIX} from 'utils/address';
import Validator from "../paramValidator";
import injectpromise from 'injectpromise';

const UNW_MESSAGE_HEADER = '\x19UNICHAIN Signed Message:\n32';
const ETH_MESSAGE_HEADER = '\x19Ethereum Signed Message:\n32';

function toHex(value) {
    return UnichainJS.address.toHex(value);
}

export default class Api {
    constructor(unichainJS = false) {
        if (!unichainJS || !unichainJS instanceof UnichainJS)
            throw new Error('Expected instance of UnichainJS');

        this.unichainJS = unichainJS;
        this.injectPromise = injectpromise(this);
        this.cache = {
            contracts: {}
        }
        this.validator = new Validator(unichainJS);
    }

    _parseToken(token) {
        return {
            ...token,
            name: this.unichainJS.toUtf8(token.name),
            abbr: token.abbr && this.unichainJS.toUtf8(token.abbr),
            description: token.description && this.unichainJS.toUtf8(token.description),
            url: token.url && this.unichainJS.toUtf8(token.url)
        };
    }

    getCurrentBlock(callback = false) {
        if (!callback)
            return this.injectPromise(this.getCurrentBlock);

        this.unichainJS.fullNode.request('wallet/getnowblock').then(block => {
            callback(null, block);
        }).catch(err => callback(err));
    }

    getConfirmedCurrentBlock(callback = false) {
        if (!callback)
            return this.injectPromise(this.getConfirmedCurrentBlock);

        this.unichainJS.solidityNode.request('walletsolidity/getnowblock').then(block => {
            callback(null, block);
        }).catch(err => callback(err));
    }

    getBlock(block = this.unichainJS.defaultBlock, callback = false) {
        if (utils.isFunction(block)) {
            callback = block;
            block = this.unichainJS.defaultBlock;
        }

        if (!callback)
            return this.injectPromise(this.getBlock, block);

        if (block === false)
            return callback('No block identifier provided');

        if (block == 'earliest')
            block = 0;

        if (block == 'latest')
            return this.getCurrentBlock(callback);

        if (isNaN(block) && utils.isHex(block))
            return this.getBlockByHash(block, callback);

        this.getBlockByNumber(block, callback);
    }

    getBlockByHash(blockHash, callback = false) {
        if (!callback)
            return this.injectPromise(this.getBlockByHash, blockHash);

        this.unichainJS.fullNode.request('wallet/getblockbyid', {
            value: blockHash
        }, 'post').then(block => {
            if (!Object.keys(block).length)
                return callback('Block not found');

            callback(null, block);
        }).catch(err => callback(err));
    }

    getBlockByNumber(blockID, callback = false) {
        if (!callback)
            return this.injectPromise(this.getBlockByNumber, blockID);

        if (!utils.isInteger(blockID) || blockID < 0)
            return callback('Invalid block number provided');

        this.unichainJS.fullNode.request('wallet/getblockbynum', {
            num: parseInt(blockID)
        }, 'post').then(block => {
            if (!Object.keys(block).length)
                return callback('Block not found');

            callback(null, block);
        }).catch(err => callback(err));
    }

    getBlockTransactionCount(block = this.unichainJS.defaultBlock, callback = false) {
        if (utils.isFunction(block)) {
            callback = block;
            block = this.unichainJS.defaultBlock;
        }

        if (!callback)
            return this.injectPromise(this.getBlockTransactionCount, block);

        this.getBlock(block).then(({transactions = []}) => {
            callback(null, transactions.length);
        }).catch(err => callback(err));
    }

    getTransactionFromBlock(block = this.unichainJS.defaultBlock, index, callback = false) {
        if (utils.isFunction(index)) {
            callback = index;
            index = 0;
        }

        if (utils.isFunction(block)) {
            callback = block;
            block = this.unichainJS.defaultBlock;
        }

        if (!callback)
            return this.injectPromise(this.getTransactionFromBlock, block, index);

        this.getBlock(block).then(({transactions = false}) => {
            if (!transactions)
                callback('Transaction not found in block');
            else if (typeof index == 'number') {
                if (index >= 0 && index < transactions.length)
                    callback(null, transactions[index]);
                else
                    callback('Invalid transaction index provided');
            } else
                callback(null, transactions);
        }).catch(err => callback(err));
    }

    getTransaction(transactionID, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTransaction, transactionID);

        this.unichainJS.fullNode.request('wallet/gettransactionbyid', {
            value: transactionID
        }, 'post').then(transaction => {
            if (!Object.keys(transaction).length)
                return callback('Transaction not found');

            callback(null, transaction);
        }).catch(err => callback(err));
    }

    getConfirmedTransaction(transactionID, callback = false) {
        if (!callback)
            return this.injectPromise(this.getConfirmedTransaction, transactionID);

        this.unichainJS.solidityNode.request('walletsolidity/gettransactionbyid', {
            value: transactionID
        }, 'post').then(transaction => {
            if (!Object.keys(transaction).length)
                return callback('Transaction not found');

            callback(null, transaction);
        }).catch(err => callback(err));
    }

    getUnconfirmedTransactionInfo(transactionID, callback = false) {
        return this._getTransactionInfoById(transactionID, {confirmed: false}, callback)
    }

    getTransactionInfo(transactionID, callback = false) {
        return this._getTransactionInfoById(transactionID, {confirmed: true}, callback)
    }

    _getTransactionInfoById(transactionID, options, callback = false) {
        if (!callback)
            return this.injectPromise(this._getTransactionInfoById, transactionID, options);

        this.unichainJS[options.confirmed ? 'solidityNode' : 'fullNode'].request(`wallet${options.confirmed ? 'solidity' : ''}/gettransactioninfobyid`, {
            value: transactionID
        }, 'post').then(transaction => {
            callback(null, transaction);
        }).catch(err => callback(err));
    }

    getTransactionsToAddress(address = this.unichainJS.defaultAddress.hex, limit = 30, offset = 0, callback = false) {
        if (utils.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }

        if (utils.isFunction(limit)) {
            callback = limit;
            limit = 30;
        }

        if (!callback)
            return this.injectPromise(this.getTransactionsToAddress, address, limit, offset);

        address = this.unichainJS.address.toHex(address);

        return this.getTransactionsRelated(address, 'to', limit, offset, callback);
    }

    getTransactionsFromAddress(address = this.unichainJS.defaultAddress.hex, limit = 30, offset = 0, callback = false) {
        if (utils.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }

        if (utils.isFunction(limit)) {
            callback = limit;
            limit = 30;
        }

        if (!callback)
            return this.injectPromise(this.getTransactionsFromAddress, address, limit, offset);

        address = this.unichainJS.address.toHex(address);

        return this.getTransactionsRelated(address, 'from', limit, offset, callback);
    }

    async getTransactionsRelated(address = this.unichainJS.defaultAddress.hex, direction = 'all', limit = 30, offset = 0, callback = false) {
        if (utils.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }

        if (utils.isFunction(limit)) {
            callback = limit;
            limit = 30;
        }

        if (utils.isFunction(direction)) {
            callback = direction;
            direction = 'all';
        }

        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getTransactionsRelated, address, direction, limit, offset);

        if (!['to', 'from', 'all'].includes(direction))
            return callback('Invalid direction provided: Expected "to", "from" or "all"');

        if (direction == 'all') {
            try {
                const [from, to] = await Promise.all([
                    this.getTransactionsRelated(address, 'from', limit, offset),
                    this.getTransactionsRelated(address, 'to', limit, offset)
                ])

                return callback(null, [
                    ...from.map(tx => (tx.direction = 'from', tx)),
                    ...to.map(tx => (tx.direction = 'to', tx))
                ].sort((a, b) => {
                    return b.raw_data.timestamp - a.raw_data.timestamp
                }));
            } catch (ex) {
                return callback(ex);
            }
        }

        if (!this.unichainJS.isAddress(address))
            return callback('Invalid address provided');

        if (!utils.isInteger(limit) || limit < 0 || (offset && limit < 1))
            return callback('Invalid limit provided');

        if (!utils.isInteger(offset) || offset < 0)
            return callback('Invalid offset provided');

        address = this.unichainJS.address.toHex(address);

        this.unichainJS.solidityNode.request(`walletextension/gettransactions${direction}this`, {
            account: {
                address
            },
            offset,
            limit
        }, 'post').then(({transaction}) => {
            callback(null, transaction);
        }).catch(err => callback(err));
    }

    getAccount(address = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getAccount, address);

        if (!this.unichainJS.isAddress(address))
            return callback('Invalid address provided');

        address = this.unichainJS.address.toHex(address);

        this.unichainJS.solidityNode.request('walletsolidity/getaccount', {
            address
        }, 'post').then(account => {
            callback(null, account);
        }).catch(err => callback(err));
    }

    getAccountById(id = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getAccountById, id);

        this.getAccountInfoById(id, {confirmed: true}, callback);
    }

    getAccountInfoById(id, options, callback) {
        if (this.validator.notValid([
            {
                name: 'accountId',
                type: 'hex',
                value: id
            },
            {
                name: 'accountId',
                type: 'string',
                lte: 32,
                gte: 8,
                value: id
            }
        ], callback))
            return;

        if (id.startsWith('0x')) {
            id = id.slice(2);
        }

        this.unichainJS[options.confirmed ? 'solidityNode' : 'fullNode'].request(`wallet${options.confirmed ? 'solidity' : ''}/getaccountbyid`, {
            account_id: id
        }, 'post').then(account => {
            callback(null, account);
        }).catch(err => callback(err));
    }

    getBalance(address = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getBalance, address);

        this.getAccount(address).then(({balance = 0}) => {
            callback(null, balance);
        }).catch(err => callback(err));
    }

    getUnconfirmedAccount(address = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getUnconfirmedAccount, address);

        if (!this.unichainJS.isAddress(address))
            return callback('Invalid address provided');

        address = this.unichainJS.address.toHex(address);

        this.unichainJS.fullNode.request('wallet/getaccount', {
            address
        }, 'post').then(account => {
            callback(null, account);
        }).catch(err => callback(err));
    }

    getUnconfirmedAccountById(id, callback = false) {
        if (!callback)
            return this.injectPromise(this.getUnconfirmedAccountById, id);

        this.getAccountInfoById(id, {confirmed: false}, callback);
    }

    getUnconfirmedBalance(address = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getUnconfirmedBalance, address);

        this.getUnconfirmedAccount(address).then(({balance = 0}) => {
            callback(null, balance);
        }).catch(err => callback(err));
    }

    getBandwidth(address = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getBandwidth, address);

        if (!this.unichainJS.isAddress(address))
            return callback('Invalid address provided');

        address = this.unichainJS.address.toHex(address);

        this.unichainJS.fullNode.request('wallet/getaccountnet', {
            address
        }, 'post').then(({freeNetUsed = 0, freeNetLimit = 0, NetUsed = 0, NetLimit = 0}) => {
            callback(null, (freeNetLimit - freeNetUsed) + (NetLimit - NetUsed));
        }).catch(err => callback(err));
    }

    getTokensIssuedByAddress(address = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getTokensIssuedByAddress, address);

        if (!this.unichainJS.isAddress(address))
            return callback('Invalid address provided');

        address = this.unichainJS.address.toHex(address);

        this.unichainJS.fullNode.request('wallet/getassetissuebyaccount', {
            address
        }, 'post').then(({assetIssue = false}) => {
            if (!assetIssue)
                return callback(null, {});

            const tokens = assetIssue.map(token => {
                return this._parseToken(token);
            }).reduce((tokens, token) => {
                return tokens[token.name] = token, tokens;
            }, {});

            callback(null, tokens);
        }).catch(err => callback(err));
    }

    getTokenFromID(tokenID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTokenFromID, tokenID);

        if (utils.isInteger(tokenID))
            tokenID = tokenID.toString()

        if (!utils.isString(tokenID) || !tokenID.length)
            return callback('Invalid token ID provided');

        this.unichainJS.fullNode.request('wallet/getassetissuebyname', {
            value: this.unichainJS.fromUtf8(tokenID)
        }, 'post').then(token => {
            if (!token.name)
                return callback('Token does not exist');

            callback(null, this._parseToken(token));
        }).catch(err => callback(err));
    }

    listNodes(callback = false) {
        if (!callback)
            return this.injectPromise(this.listNodes);

        this.unichainJS.fullNode.request('wallet/listnodes').then(({nodes = []}) => {
            callback(null, nodes.map(({address: {host, port}}) => (
                `${this.unichainJS.toUtf8(host)}:${port}`
            )));
        }).catch(err => callback(err));
    }

    getBlockRange(start = 0, end = 30, callback = false) {
        if (utils.isFunction(end)) {
            callback = end;
            end = 30;
        }

        if (utils.isFunction(start)) {
            callback = start;
            start = 0;
        }

        if (!callback)
            return this.injectPromise(this.getBlockRange, start, end);

        if (!utils.isInteger(start) || start < 0)
            return callback('Invalid start of range provided');

        if (!utils.isInteger(end) || end <= start)
            return callback('Invalid end of range provided');

        this.unichainJS.fullNode.request('wallet/getblockbylimitnext', {
            startNum: parseInt(start),
            endNum: parseInt(end) + 1
        }, 'post').then(({block = []}) => {
            callback(null, block);
        }).catch(err => callback(err));
    }

    listWitnesses(callback = false) {
        if (!callback)
            return this.injectPromise(this.listWitnesses);

        this.unichainJS.fullNode.request('wallet/listwitnesses').then(({witnesses = []}) => {
            callback(null, witnesses);
        }).catch(err => callback(err));
    }

    listTokens(limit = 0, offset = 0, callback = false) {
        if (utils.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }

        if (utils.isFunction(limit)) {
            callback = limit;
            limit = 0;
        }

        if (!callback)
            return this.injectPromise(this.listTokens, limit, offset);

        if (!utils.isInteger(limit) || limit < 0 || (offset && limit < 1))
            return callback('Invalid limit provided');

        if (!utils.isInteger(offset) || offset < 0)
            return callback('Invalid offset provided');

        if (!limit) {
            return this.unichainJS.fullNode.request('wallet/getassetissuelist').then(({assetIssue = []}) => {
                callback(null, assetIssue.map(token => this._parseToken(token)));
            }).catch(err => callback(err));
        }

        this.unichainJS.fullNode.request('wallet/getpaginatedassetissuelist', {
            offset: parseInt(offset),
            limit: parseInt(limit)
        }, 'post').then(({assetIssue = []}) => {
            callback(null, assetIssue.map(token => this._parseToken(token)));
        }).catch(err => callback(err));
    }

    timeUntilNextVoteCycle(callback = false) {
        if (!callback)
            return this.injectPromise(this.timeUntilNextVoteCycle);

        this.unichainJS.fullNode.request('wallet/getnextmaintenancetime').then(({num = -1}) => {
            if (num == -1)
                return callback('Failed to get time until next vote cycle');

            callback(null, Math.floor(num / 1000));
        }).catch(err => callback(err));
    }

    getContract(contractAddress, callback = false) {
        if (!callback)
            return this.injectPromise(this.getContract, contractAddress);

        if (!this.unichainJS.isAddress(contractAddress))
            return callback('Invalid contract address provided');

        if (this.cache.contracts[contractAddress]) {
            callback(null, this.cache.contracts[contractAddress]);
            return;
        }

        contractAddress = this.unichainJS.address.toHex(contractAddress);

        this.unichainJS.fullNode.request('wallet/getcontract', {
            value: contractAddress
        }).then(contract => {
            if (contract.Error)
                return callback('Contract does not exist');
            this.cache.contracts[contractAddress] = contract;
            callback(null, contract);
        }).catch(err => callback(err));
    }

    async verifyMessage(message = false, signature = false, address = this.unichainJS.defaultAddress.base58, useUnichainHeader = true, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.base58;
            useUnichainHeader = true;
        }

        if (utils.isFunction(useUnichainHeader)) {
            callback = useUnichainHeader;
            useUnichainHeader = true;
        }

        if (!callback)
            return this.injectPromise(this.verifyMessage, message, signature, address, useUnichainHeader);

        if (!utils.isHex(message))
            return callback('Expected hex message input');

        if (Api.verifySignature(message, address, signature, useUnichainHeader))
            return callback(null, true);

        callback('Signature does not match');
    }

    static verifySignature(message, address, signature, useUnichainHeader = true) {
        message = message.replace(/^0x/, '');
        signature = signature.replace(/^0x/, '');
        const messageBytes = [
            ...toUtf8Bytes(useUnichainHeader ? UNW_MESSAGE_HEADER : ETH_MESSAGE_HEADER),
            ...utils.code.hexStr2byteArray(message)
        ];

        const messageDigest = keccak256(messageBytes);
        const recovered = recoverAddress(messageDigest, {
            recoveryParam: signature.substring(128, 130) == '1c' ? 1 : 0,
            r: '0x' + signature.substring(0, 64),
            s: '0x' + signature.substring(64, 128)
        });

        const unichainAddress = ADDRESS_PREFIX + recovered.substr(2);
        const base58Address = UnichainJS.address.fromHex(unichainAddress);

        return base58Address == UnichainJS.address.fromHex(address);
    }

    async sign(transaction = false, privateKey = this.unichainJS.defaultPrivateKey, useUnichainHeader = true, multisig = false, callback = false) {

        if (utils.isFunction(multisig)) {
            callback = multisig;
            multisig = false;
        }

        if (utils.isFunction(useUnichainHeader)) {
            callback = useUnichainHeader;
            useUnichainHeader = true;
            multisig = false;
        }

        if (utils.isFunction(privateKey)) {
            callback = privateKey;
            privateKey = this.unichainJS.defaultPrivateKey;
            useUnichainHeader = true;
            multisig = false;
        }


        if (!callback)
            return this.injectPromise(this.sign, transaction, privateKey, useUnichainHeader, multisig);

        // Message signing
        if (utils.isString(transaction)) {

            if (!utils.isHex(transaction))
                return callback('Expected hex message input');

            try {
                const signatureHex = Api.signString(transaction, privateKey, useUnichainHeader)
                return callback(null, signatureHex);
            } catch (ex) {
                callback(ex);
            }
        }

        if (!utils.isObject(transaction))
            return callback('Invalid transaction provided');

        if (!multisig && transaction.signature)
            return callback('Transaction is already signed');

        try {
            if (!multisig) {
                const address = this.unichainJS.address.toHex(
                    this.unichainJS.address.fromPrivateKey(privateKey)
                ).toLowerCase();

                if (address !== transaction.raw_data.contract[0].parameter.value.owner_address.toLowerCase())
                    return callback('Private key does not match address in transaction');
            }
            return callback(null,
                utils.crypto.signTransaction(privateKey, transaction)
            );
        } catch (ex) {
            callback(ex);
        }
    }

    static signString(message, privateKey, useUnichainHeader = true) {
        message = message.replace(/^0x/, '');
        const signingKey = new SigningKey(privateKey);
        const messageBytes = [
            ...toUtf8Bytes(useUnichainHeader ? UNW_MESSAGE_HEADER : ETH_MESSAGE_HEADER),
            ...utils.code.hexStr2byteArray(message)
        ];

        const messageDigest = keccak256(messageBytes);
        const signature = signingKey.signDigest(messageDigest);

        const signatureHex = [
            '0x',
            signature.r.substring(2),
            signature.s.substring(2),
            Number(signature.v).toString(16)
        ].join('');

        return signatureHex
    }

    async multiSign(transaction = false, privateKey = this.unichainJS.defaultPrivateKey, permissionId = false, callback = false) {

        if (utils.isFunction(permissionId)) {
            callback = permissionId;
            permissionId = 0;
        }

        if (utils.isFunction(privateKey)) {
            callback = privateKey;
            privateKey = this.unichainJS.defaultPrivateKey;
            permissionId = 0;
        }

        if (!callback)
            return this.injectPromise(this.multiSign, transaction, privateKey, permissionId);

        if (!utils.isObject(transaction) || !transaction.raw_data || !transaction.raw_data.contract)
            return callback('Invalid transaction provided');

        // If owner permission or permission id exists in transaction, do sign directly
        // If no permission id inside transaction or user passes permission id, use old way to reset permission id
        if (!transaction.raw_data.contract[0].Permission_id && permissionId > 0) {
            // set permission id
            transaction.raw_data.contract[0].Permission_id = permissionId;

            // check if private key insides permission list
            const address = this.unichainJS.address.toHex(this.unichainJS.address.fromPrivateKey(privateKey)).toLowerCase();
            const signWeight = await this.getSignWeight(transaction, permissionId);

            if (signWeight.result.code === 'PERMISSION_ERROR') {
                return callback(signWeight.result.message);
            }

            let foundKey = false;
            signWeight.permission.keys.map(key => {
                if (key.address === address)
                    foundKey = true;
            });

            if (!foundKey)
                return callback(privateKey + ' has no permission to sign');

            if (signWeight.approved_list && signWeight.approved_list.indexOf(address) != -1) {
                return callback(privateKey + ' already sign transaction');
            }

            // reset transaction
            if (signWeight.transaction && signWeight.transaction.transaction) {
                transaction = signWeight.transaction.transaction;
                if (permissionId > 0) {
                    transaction.raw_data.contract[0].Permission_id = permissionId;
                }
            } else {
                return callback('Invalid transaction provided');
            }
        }

        // sign
        try {
            return callback(null, utils.crypto.signTransaction(privateKey, transaction));
        } catch (ex) {
            callback(ex);
        }
    }

    async getApprovedList(transaction, callback = false) {
        if (!callback)
            return this.injectPromise(this.getApprovedList, transaction);

        if (!utils.isObject(transaction))
            return callback('Invalid transaction provided');


        this.unichainJS.fullNode.request(
            'wallet/getapprovedlist',
            transaction,
            'post'
        ).then(result => {
            callback(null, result);
        }).catch(err => callback(err));
    }

    async getSignWeight(transaction, permissionId, callback = false) {
        if (utils.isFunction(permissionId)) {
            callback = permissionId;
            permissionId = undefined;
        }

        if (!callback)
            return this.injectPromise(this.getSignWeight, transaction, permissionId);

        if (!utils.isObject(transaction) || !transaction.raw_data || !transaction.raw_data.contract)
            return callback('Invalid transaction provided');

        if (utils.isInteger(permissionId)) {
            transaction.raw_data.contract[0].Permission_id = parseInt(permissionId);
        } else if (typeof transaction.raw_data.contract[0].Permission_id !== 'number') {
            transaction.raw_data.contract[0].Permission_id = 0;
        }

        if (!utils.isObject(transaction))
            return callback('Invalid transaction provided');


        this.unichainJS.fullNode.request(
            'wallet/getsignweight',
            transaction,
            'post'
        ).then(result => {
            callback(null, result);
        }).catch(err => callback(err));
    }

    sendRawTransaction(signedTransaction = false, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback)
            return this.injectPromise(this.sendRawTransaction, signedTransaction, options);

        if (!utils.isObject(signedTransaction))
            return callback('Invalid transaction provided');

        if (!utils.isObject(options))
            return callback('Invalid options provided');

        if (!signedTransaction.signature || !utils.isArray(signedTransaction.signature))
            return callback('Transaction is not signed');

        this.unichainJS.fullNode.request(
            'wallet/broadcasttransaction',
            signedTransaction,
            'post'
        ).then(result => {
            if (result.result)
                result.transaction = signedTransaction;
            callback(null, result);
        }).catch(err => callback(err));
    }

    async sendTransaction(to = false, amount = false, expiredTime = 0, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.sendTransaction, to, amount, options);

        if (!this.unichainJS.isAddress(to))
            return callback('Invalid recipient provided');

        if (!utils.isInteger(amount) || amount <= 0)
            return callback('Invalid amount provided');

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Function requires either a private key or address to be set');

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.sendUnw(to, amount, expiredTime, address);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    async sendToken(to = false, amount = false, tokenID = false, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.sendToken, to, amount, tokenID, options);

        if (!this.unichainJS.isAddress(to))
            return callback('Invalid recipient provided');

        if (!utils.isInteger(amount) || amount <= 0)
            return callback('Invalid amount provided');

        if (utils.isInteger(tokenID))
            tokenID = tokenID.toString()

        if (!utils.isString(tokenID))
            return callback('Invalid token ID provided');

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Function requires either a private key or address to be set');

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.sendToken(to, amount, tokenID, address);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * Freezes an amount of UNW.
     * Will give bandwidth OR Energy and UNICHAIN Power(voting rights)
     * to the owner of the frozen tokens.
     *
     * @param amount - is the number of frozen unw
     * @param duration - is the duration in days to be frozen
     * @param resource - is the type, must be either "ENERGY" or "BANDWIDTH"
     * @param options
     * @param callback
     */
    async freezeBalance(amount = 0, duration = 3, resource = "BANDWIDTH", options = {}, receiverAddress = undefined, callback = false) {
        if (utils.isFunction(receiverAddress)) {
            callback = receiverAddress;
            receiverAddress = undefined;
        }
        if (utils.isFunction(duration)) {
            callback = duration;
            duration = 3;
        }

        if (utils.isFunction(resource)) {
            callback = resource;
            resource = "BANDWIDTH";
        }

        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.freezeBalance, amount, duration, resource, options, receiverAddress);

        if (!['BANDWIDTH', 'ENERGY'].includes(resource))
            return callback('Invalid resource provided: Expected "BANDWIDTH" or "ENERGY"');

        if (!utils.isInteger(amount) || amount <= 0)
            return callback('Invalid amount provided');

        if (!utils.isInteger(duration) || duration < 3)
            return callback('Invalid duration provided, minimum of 3 days');

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Function requires either a private key or address to be set');

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const freezeBalance = await this.unichainJS.transactionBuilder.freezeBalance(amount, duration, resource, address, receiverAddress);
            const signedTransaction = await this.sign(freezeBalance, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * Unfreeze UNW that has passed the minimum freeze duration.
     * Unfreezing will remove bandwidth and UNICHAIN Power.
     *
     * @param resource - is the type, must be either "ENERGY" or "BANDWIDTH"
     * @param options
     * @param callback
     */
    async unfreezeBalance(resource = "BANDWIDTH", options = {}, receiverAddress = undefined, callback = false) {
        if (utils.isFunction(receiverAddress)) {
            callback = receiverAddress;
            receiverAddress = undefined;
        }

        if (utils.isFunction(resource)) {
            callback = resource;
            resource = 'BANDWIDTH';
        }

        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.unfreezeBalance, resource, options, receiverAddress);

        if (!['BANDWIDTH', 'ENERGY'].includes(resource))
            return callback('Invalid resource provided: Expected "BANDWIDTH" or "ENERGY"');

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Function requires either a private key or address to be set');

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const unfreezeBalance = await this.unichainJS.transactionBuilder.unfreezeBalance(resource, address, receiverAddress);
            const signedTransaction = await this.sign(unfreezeBalance, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * Modify account name
     * Note: Username is allowed to edit only once.
     *
     * @param privateKey - Account private Key
     * @param accountName - name of the account
     * @param callback
     *
     * @return modified Transaction Object
     */
    async updateAccount(accountName = false, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback) {
            return this.injectPromise(this.updateAccount, accountName, options);
        }

        if (!utils.isString(accountName) || !accountName.length) {
            return callback('Name must be a string');
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Function requires either a private key or address to be set');

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const updateAccount = await this.unichainJS.transactionBuilder.updateAccount(accountName, address);
            const signedTransaction = await this.sign(updateAccount, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    signMessage(...args) {
        return this.sign(...args);
    }

    sendAsset(...args) {
        return this.sendToken(...args);
    }

    send(...args) {
        return this.sendTransaction(...args);
    }

    sendUnw(...args) {
        return this.sendTransaction(...args);
    }

    broadcast(...args) {
        return this.sendRawTransaction(...args);
    }

    signTransaction(...args) {
        return this.sign(...args);
    }

    /**
     * Gets a network modification proposal by ID.
     */
    getProposal(proposalID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getProposal, proposalID);

        if (!utils.isInteger(proposalID) || proposalID < 0)
            return callback('Invalid proposalID provided');

        this.unichainJS.fullNode.request('wallet/getproposalbyid', {
            id: parseInt(proposalID),
        }, 'post').then(proposal => {
            callback(null, proposal);
        }).catch(err => callback(err));
    }

    /**
     * Lists all network modification proposals.
     */
    listProposals(callback = false) {
        if (!callback)
            return this.injectPromise(this.listProposals);

        this.unichainJS.fullNode.request('wallet/listproposals', {}, 'post').then(({proposals = []}) => {
            callback(null, proposals);
        }).catch(err => callback(err));
    }

    /**
     * Lists all parameters available for network modification proposals.
     */
    getChainParameters(callback = false) {
        if (!callback)
            return this.injectPromise(this.getChainParameters);

        this.unichainJS.fullNode.request('wallet/getchainparameters', {}, 'post').then(({chainParameter = []}) => {
            callback(null, chainParameter);
        }).catch(err => callback(err));
    }

    /**
     * Get the account resources
     */
    getAccountResources(address = this.unichainJS.defaultAddress.hex, callback = false) {
        if (!callback)
            return this.injectPromise(this.getAccountResources, address);

        if (!this.unichainJS.isAddress(address))
            return callback('Invalid address provided');

        this.unichainJS.fullNode.request('wallet/getaccountresource', {
            address: this.unichainJS.address.toHex(address),
        }, 'post').then(resources => {
            callback(null, resources);
        }).catch(err => callback(err));
    }

    /**
     * Get the exchange ID.
     */
    getExchangeByID(exchangeID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getExchangeByID, exchangeID);

        if (!utils.isInteger(exchangeID) || exchangeID < 0)
            return callback('Invalid exchangeID provided');

        this.unichainJS.fullNode.request('wallet/getexchangebyid', {
            id: exchangeID,
        }, 'post').then(exchange => {
            callback(null, exchange);
        }).catch(err => callback(err));
    }

    /**
     * Lists the exchanges
     */
    listExchanges(callback = false) {
        if (!callback)
            return this.injectPromise(this.listExchanges);

        this.unichainJS.fullNode.request('wallet/listexchanges', {}, 'post').then(({exchanges = []}) => {
            callback(null, exchanges);
        }, 'post').catch(err => callback(err));
    }

    /**
     * Lists all network modification proposals.
     */
    listExchangesPaginated(limit = 10, offset = 0, callback = false) {
        if (utils.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }
        if (utils.isFunction(limit)) {
            callback = limit;
            limit = 30;
        }
        if (!callback)
            return this.injectPromise(this.listExchanges);

        this.unichainJS.fullNode.request('wallet/listexchangespaginated', {
            limit,
            offset
        }, 'post').then(({exchanges = []}) => {
            callback(null, exchanges);
        }).catch(err => callback(err));
    }

    /**
     * Get info about thre node
     */
    getNodeInfo(callback = false) {
        if (!callback)
            return this.injectPromise(this.getNodeInfo);

        this.unichainJS.fullNode.request('wallet/getnodeinfo', {}, 'post').then(info => {
            callback(null, info);
        }, 'post').catch(err => callback(err));
    }


    getTokenListByName(tokenID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTokenListByName, tokenID);

        if (utils.isInteger(tokenID))
            tokenID = tokenID.toString()

        if (!utils.isString(tokenID) || !tokenID.length)
            return callback('Invalid token ID provided');

        this.unichainJS.fullNode.request('wallet/getassetissuelistbyname', {
            value: this.unichainJS.fromUtf8(tokenID)
        }, 'post').then(token => {
            if (!token.name)
                return callback('Token does not exist');

            callback(null, this._parseToken(token));
        }).catch(err => callback(err));
    }

    getTokenByID(tokenID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTokenByID, tokenID);

        if (utils.isInteger(tokenID))
            tokenID = tokenID.toString()

        if (!utils.isString(tokenID) || !tokenID.length)
            return callback('Invalid token ID provided');

        this.unichainJS.fullNode.request('wallet/getassetissuebyid', {
            value: tokenID
        }, 'post').then(token => {
            if (!token.name)
                return callback('Token does not exist');

            callback(null, this._parseToken(token));
        }).catch(err => callback(err));
    }

    async getReward(address, options = {}, callback = false) {
        options.confirmed = true;
        return this._getReward(address, options, callback);
    }

    async getUnconfirmedReward(address, options = {}, callback = false) {
        options.confirmed = false;
        return this._getReward(address, options, callback);
    }

    async getBrokerage(address, options = {}, callback = false) {
        options.confirmed = true;
        return this._getBrokerage(address, options, callback);
    }

    async getUnconfirmedBrokerage(address, options = {}, callback = false) {
        options.confirmed = false;
        return this._getBrokerage(address, options, callback);
    }

    async _getReward(address = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(address)) {
            options = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this._getReward, address, options);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: address
            }
        ], callback))
            return;

        const data = {
            address: toHex(address)
        };

        this.unichainJS[options.confirmed ? 'solidityNode' : 'fullNode'].request(`wallet${options.confirmed ? 'solidity' : ''}/getReward`, data, 'post')
            .then((result = {}) => {

                if (typeof result.reward === 'undefined')
                    return callback('Not found.');

                callback(null, result.reward);
            }).catch(err => callback(err));
    }


    async _getBrokerage(address = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(address)) {
            options = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this._getBrokerage, address, options);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: address
            }
        ], callback))
            return;

        const data = {
            address: toHex(address)
        };

        this.unichainJS[options.confirmed ? 'solidityNode' : 'fullNode'].request(`wallet${options.confirmed ? 'solidity' : ''}/getBrokerage`, data, 'post')
            .then((result = {}) => {

                if (typeof result.brokerage === 'undefined')
                    return callback('Not found.');

                callback(null, result.brokerage);
            }).catch(err => callback(err));
    }

    //URC30 APIs
    getTokenPool (tokenName, pageSize = 10, index = 0, callback = false) {
        if (!callback) 
            return this.injectPromise(this.getTokenPool, tokenName, pageSize, index);
        
        const data = {
            token_name: tokenName,
            page_size: pageSize,
            page_index: index
        }
        this.unichainJS.fullNode.request('wallet/gettokenpool', data, 'post').then(token => {
            return callback(token)
        }).catch(err => callback(err));
    }
    
    getFutureToken (tokenName, ownerAddress, pageSize = 10, index = 0, callback = false) {
        if (!callback) 
            return this.injectPromise(this.getFutureToken, tokenName, ownerAddress, pageSize, index);
        
        const data = {
            token_name: tokenName,
            page_size: pageSize,
            page_index: index,
            owner_address: toHex(ownerAddress)
        }
        this.unichainJS.fullNode.request('wallet/getfuturetoken', data, 'post').then(token => {
            return callback(token)
        }).catch(err => callback(err));
    }

    getFutureTransfer (ownerAddress, pageSize = 10, index = 0, callback = false) {
        if (!callback) 
            return this.injectPromise(this.getFutureTransfer, ownerAddress, pageSize, index);
        
        const data = {
            owner_address: toHex(ownerAddress),
            page_size: pageSize,
            page_index: index
        }
        this.unichainJS.fullNode.request('wallet/getfuturetransfer', data, 'post').then(token => {
            return callback(token)
        }).catch(err => callback(err));
    }

    /* NEW CONTRACT POSBRIGDE API */
    /**
     * 
     * @param {*} new_owner 
     * @param {*} min_validator 
     * @param {*} validators 
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    async posBridgeSetup(new_owner, min_validator, validators, consensus_rate, predicate_native, predicate_token, predicate_nft, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.posBridgeSetup, new_owner, min_validator, validators, consensus_rate, predicate_native, predicate_token, predicate_nft, options);
        }

        if (validators && validators.length < min_validator) {
            return callback('Number of validator in list is not enough');
        }

        if (!new_owner) {
            return callback('New owner is required');
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.posBridgeSetup(address, new_owner, min_validator, validators, consensus_rate, predicate_native, predicate_token, predicate_nft);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} root_chainid 
     * @param {*} root_token [hex address if token, symbol if native]
     * @param {*} child_chainid 
     * @param {*} child_token [hex address]
     * @param {*} root_or_child 
     * @param {*} type 
     * 1: native
     * 2: erc20
     * 3: erc721]
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    async posBridgeMapToken(root_chainid, root_token, child_chainid, child_token, type, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.posBridgeMapToken, root_chainid, root_token, child_chainid, child_token, type, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.posBridgeMapToken(address, root_chainid, root_token, child_chainid, child_token, type);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} root_token 
     * @param {*} root_chainid 
     * @param {*} child_token 
     * @param {*} child_chainid 
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    async posBridgeCleanMapToken(root_chainid, root_token, child_chainid, child_token, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.posBridgeCleanMapToken, root_chainid, root_token, child_chainid, child_token, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.posBridgeCleanMapToken(address, root_chainid, root_token, child_chainid, child_token);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} root_token [hex address if token, unw if native]
     * @param {*} child_chainid 
     * @param {*} receive_address 
     * @param {*} data [amount or token id]
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    async posBridgeDeposit(root_token, child_chainid, receive_address, data, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.posBridgeDeposit, root_token, child_chainid, receive_address, data, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.posBridgeDeposit(address, root_token, child_chainid, receive_address, data);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} signatures [rlp encoded]
     * @param {*} message [rlp encoded]
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    async posBridgeDepositExec(signatures, message, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.posBridgeDepositExec, signatures, message, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.posBridgeDepositExec(address, signatures, message);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} child_token 
     * @param {*} receive_address 
     * @param {*} data [amount or tokenid]
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    async posBridgeWithdraw(child_token, receive_address, data, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.posBridgeWithdraw, child_token, receive_address, data, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.posBridgeWithdraw(address, child_token, receive_address, data);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} signatures [rlp encoded]
     * @param {*} message [rlp encoded]
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    async posBridgeWithdrawExec(signatures, message, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.posBridgeWithdrawExec, signatures, message, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.posBridgeWithdrawExec(address, signatures, message);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /** NEW CONTRACT URC721 */
    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} symbol 
     * @param {*} name 
     * @param {*} total_supply 
     * @param {*} minter 
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    async urc721Create(symbol, name, total_supply, minter, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc721Create, symbol, name, total_supply, minter, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc721Create(address, symbol, name, total_supply, minter, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} urc721Address 
     * @param {*} to_address 
     * @param {*} uri 
     * @param {*} token_id 
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    async urc721Mint(urc721Address, to_address, uri, token_id, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc721Mint, urc721Address, to_address, uri, token_id, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc721Mint(address, urc721Address, to_address, uri, token_id, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    async urc721RemoveMinter(urc721Address, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc721RemoveMinter, urc721Address, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc721RemoveMinter(address, urc721Address, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} minter 
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    async urc721AddMinter(urc721Address, minter, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc721AddMinter, urc721Address, minter, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc721AddMinter(address, urc721Address, minter, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    async urc721RenounceMinter(urc721Address, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc721RenounceMinter, urc721Address, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc721RenounceMinter(address, urc721Address, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} token_id 
     * @param {*} callback 
     * @returns 
     */
    async urc721Burn(urc721Address, token_id, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc721Burn, urc721Address, token_id, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc721Burn(address, urc721Address, token_id, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} token_id 
     * @param {*} to 
     * @param {*} approve 
     * @param {*} callback 
     * @returns 
     */
    async urc721Approve(urc721Address, token_id, to, approve, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc721Approve, urc721Address, token_id, to, approve, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc721Approve(address, urc721Address, token_id, to, approve, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} to_address 
     * @param {*} approve 
     * @param {*} callback 
     * @returns 
     */
    async urc721SetApprovalForAll(to_address, approve, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc721SetApprovalForAll, to_address, approve, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc721SetApprovalForAll(address, to_address, approve, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} to 
     * @param {*} token_id 
     * @param {*} callback 
     * @returns 
     */
    async urc721TransferFrom(urc721Address, to, token_id, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc721TransferFrom, urc721Address, to, token_id, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc721TransferFrom(address, urc721Address, to, token_id, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    async urc721BalanceOf(callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721BalanceOf);
        }
        try {
            const resp = await this.unichainJS.transactionBuilder.urc721BalanceOf();
            return callback(null, resp);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    async urc721Name(callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721Name);
        }
        try {
            const resp = await this.unichainJS.transactionBuilder.urc721Name();
            return callback(null, resp);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    async urc721Symbol(callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721Symbol);
        }
        try {
            const resp = await this.unichainJS.transactionBuilder.urc721Symbol();
            return callback(null, resp);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    async urc721TokenUri(callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721TokenUri);
        }
        try {
            const resp = await this.unichainJS.transactionBuilder.urc721TokenUri();
            return callback(null, resp);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    async urc721TotalSupply(callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721TotalSupply);
        }
        try {
            const resp = await this.unichainJS.transactionBuilder.urc721TotalSupply();
            return callback(null, resp);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    async urc721IsApprovedForAll(callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721IsApprovedForAll);
        }
        try {
            const resp = await this.unichainJS.transactionBuilder.urc721IsApprovedForAll();
            return callback(null, resp);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    async urc721OwnerOf(callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721OwnerOf);
        }
        try {
            const resp = await this.unichainJS.transactionBuilder.urc721OwnerOf();
            return callback(null, resp);
        } catch (ex) {
            return callback(ex);
        }
    }

    /** NEW CONTRACT URC20 */
    /**
     * 
     * @param {*} owner_address 
     * @param {*} data 
     * @param {*} callback 
     * @returns 
     */
    async urc20Create(data, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc20Create, data, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc20Create(address, data, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} from 
     * @param {*} to 
     * @param {*} address 
     * @param {*} amount 
     * @param {*} available_time 
     * @param {*} callback 
     * @returns 
     */
    async urc20TransferFrom(from, to, urc20Address, amount, available_time, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc20TransferFrom, from, to, urc20Address, amount, available_time, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc20TransferFrom(address, from, to, urc20Address, amount, available_time, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} to 
     * @param {*} amount 
     * @param {*} available_time 
     * @param {*} callback 
     * @returns 
     */
    async urc20Transfer(urc20Address, to, amount, available_time, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc20Transfer, urc20Address, to, amount, available_time, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc20Transfer(address, urc20Address, to, amount, available_time, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} spender 
     * @param {*} amount 
     * @param {*} callback 
     * @returns 
     */
    async urc20Approve(urc20Address, spender, amount, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc20Approve, urc20Address, spender, amount, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc20Approve(address, urc20Address, spender, amount, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} amount 
     * @param {*} callback 
     * @returns 
     */
    async urc20Mint(urc20Address, amount, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc20Mint, urc20Address, amount, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc20Mint(address, urc20Address, amount, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} amount 
     * @param {*} callback 
     * @returns 
     */
    async urc20Burn(urc20Address, amount, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc20Burn, urc20Address, amount, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc20Burn(address, urc20Address, amount, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} to_address 
     * @param {*} address 
     * @param {*} callback 
     * @returns 
     */
    async urc20TransferOwner(to_address, urc20Address, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc20TransferOwner, to_address, urc20Address, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc20TransferOwner(address, to_address, urc20Address, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} amount 
     * @param {*} callback 
     * @returns 
     */
    async urc20Exchange(urc20Address, amount, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc20Exchange, urc20Address, amount, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc20Exchange(address, urc20Address, amount, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} amount 
     * @param {*} callback 
     * @returns 
     */
    async urc20ContributePoolFee(urc20Address, amount, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc20ContributePoolFee, urc20Address, amount, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc20ContributePoolFee(address, urc20Address, amount, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} fee 
     * @param {*} extra_fee_rate 
     * @param {*} lot 
     * @param {*} url 
     * @param {*} total_supply 
     * @param {*} fee_pool 
     * @param {*} exch_unx_num 
     * @param {*} exch_num 
     * @param {*} create_acc_fee 
     * @param {*} callback 
     * @returns 
     */
    async urc20UpdateParams(urc20Address, fee, extra_fee_rate, lot, url, total_supply, fee_pool, exch_unx_num, exch_num, create_acc_fee, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc20UpdateParams, urc20Address, fee, extra_fee_rate, lot, url, total_supply, fee_pool, exch_unx_num, exch_num, create_acc_fee, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc20UpdateParams(address, urc20Address, fee, extra_fee_rate, lot, url, total_supply, fee_pool, exch_unx_num, exch_num, create_acc_fee, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} callback 
     * @returns 
     */
    async urc20WithdrawFuture(urc20Address, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string') {
            options = {
                privateKey: options
            };
        }

        if (!callback){
            return this.injectPromise(this.urc20WithdrawFuture, urc20Address, options);
        }

        options = {
            privateKey: this.unichainJS.defaultPrivateKey,
            address: this.unichainJS.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address){
            return callback('Function requires either a private key or address to be set');
        }

        try {
            const address = options.privateKey ? this.unichainJS.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.unichainJS.transactionBuilder.urc20WithdrawFuture(address, urc20Address, options);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }
    
    // async subcrible(topic, confirm = true, since = Date.now(), sort = 'timeStamp', cb) {
    //     const timer = since
    //     setInterval(() => {
    //         const sinceNow = timer + 3000
    //         const resp = await axios.get(`http://13.213.56.230:8080/event/native?topic=${topic}&confirmed=${confirm}&since=${sinceNow}&sort=${sort}`)
    //         cb(resp.data)
    //     }, 3000)
    // }
};