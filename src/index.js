import providers from 'lib/providers';
import utils from 'utils';
import BigNumber from 'bignumber.js';
import EventEmitter from 'eventemitter3';
import {version} from '../package.json';
import semver from 'semver';
import injectpromise from 'injectpromise';

import TransactionBuilder from 'lib/transactionBuilder';
import Api from 'lib/api';
import Contract from 'lib/contract';
import Plugin from 'lib/plugin';
import Event from 'lib/event';
import {keccak256} from 'utils/ethersUtils';
import {ADDRESS_PREFIX} from 'utils/address';
import {Wallet} from 'utils/ethersUtils';

const DEFAULT_VERSION = '1.0.1';

export default class UnichainJS extends EventEmitter {
    static providers = providers;
    static BigNumber = BigNumber;
    static TransactionBuilder = TransactionBuilder;
    static Api = Api;
    static Contract = Contract;
    static Plugin = Plugin;
    static Event = Event;
    static version = version;
    static utils = utils;
    static Wallet = Wallet

    // for retro-compatibility: solidityNode
    constructor(options = false, solidityNode = false, eventServer = false, privateKey = false, isServiceWorker = false) {
        super();

        let fullNode;
        if (typeof options === 'object' && (options.fullNode || options.fullHost)) {
            fullNode = options.fullNode || options.fullHost;
            solidityNode = options.solidityNode || options.relayNode || options.fullHost;
            eventServer = options.eventServer || options.fullHost;
            privateKey = options.privateKey;
            isServiceWorker = options.isServiceWorker || false;
        } else {
            fullNode = options;
        }

        if (utils.isString(fullNode))
            fullNode = new providers.HttpProvider(fullNode, isServiceWorker);

        if (utils.isString(solidityNode))
            solidityNode = new providers.HttpProvider(solidityNode, isServiceWorker);

        if (utils.isString(eventServer))
            eventServer = new providers.HttpProvider(eventServer, isServiceWorker);

        this.event = new Event(this);
        this.transactionBuilder = new TransactionBuilder(this);
        this.api = new Api(this);
        this.unx = this.api; //for compatible 
        this.plugin = new Plugin(this, options);
        this.utils = utils;
        this.Wallet = Wallet;

        this.setFullNode(fullNode);
        this.setSolidityNode(solidityNode);
        this.setEventServer(eventServer);

        this.providers = providers;
        this.BigNumber = BigNumber;

        this.defaultBlock = false;
        this.defaultPrivateKey = false;
        this.defaultAddress = {
            hex: false,
            base58: false
        };

        [
            'sha3', 'toHex', 'toUtf8', 'fromUtf8',
            'toAscii', 'fromAscii', 'toDecimal', 'fromDecimal',
            'toGinza', 'fromGinza', 'toBigNumber', 'isAddress',
            'createAccount', 'address', 'version', 'Wallet'
        ].forEach(key => {
            this[key] = UnichainJS[key];
        });

        if (privateKey)
            this.setPrivateKey(privateKey);

        this.fullnodeVersion = DEFAULT_VERSION;
        this.injectPromise = injectpromise(this);
        this.isServiceWorker = isServiceWorker
    }

    async getFullnodeVersion() {
        try {
            const nodeInfo = await this.api.getNodeInfo()
            this.fullnodeVersion = nodeInfo.configNodeInfo.codeVersion
            if (this.fullnodeVersion.split('.').length === 2) {
                this.fullnodeVersion += '.0';
            }
        } catch (err) {
            this.fullnodeVersion = DEFAULT_VERSION;
        }
    }

    setDefaultBlock(blockID = false) {
        if ([false, 'latest', 'earliest', 0].includes(blockID)) {
            return this.defaultBlock = blockID;
        }

        if (!utils.isInteger(blockID) || !blockID)
            throw new Error('Invalid block ID provided');

        this.defaultBlock = Math.abs(blockID);
    }

    setPrivateKey(privateKey) {
        try {
            this.setAddress(
                this.address.fromPrivateKey(privateKey)
            );
        } catch {
            throw new Error('Invalid private key provided');
        }

        this.defaultPrivateKey = privateKey;
        this.emit('privateKeyChanged', privateKey);
    }

    setAddress(address) {
        if (!this.isAddress(address))
            throw new Error('Invalid address provided');

        const hex = this.address.toHex(address);
        const base58 = this.address.fromHex(address);

        if (this.defaultPrivateKey && this.address.fromPrivateKey(this.defaultPrivateKey) !== base58)
            this.defaultPrivateKey = false;

        this.defaultAddress = {
            hex,
            base58
        };

        this.emit('addressChanged', {hex, base58});
    }

    fullnodeSatisfies(version) {
        return semver.satisfies(this.fullnodeVersion, version);
    }

    isValidProvider(provider) {
        return Object.values(providers).some(knownProvider => provider instanceof knownProvider);
    }

    setFullNode(fullNode) {
        if (utils.isString(fullNode))
            fullNode = new providers.HttpProvider(fullNode, this.isServiceWorker);

        if (!this.isValidProvider(fullNode))
            throw new Error('Invalid full node provided');

        this.fullNode = fullNode;
        this.fullNode.setStatusPage('wallet/getnowblock');

        this.getFullnodeVersion();
    }

    setSolidityNode(solidityNode) {
        if (utils.isString(solidityNode))
            solidityNode = new providers.HttpProvider(solidityNode, this.isServiceWorker);

        if (!this.isValidProvider(solidityNode))
            throw new Error('Invalid solidity node provided');

        this.solidityNode = solidityNode;
        this.solidityNode.setStatusPage('walletsolidity/getnowblock');
    }

    setEventServer(...params) {
        this.event.setServer(...params)
    }

    currentProviders() {
        return {
            fullNode: this.fullNode,
            solidityNode: this.solidityNode,
            eventServer: this.eventServer
        };
    }

    currentProvider() {
        return this.currentProviders();
    }


    getEventResult(...params) {

        if (typeof params[1] !== 'object') {
            params[1] = {
                sinceTimestamp: params[1] || 0,
                eventName: params[2] || false,
                blockNumber: params[3] || false,
                size: params[4] || 20,
                page: params[5] || 1
            }
            params.splice(2, 4)

            // callback:
            if (!utils.isFunction(params[2])) {

                if (utils.isFunction(params[1].page)) {
                    params[2] = params[1].page;
                    params[1].page = 1;
                } else if (utils.isFunction(params[1].size)) {
                    params[2] = params[1].size;
                    params[1].size = 20;
                    params[1].page = 1;
                }
            }
        }

        return this.event.getEventsByContractAddress(...params);
    }

    getEventByTransactionID(...params) {
        return this.event.getEventsByTransactionID(...params)
    }

    contract(abi = [], address = false) {
        return new Contract(this, abi, address);
    }

    static get address() {
        return {
            fromHex(address) {
                if (!utils.isHex(address))
                    return address;

                return utils.crypto.getBase58CheckAddress(
                    utils.code.hexStr2byteArray(address.replace(/^0x/, ADDRESS_PREFIX))
                );
            },
            toHex(address) {
                if (utils.isHex(address))
                    return address.toLowerCase().replace(/^0x/, ADDRESS_PREFIX);

                return utils.code.byteArray2hexStr(
                    utils.crypto.decodeBase58Address(address)
                ).toLowerCase();
            },
            fromPrivateKey(privateKey) {
                try {
                    return utils.crypto.pkToAddress(privateKey);
                } catch {
                    return false;
                }
            }
        }
    }

    static sha3(string, prefix = true) {
        return (prefix ? '0x' : '') + keccak256(Buffer.from(string, 'utf-8')).toString().substring(2);
    }

    static toHex(val) {
        if (utils.isBoolean(val))
            return UnichainJS.fromDecimal(+val);

        if (utils.isBigNumber(val))
            return UnichainJS.fromDecimal(val);

        if (typeof val === 'object')
            return UnichainJS.fromUtf8(JSON.stringify(val));

        if (utils.isString(val)) {
            if (/^(-|)0x/.test(val))
                return val;

            if (!isFinite(val))
                return UnichainJS.fromUtf8(val);
        }

        let result = UnichainJS.fromDecimal(val);
        if (result === '0xNaN') {
            throw new Error('The passed value is not convertible to a hex string');
        } else {
            return result;
        }
    }

    static toUtf8(hex) {
        if (utils.isHex(hex)) {
            hex = hex.replace(/^0x/, '');
            return Buffer.from(hex, 'hex').toString('utf8');
        } else {
            throw new Error('The passed value is not a valid hex string');
        }
    }

    static fromUtf8(string) {
        if (!utils.isString(string)) {
            throw new Error('The passed value is not a valid utf-8 string')
        }
        return '0x' + Buffer.from(string, 'utf8').toString('hex');
    }

    static toAscii(hex) {
        if (utils.isHex(hex)) {
            let str = "";
            let i = 0, l = hex.length;
            if (hex.substring(0, 2) === '0x') {
                i = 2;
            }
            for (; i < l; i += 2) {
                let code = parseInt(hex.substr(i, 2), 16);
                str += String.fromCharCode(code);
            }
            return str;
        } else {
            throw new Error('The passed value is not a valid hex string');
        }
    }

    static fromAscii(string, padding) {
        if (!utils.isString(string)) {
            throw new Error('The passed value is not a valid utf-8 string')
        }
        return '0x' + Buffer.from(string, 'ascii').toString('hex').padEnd(padding, '0');
    }


    static toDecimal(value) {
        return UnichainJS.toBigNumber(value).toNumber();
    }

    static fromDecimal(value) {
        const number = UnichainJS.toBigNumber(value);
        const result = number.toString(16);

        return number.isLessThan(0) ? '-0x' + result.substr(1) : '0x' + result;
    }

    static fromGinza(ginza) {
        const unw = UnichainJS.toBigNumber(ginza).div(1_000_000);
        return utils.isBigNumber(ginza) ? unw : unw.toString(10);
    }

    static toGinza(unw) {
        const ginza = UnichainJS.toBigNumber(unw).times(1_000_000);
        return utils.isBigNumber(unw) ? ginza : ginza.toString(10);
    }

    static toBigNumber(amount = 0) {
        if (utils.isBigNumber(amount))
            return amount;

        if (utils.isString(amount) && /^(-|)0x/.test(amount))
            return new BigNumber(amount.replace('0x', ''), 16);

        return new BigNumber(amount.toString(10), 10);
    }

    static isAddress(address = false) {
        if (!utils.isString(address))
            return false;

        // Convert HEX to Base58
        if (address.length === 42) {
            try {
                return UnichainJS.isAddress(
                    utils.crypto.getBase58CheckAddress(
                        utils.code.hexStr2byteArray(address) // it throws an error if the address starts with 0x
                    )
                );
            } catch (err) {
                return false;
            }
        }
        try {
            return utils.crypto.isAddressValid(address);
        } catch (err) {
            return false;
        }
    }

    static async createAccount() {
        const account = utils.accounts.generateAccount();

        return account;
    }

    async isConnected(callback = false) {
        if (!callback)
            return this.injectPromise(this.isConnected);

        return callback(null, {
            fullNode: await this.fullNode.isConnected(),
            solidityNode: await this.solidityNode.isConnected(),
            eventServer: this.eventServer && await this.eventServer.isConnected()
        });
    }
};
