import UnichainJS from 'index';
import utils from 'utils';
import {AbiCoder} from 'utils/ethersUtils';
import Validator from 'paramValidator';
import {ADDRESS_PREFIX_REGEX} from 'utils/address';
import injectpromise from 'injectpromise';

let self;

//helpers

function toHex(value) {
    return UnichainJS.address.toHex(value);
}

function fromUtf8(value) {
    return self.unichainJS.fromUtf8(value);
}

function resultManager(transaction, callback) {
    if (transaction.Error)
        return callback(transaction.Error);

    if (transaction.result && transaction.result.message) {
        return callback(
            self.unichainJS.toUtf8(transaction.result.message)
        );
    }

    return callback(null, transaction);
}


export default class TransactionBuilder {
    constructor(unichainJS = false) {
        if (!unichainJS || !unichainJS instanceof UnichainJS)
            throw new Error('Expected instance of UnichainJS');
        self = this;
        this.unichainJS = unichainJS;
        this.injectPromise = injectpromise(this);
        this.validator = new Validator(unichainJS);
    }

    sendUnw(to = false, amount = 0, expiredTime = 0, from = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(from)) {
            callback = from;
            from = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(from)) {
            options = from;
            from = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.sendUnw, to, amount, expiredTime, from, options);

        // accept amounts passed as strings
        amount = parseInt(amount)

        if (this.validator.notValid([
            {
                name: 'recipient',
                type: 'address',
                value: to
            },
            {
                name: 'origin',
                type: 'address',
                value: from
            },
            {
                names: ['recipient', 'origin'],
                type: 'notEqual',
                msg: 'Cannot transfer UNW to the same account'
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            },
            {
                name: 'expired_time',
                type: 'integer',
                value: expiredTime
            }
        ], callback))
            return;

        const isFuture = expiredTime > 0;
       
        let data = {
            to_address: toHex(to),
            owner_address: toHex(from),
            amount: amount,
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }
        let apiPath = 'wallet/createtransaction'
        if (isFuture) {
            data.expire_time = expiredTime
            apiPath = 'wallet/createfuturetransaction'
        }
        this.unichainJS.fullNode.request(apiPath, data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    sendToken(to = false, amount = 0, tokenID = false, from = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(from)) {
            callback = from;
            from = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(from)) {
            options = from;
            from = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.sendToken, to, amount, tokenID, from, options);

        amount = parseInt(amount)
        if (this.validator.notValid([
            {
                name: 'recipient',
                type: 'address',
                value: to
            },
            {
                name: 'origin',
                type: 'address',
                value: from,
            },
            {
                names: ['recipient', 'origin'],
                type: 'notEqual',
                msg: 'Cannot transfer tokens to the same account'
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            },
            {
                name: 'token ID',
                type: 'tokenId',
                value: tokenID
            }
        ], callback))
            return;

        const data = {
            to_address: toHex(to),
            owner_address: toHex(from),
            asset_name: fromUtf8(tokenID),
            amount: parseInt(amount)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/transferasset', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    purchaseToken(issuerAddress = false, tokenID = false, amount = 0, buyer = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(buyer)) {
            callback = buyer;
            buyer = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(buyer)) {
            options = buyer;
            buyer = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.purchaseToken, issuerAddress, tokenID, amount, buyer, options);

        if (this.validator.notValid([
            {
                name: 'buyer',
                type: 'address',
                value: buyer
            },
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress
            },
            {
                names: ['buyer', 'issuer'],
                type: 'notEqual',
                msg: 'Cannot purchase tokens from same account'
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            },
            {
                name: 'token ID',
                type: 'tokenId',
                value: tokenID
            }
        ], callback))
            return;

        const data = {
            to_address: toHex(issuerAddress),
            owner_address: toHex(buyer),
            asset_name: fromUtf8(tokenID),
            amount: parseInt(amount)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/participateassetissue', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    freezeBalance(amount = 0, duration = 3, resource = "BANDWIDTH", address = this.unichainJS.defaultAddress.hex, receiverAddress = undefined, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(receiverAddress)) {
            callback = receiverAddress;
            receiverAddress = undefined;
        } else if (utils.isObject(receiverAddress)) {
            options = receiverAddress;
            receiverAddress = undefined;
        }

        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(address)) {
            options = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (utils.isFunction(duration)) {
            callback = duration;
            duration = 3;
        }

        if (utils.isFunction(resource)) {
            callback = resource;
            resource = "BANDWIDTH";
        }

        if (!callback)
            return this.injectPromise(this.freezeBalance, amount, duration, resource, address, receiverAddress, options);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: address
            },
            {
                name: 'receiver',
                type: 'address',
                value: receiverAddress,
                optional: true
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            },
            {
                name: 'duration',
                type: 'integer',
                gte: 3,
                value: duration
            },
            {
                name: 'resource',
                type: 'resource',
                value: resource,
                msg: 'Invalid resource provided: Expected "BANDWIDTH" or "ENERGY'
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(address),
            frozen_balance: parseInt(amount),
            frozen_duration: parseInt(duration),
            resource: resource
        }

        if (utils.isNotNullOrUndefined(receiverAddress) && toHex(receiverAddress) !== toHex(address)) {
            data.receiver_address = toHex(receiverAddress)
        }

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/freezebalance', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    unfreezeBalance(resource = "BANDWIDTH", address = this.unichainJS.defaultAddress.hex, receiverAddress = undefined, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(receiverAddress)) {
            callback = receiverAddress;
            receiverAddress = undefined;
        } else if (utils.isObject(receiverAddress)) {
            options = receiverAddress;
            receiverAddress = undefined;
        }

        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(address)) {
            options = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (utils.isFunction(resource)) {
            callback = resource;
            resource = "BANDWIDTH";
        }

        if (!callback)
            return this.injectPromise(this.unfreezeBalance, resource, address, receiverAddress, options);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: address
            },
            {
                name: 'receiver',
                type: 'address',
                value: receiverAddress,
                optional: true
            },
            {
                name: 'resource',
                type: 'resource',
                value: resource,
                msg: 'Invalid resource provided: Expected "BANDWIDTH" or "ENERGY'
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(address),
            resource: resource
        }

        if (utils.isNotNullOrUndefined(receiverAddress) && toHex(receiverAddress) !== toHex(address)) {
            data.receiver_address = toHex(receiverAddress)
        }

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/unfreezebalance', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    withdrawBlockRewards(address = this.unichainJS.defaultAddress.hex, options, callback = false) {
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
            return this.injectPromise(this.withdrawBlockRewards, address, options);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: address
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(address)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/withdrawbalance', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    applyForWitness(
        address = this.unichainJS.defaultAddress.hex,
        url = false,
        options,
        callback = false
    ) {
        console.log(toHex(address), utils.isObject(url))
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }
        if (utils.isObject(url) && utils.isValidURL(address)) {
            options = url;
            url = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.applyForWitness, address, url, options);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: address
            },
            {
                name: 'url',
                type: 'url',
                value: url,
                msg: 'Invalid url provided'
            }
        ], callback))
            return;

        console.log(toHex(address))

        const data = {
            owner_address: toHex(address),
            url: fromUtf8(url)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/createwitness', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    vote(votes = {}, voterAddress = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(voterAddress)) {
            callback = voterAddress;
            voterAddress = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(voterAddress)) {
            options = voterAddress;
            voterAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.vote, votes, voterAddress, options);

        if (this.validator.notValid([
            {
                name: 'voter',
                type: 'address',
                value: voterAddress
            },
            {
                name: 'votes',
                type: 'notEmptyObject',
                value: votes
            }
        ], callback))
            return;

        let invalid = false;

        votes = Object.entries(votes).map(([witnessAddress, voteCount]) => {
            if (invalid)
                return;

            if (this.validator.notValid([
                {
                    name: 'Witness',
                    type: 'address',
                    value: witnessAddress
                },
                {
                    name: 'vote count',
                    type: 'integer',
                    gt: 0,
                    value: voteCount,
                    msg: 'Invalid vote count provided for Witness: ' + witnessAddress
                }
            ]))
                return invalid = true;

            return {
                vote_address: toHex(witnessAddress),
                vote_count: parseInt(voteCount)
            };
        });

        if (invalid)
            return;

        const data = {
            owner_address: toHex(voterAddress),
            votes,
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/votewitnessaccount', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    createSmartContract(options = {}, issuerAddress = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createSmartContract, options, issuerAddress);

        const feeLimit = options.feeLimit || 1_000_000_000;
        let userFeePercentage = options.userFeePercentage;
        if (typeof userFeePercentage !== 'number' && !userFeePercentage) {
            userFeePercentage = 100;
        }
        const originEnergyLimit = options.originEnergyLimit || 10_000_000;
        const callValue = options.callValue || 0;
        const tokenValue = options.tokenValue;
        const tokenId = options.tokenId || options.token_id;

        let {
            abi = false,
            bytecode = false,
            parameters = [],
            name = ""
        } = options;

        if (abi && utils.isString(abi)) {
            try {
                abi = JSON.parse(abi);
            } catch {
                return callback('Invalid options.abi provided');
            }
        }

        if (abi.entrys)
            abi = abi.entrys;

        if (!utils.isArray(abi))
            return callback('Invalid options.abi provided');


        const payable = abi.some(func => {
            return func.type == 'constructor' && func.payable;
        });

        if (this.validator.notValid([
            {
                name: 'bytecode',
                type: 'hex',
                value: bytecode
            },
            {
                name: 'feeLimit',
                type: 'integer',
                value: feeLimit,
                gt: 0,
                lte: 1_000_000_000
            },
            {
                name: 'callValue',
                type: 'integer',
                value: callValue,
                gte: 0
            },
            {
                name: 'userFeePercentage',
                type: 'integer',
                value: userFeePercentage,
                gte: 0,
                lte: 100
            },
            {
                name: 'originEnergyLimit',
                type: 'integer',
                value: originEnergyLimit,
                gte: 0,
                lte: 10_000_000
            },
            {
                name: 'parameters',
                type: 'array',
                value: parameters
            },
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress
            },
            {
                name: 'tokenValue',
                type: 'integer',
                value: tokenValue,
                gte: 0,
                optional: true
            },
            {
                name: 'tokenId',
                type: 'integer',
                value: tokenId,
                gte: 0,
                optional: true
            }
        ], callback))
            return;

        if (payable && callValue == 0 && tokenValue == 0)
            return callback('When contract is payable, options.callValue or options.tokenValue must be a positive integer');

        if (!payable && (callValue > 0 || tokenValue > 0))
            return callback('When contract is not payable, options.callValue and options.tokenValue must be 0');


        var constructorParams = abi.find(
            (it) => {
                return it.type === 'constructor';
            }
        );

        if (typeof constructorParams !== 'undefined' && constructorParams) {
            const abiCoder = new AbiCoder();
            const types = [];
            const values = [];
            constructorParams = constructorParams.inputs;

            if (parameters.length != constructorParams.length)
                return callback(`constructor needs ${constructorParams.length} but ${parameters.length} provided`);

            for (let i = 0; i < parameters.length; i++) {
                let type = constructorParams[i].type;
                let value = parameters[i];

                if (!type || !utils.isString(type) || !type.length)
                    return callback('Invalid parameter type provided: ' + type);

                if (type == 'address')
                    value = toHex(value).replace(ADDRESS_PREFIX_REGEX, '0x');

                types.push(type);
                values.push(value);
            }

            try {
                parameters = abiCoder.encode(types, values).replace(/^(0x)/, '');
            } catch (ex) {
                return callback(ex);
            }
        } else parameters = '';

        const args = {
            owner_address: toHex(issuerAddress),
            fee_limit: parseInt(feeLimit),
            call_value: parseInt(callValue),
            consume_user_resource_percent: userFeePercentage,
            origin_energy_limit: originEnergyLimit,
            abi: JSON.stringify(abi),
            bytecode,
            parameter: parameters,
            name
        };

        // tokenValue and tokenId can cause errors if provided when the  proposal has not been approved yet. So we set them only if they are passed to the method.
        if (utils.isNotNullOrUndefined(tokenValue))
            args.call_token_value = parseInt(tokenValue)
        if (utils.isNotNullOrUndefined(tokenId))
            args.token_id = parseInt(tokenId)
        if (options && options.permissionId)
            args.Permission_id = options.permissionId;

        this.unichainJS.fullNode.request('wallet/deploycontract', args, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    triggerSmartContract(...params) {
        if (typeof params[2] !== 'object') {
            params[2] = {
                feeLimit: params[2],
                callValue: params[3]
            }
            params.splice(3, 1)
        }
        return this._triggerSmartContract(...params);
    }

    triggerConstantContract(...params) {
        params[2]._isConstant = true
        return this.triggerSmartContract(...params);
    }

    triggerConfirmedConstantContract(...params) {
        params[2]._isConstant = true
        params[2].confirmed = true
        return this.triggerSmartContract(...params);
    }

    _triggerSmartContract(
        contractAddress,
        functionSelector,
        options = {},
        parameters = [],
        issuerAddress = this.unichainJS.defaultAddress.hex,
        callback = false
    ) {

        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (utils.isFunction(parameters)) {
            callback = parameters;
            parameters = [];
        }

        if (!callback) {
            return this.injectPromise(
                this._triggerSmartContract,
                contractAddress,
                functionSelector,
                options,
                parameters,
                issuerAddress
            );
        }

        let {
            tokenValue,
            tokenId,
            callValue,
            feeLimit,
        } = Object.assign({
            callValue: 0,
            feeLimit: 1_000_000_000
        }, options)

        if (this.validator.notValid([
            {
                name: 'feeLimit',
                type: 'integer',
                value: feeLimit,
                gt: 0,
                lte: 1_000_000_000
            },
            {
                name: 'callValue',
                type: 'integer',
                value: callValue,
                gte: 0
            },
            {
                name: 'parameters',
                type: 'array',
                value: parameters
            },
            {
                name: 'contract',
                type: 'address',
                value: contractAddress
            },
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress,
                optional: true
            },
            {
                name: 'tokenValue',
                type: 'integer',
                value: tokenValue,
                gte: 0,
                optional: true
            },
            {
                name: 'tokenId',
                type: 'integer',
                value: tokenId,
                gte: 0,
                optional: true
            },
            {
                name: 'function selector',
                type: 'not-empty-string',
                value: functionSelector
            }
        ], callback))
            return;

        functionSelector = functionSelector.replace('/\s*/g', '');

        if (parameters.length) {
            const abiCoder = new AbiCoder();
            let types = [];
            const values = [];

            for (let i = 0; i < parameters.length; i++) {
                let {type, value} = parameters[i];

                if (!type || !utils.isString(type) || !type.length)
                    return callback('Invalid parameter type provided: ' + type);

                if (type == 'address')
                    value = toHex(value).replace(ADDRESS_PREFIX_REGEX, '0x');

                types.push(type);
                values.push(value);
            }

            try {
                parameters = abiCoder.encode(types, values).replace(/^(0x)/, '');
            } catch (ex) {
                return callback(ex);
            }
        } else parameters = '';

        const args = {
            contract_address: toHex(contractAddress),
            owner_address: toHex(issuerAddress),
            function_selector: functionSelector,
            parameter: parameters
        };

        if (!options._isConstant) {
            args.call_value = parseInt(callValue)
            args.fee_limit = parseInt(feeLimit)
            if (utils.isNotNullOrUndefined(tokenValue))
                args.call_token_value = parseInt(tokenValue)
            if (utils.isNotNullOrUndefined(tokenId))
                args.token_id = parseInt(tokenId)
        }

        if (options.permissionId) {
            args.Permission_id = options.permissionId;
        }

        this.unichainJS[options.confirmed ? 'solidityNode' : 'fullNode'].request(`wallet${options.confirmed ? 'solidity' : ''}/trigger${options._isConstant ? 'constant' : 'smart'}contract`, args, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    clearABI(contractAddress, ownerAddress = this.unichainJS.defaultAddress.hex, callback = false) {
        if (!callback)
            return this.injectPromise(this.clearABI, contractAddress, ownerAddress);

        if (!this.unichainJS.isAddress(contractAddress))
            return callback('Invalid contract address provided');

        if (!this.unichainJS.isAddress(ownerAddress))
            return callback('Invalid owner address provided');

        const data = {
            contract_address: toHex(contractAddress),
            owner_address: toHex(ownerAddress)
        };

        if (this.unichainJS.api.cache.contracts[contractAddress]) {
            delete this.unichainJS.api.cache.contracts[contractAddress]
        }
        this.unichainJS.fullNode.request('wallet/clearabi', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));

    }

    updateBrokerage(brokerage, ownerAddress = this.unichainJS.defaultAddress.hex, callback = false) {
        if (!callback)
            return this.injectPromise(this.updateBrokerage, brokerage, ownerAddress);

        if (!utils.isNotNullOrUndefined(brokerage))
            return callback('Invalid brokerage provided');

        if (!utils.isInteger(brokerage) || brokerage < 0 || brokerage > 100)
            return callback('Brokerage must be an integer between 0 and 100');

        if (!this.unichainJS.isAddress(ownerAddress))
            return callback('Invalid owner address provided');

        const data = {
            brokerage: parseInt(brokerage),
            owner_address: toHex(ownerAddress)
        };

        this.unichainJS.fullNode.request('wallet/updateBrokerage', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));

    }

    createToken(options = {}, issuerAddress = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createToken, options, issuerAddress);

        const {
            name = false,
            abbreviation = false,
            description = false,
            url = false,
            totalSupply = 0,
            unxRatio = 1, // How much UNW will `tokenRatio` cost?
            tokenRatio = 1, // How many tokens will `unwRatio` afford?
            saleStart = Date.now(),
            saleEnd = false,
            freeBandwidth = 0, // The creator's "donated" bandwidth for use by token holders
            freeBandwidthLimit = 0, // Out of `totalFreeBandwidth`, the amount each token holder get
            frozenAmount = 0,
            frozenDuration = 0,
            // for now there is no default for the following values
            voteScore,
            precision
        } = options;

        if (this.validator.notValid([
            {
                name: 'Supply amount',
                type: 'positive-integer',
                value: totalSupply
            },
            {
                name: 'UNW ratio',
                type: 'positive-integer',
                value: unxRatio
            },
            {
                name: 'Token ratio',
                type: 'positive-integer',
                value: tokenRatio
            },
            {
                name: 'token abbreviation',
                type: 'not-empty-string',
                value: abbreviation
            },
            {
                name: 'token name',
                type: 'not-empty-string',
                value: name
            },
            {
                name: 'token description',
                type: 'not-empty-string',
                value: description
            },
            {
                name: 'token url',
                type: 'url',
                value: url
            },
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress
            },
            {
                name: 'sale start timestamp',
                type: 'integer',
                value: saleStart,
                gte: Date.now()
            },
            {
                name: 'sale end timestamp',
                type: 'integer',
                value: saleEnd,
                gt: saleStart
            },
            {
                name: 'Free bandwidth amount',
                type: 'integer',
                value: freeBandwidth,
                gte: 0
            },
            {
                name: 'Free bandwidth limit',
                type: 'integer',
                value: freeBandwidthLimit,
                gte: 0
            },
            {
                name: 'Frozen supply',
                type: 'integer',
                value: frozenAmount,
                gte: 0
            },
            {
                name: 'Frozen duration',
                type: 'integer',
                value: frozenDuration,
                gte: 0
            }
        ], callback))
            return;

        if (utils.isNotNullOrUndefined(voteScore) && (!utils.isInteger(voteScore) || voteScore <= 0))
            return callback('voteScore must be a positive integer greater than 0');

        if (utils.isNotNullOrUndefined(precision) && (!utils.isInteger(precision) || precision <= 0 || precision > 6))
            return callback('precision must be a positive integer > 0 and <= 6');

        const data = {
            owner_address: toHex(issuerAddress),
            name: fromUtf8(name),
            abbr: fromUtf8(abbreviation),
            description: fromUtf8(description),
            url: fromUtf8(url),
            total_supply: parseInt(totalSupply),
            unx_num: parseInt(unxRatio),
            num: parseInt(tokenRatio),
            start_time: parseInt(saleStart),
            end_time: parseInt(saleEnd),
            free_asset_net_limit: parseInt(freeBandwidth),
            public_free_asset_net_limit: parseInt(freeBandwidthLimit),
            frozen_supply: {
                frozen_amount: parseInt(frozenAmount),
                frozen_days: parseInt(frozenDuration)
            }
        }
        if (this.unichainJS.fullnodeSatisfies('>=3.5.0') && !(parseInt(frozenAmount) > 0)) {
            delete data.frozen_supply
        }
        if (precision && !isNaN(parseInt(precision))) {
            data.precision = parseInt(precision);
        }
        if (voteScore && !isNaN(parseInt(voteScore))) {
            data.vote_score = parseInt(voteScore)
        }
        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/createassetissue', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    createURC30Token(options = {}, issuerAddress = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createURC30Token, options, issuerAddress);

        const {
            name,
            abbr,
            max_supply,
            total_supply,
            start_time,
            end_time,
            description,
            url,
            fee,
            extra_fee_rate,
            create_acc_fee,
            fee_pool,
            lot,
            exch_unx_num,
            exch_num,
            owner_address
        } = options;

        if (this.validator.notValid([
            {
                name: 'token name',
                type: 'not-empty-string',
                value: name
            },
            {
                name: 'token abbr',
                type: 'not-empty-string',
                value: abbr
            },
            {
                name: 'Init amount',
                type: 'positive-integer',
                value: total_supply
            },
            {
                name: 'Max amount',
                type: 'positive-integer',
                value: max_supply
            },
            {
                name: 'UNW exchange ratio',
                type: 'positive-integer',
                value: exch_unx_num
            },
            {
                name: 'Token ratio',
                type: 'positive-integer',
                value: exch_num
            },
            {
                name: 'token description',
                type: 'not-empty-string',
                value: description
            },
            {
                name: 'token url',
                type: 'url',
                value: url
            },
            {
                name: 'address',
                type: 'address',
                value: owner_address
            },
            {
                name: 'Start time',
                type: 'integer',
                value: start_time,
                gte: Date.now()
            },
            {
                name: 'End time',
                type: 'integer',
                value: end_time,
                gt: start_time
            },
            {
                name: 'Fee',
                type: 'integer',
                value: fee
            },
            {
                name: 'Extra fee rate in %',
                type: 'integer',
                value: extra_fee_rate,
                lt: 100
            },
            {
                name: 'Fee pool',
                type: 'integer',
                value: fee_pool,
                gte: 10000000
            },
            {
                name: 'Lot',
                type: 'integer',
                value: lot
            },
            {
                name: 'Create account fee',
                type: 'integer',
                value: create_acc_fee
            },
        ], callback))
            return;

        const data = {
            owner_address: toHex(owner_address),
            name: name,
            abbr: abbr,
            description: description,
            url: url,
            total_supply: parseInt(total_supply),
            max_supply: parseInt(max_supply),
            exch_unx_num: parseInt(exch_unx_num),
            exch_num: parseInt(exch_num),
            start_time: parseInt(start_time),
            end_time: parseInt(end_time),
            fee: parseInt(fee),
            extra_fee_rate: parseInt(extra_fee_rate),
            create_acc_fee: parseInt(create_acc_fee),
            fee_pool: parseInt(fee_pool),
            lot: parseInt(lot)

        }
        
        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/createtoken', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    sendURC30Token(to = false, amount = 0, tokenName = false, availableTime = 0, from = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(from)) {
            callback = from;
            from = this.unichainJS.defaultAddress.hex;
        } 

        if (!callback)
            return this.injectPromise(this.sendURC30Token, to, amount, tokenName, availableTime, from);

        if (this.validator.notValid([
            {
                name: 'recipient',
                type: 'address',
                value: to
            },
            {
                name: 'origin',
                type: 'address',
                value: from,
            },
            {
                names: ['recipient', 'origin'],
                type: 'notEqual',
                msg: 'Cannot transfer tokens to the same account'
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            },
            {
                name: 'available time',
                type: 'integer',
                value: availableTime
            },
            {
                name: 'token name (id)',
                type: 'not-empty-string',
                value: tokenName
            }
        ], callback))
            return;

        const data = {
            to_address: toHex(to),
            owner_address: toHex(from),
            token_name: tokenName,
            amount: parseInt(amount)
        };

        if (availableTime) {
            data.available_time = availableTime;
        }

        this.unichainJS.fullNode.request('wallet/transfertoken', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    contributeTokenFee(tokenName, amount, from = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(from)) {
            callback = from;
            from = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.contributeTokenFee, tokenName, amount, from);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: from,
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 100000,
                value: amount,
                msg: 'min amount contribution is 0.1 UNW'
            },
            {
                name: 'token name (id)',
                type: 'not-empty-string',
                value: tokenName
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(from),
            token_name: tokenName,
            amount: parseInt(amount)
        };

        this.unichainJS.fullNode.request('wallet/contributetokenfee', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    mintToken(tokenName, amount, from = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(from)) {
            callback = from;
            from = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.mintToken, tokenName, amount, from);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: from,
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            },
            {
                name: 'token name (id)',
                type: 'not-empty-string',
                value: tokenName
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(from),
            token_name: tokenName,
            amount: parseInt(amount)
        };

        this.unichainJS.fullNode.request('wallet/minetoken', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    burnToken(tokenName, amount, from = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(from)) {
            callback = from;
            from = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.burnToken, tokenName, amount, from);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: from,
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            },
            {
                name: 'token name (id)',
                type: 'not-empty-string',
                value: tokenName
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(from),
            token_name: tokenName,
            amount: parseInt(amount)
        };

        this.unichainJS.fullNode.request('wallet/burntoken', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    withdrawFutureToken(tokenName, from = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(from)) {
            callback = from;
            from = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.withdrawFutureToken, tokenName, from);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: from,
            },
            {
                name: 'token name (id)',
                type: 'not-empty-string',
                value: tokenName
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(from),
            token_name: tokenName
        };

        this.unichainJS.fullNode.request('wallet/withdrawfuturetoken', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    transferTokenOwner(tokenName, to, from = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(from)) {
            callback = from;
            from = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.transferTokenOwner, tokenName, to, from);

        if (this.validator.notValid([
            {
                name: 'recipient',
                type: 'address',
                value: to
            },
            {
                name: 'origin',
                type: 'address',
                value: from,
            },
            {
                names: ['recipient', 'origin'],
                type: 'notEqual',
                msg: 'Cannot transfer ownership to the same account'
            },
            {
                name: 'token name (id)',
                type: 'not-empty-string',
                value: tokenName
            }
        ], callback))
            return;

        const data = {
            to_address: toHex(to),
            owner_address: toHex(from),
            token_name: tokenName
        };

        this.unichainJS.fullNode.request('wallet/transfertokenowner', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    updateAccount(accountName = false, address = this.unichainJS.defaultAddress.hex, options, callback = false) {
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

        if (!callback) {
            return this.injectPromise(this.updateAccount, accountName, address, options);
        }

        if (this.validator.notValid([
            {
                name: 'Name',
                type: 'not-empty-string',
                value: accountName
            },
            {
                name: 'origin',
                type: 'address',
                value: address
            }
        ], callback))
            return;

        const data = {
            account_name: fromUtf8(accountName),
            owner_address: toHex(address),
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/updateaccount', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    setAccountId(accountId, address = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.unichainJS.defaultAddress.hex;
        }

        if (!callback) {
            return this.injectPromise(this.setAccountId, accountId, address);
        }

        if (accountId && utils.isString(accountId) && accountId.startsWith('0x')) {
            accountId = accountId.slice(2);
        }

        if (this.validator.notValid([
            {
                name: 'accountId',
                type: 'hex',
                value: accountId
            },
            {
                name: 'accountId',
                type: 'string',
                lte: 32,
                gte: 8,
                value: accountId
            },
            {
                name: 'origin',
                type: 'address',
                value: address
            }
        ], callback))
            return;


        this.unichainJS.fullNode.request('wallet/setaccountid', {
            account_id: accountId,
            owner_address: toHex(address),
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    updateToken(options = {}, issuerAddress = this.unichainJS.defaultAddress.hex, callback = false) {
        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(issuerAddress)) {
            options = issuerAddress;
            issuerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.updateToken, options, issuerAddress);

        const {
            description = false,
            url = false,
            freeBandwidth = 0, // The creator's "donated" bandwidth for use by token holders
            freeBandwidthLimit = 0 // Out of `totalFreeBandwidth`, the amount each token holder get
        } = options;


        if (this.validator.notValid([
            {
                name: 'token description',
                type: 'not-empty-string',
                value: description
            },
            {
                name: 'token url',
                type: 'url',
                value: url
            },
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress
            },
            {
                name: 'Free bandwidth amount',
                type: 'positive-integer',
                value: freeBandwidth
            },
            {
                name: 'Free bandwidth limit',
                type: 'positive-integer',
                value: freeBandwidthLimit
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(issuerAddress),
            description: fromUtf8(description),
            url: fromUtf8(url),
            new_limit: parseInt(freeBandwidth),
            new_public_limit: parseInt(freeBandwidthLimit)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/updateasset', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    sendAsset(...args) {
        return this.sendToken(...args);
    }

    purchaseAsset(...args) {
        return this.purchaseToken(...args);
    }

    createAsset(...args) {
        return this.createToken(...args);
    }

    updateAsset(...args) {
        return this.updateToken(...args);
    }

    /**
     * Creates a proposal to modify the network.
     * Can only be created by a current Witness.
     */
    createProposal(parameters = false, issuerAddress = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(issuerAddress)) {
            options = issuerAddress;
            issuerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createProposal, parameters, issuerAddress, options);

        if (this.validator.notValid([
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress
            }
        ], callback))
            return;

        const invalid = 'Invalid proposal parameters provided';

        if (!parameters)
            return callback(invalid);

        if (!utils.isArray(parameters))
            parameters = [parameters];

        for (let parameter of parameters) {
            if (!utils.isObject(parameter))
                return callback(invalid);
        }

        const data = {
            owner_address: toHex(issuerAddress),
            parameters: parameters
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/proposalcreate', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Deletes a network modification proposal that the owner issued.
     * Only current Witness can vote on a proposal.
     */
    deleteProposal(proposalID = false, issuerAddress = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(issuerAddress)) {
            options = issuerAddress;
            issuerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.deleteProposal, proposalID, issuerAddress, options);

        if (this.validator.notValid([
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress
            },
            {
                name: 'proposalID',
                type: 'integer',
                value: proposalID,
                gte: 0
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(issuerAddress),
            proposal_id: parseInt(proposalID)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/proposaldelete', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Adds a vote to an issued network modification proposal.
     * Only current Witness can vote on a proposal.
     */
    voteProposal(proposalID = false, isApproval = false, voterAddress = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(voterAddress)) {
            callback = voterAddress;
            voterAddress = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(voterAddress)) {
            options = voterAddress;
            voterAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.voteProposal, proposalID, isApproval, voterAddress, options);

        if (this.validator.notValid([
            {
                name: 'voter',
                type: 'address',
                value: voterAddress
            },
            {
                name: 'proposalID',
                type: 'integer',
                value: proposalID,
                gte: 0
            },
            {
                name: 'has approval',
                type: 'boolean',
                value: isApproval
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(voterAddress),
            proposal_id: parseInt(proposalID),
            is_add_approval: isApproval
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/proposalapprove', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Create an exchange between a token and UNW.
     * Token Name should be a CASE SENSITIVE string.
     * PLEASE VERIFY THIS ON Unichain Explorer.
     */
    createUNWExchange(tokenName, tokenBalance, unwBalance, ownerAddress = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createUNWExchange, tokenName, tokenBalance, unwBalance, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'token name',
                type: 'not-empty-string',
                value: tokenName
            },
            {
                name: 'token balance',
                type: 'positive-integer',
                value: tokenBalance
            },
            {
                name: 'unw balance',
                type: 'positive-integer',
                value: unwBalance
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            first_token_id: fromUtf8(tokenName),
            first_token_balance: tokenBalance,
            second_token_id: '5f', // Constant for UNW.
            second_token_balance: unwBalance
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/exchangecreate', data, 'post').then(resources => {
            callback(null, resources);
        }).catch(err => callback(err));
    }

    /**
     * Create an exchange between a token and another token.
     * DO NOT USE THIS FOR UNW.
     * Token Names should be a CASE SENSITIVE string.
     * PLEASE VERIFY THIS ON Unichain Explorer.
     */
    createTokenExchange(firstTokenName, firstTokenBalance, secondTokenName, secondTokenBalance, ownerAddress = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createTokenExchange, firstTokenName, firstTokenBalance, secondTokenName, secondTokenBalance, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'first token name',
                type: 'not-empty-string',
                value: firstTokenName
            },
            {
                name: 'second token name',
                type: 'not-empty-string',
                value: secondTokenName
            },
            {
                name: 'first token balance',
                type: 'positive-integer',
                value: firstTokenBalance
            },
            {
                name: 'second token balance',
                type: 'positive-integer',
                value: secondTokenBalance
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            first_token_id: fromUtf8(firstTokenName),
            first_token_balance: firstTokenBalance,
            second_token_id: fromUtf8(secondTokenName),
            second_token_balance: secondTokenBalance
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/exchangecreate', data, 'post').then(resources => {
            callback(null, resources);
        }).catch(err => callback(err));
    }

    /**
     * Adds tokens into a bancor style exchange.
     * Will add both tokens at market rate.
     * Use "_" for the constant value for UNW.
     */
    injectExchangeTokens(exchangeID = false, tokenName = false, tokenAmount = 0, ownerAddress = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.injectExchangeTokens, exchangeID, tokenName, tokenAmount, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'token name',
                type: 'not-empty-string',
                value: tokenName
            },
            {
                name: 'token amount',
                type: 'integer',
                value: tokenAmount,
                gte: 1
            },
            {
                name: 'exchangeID',
                type: 'integer',
                value: exchangeID,
                gte: 0
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            exchange_id: parseInt(exchangeID),
            token_id: fromUtf8(tokenName),
            quant: parseInt(tokenAmount)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/exchangeinject', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Withdraws tokens from a bancor style exchange.
     * Will withdraw at market rate both tokens.
     * Use "_" for the constant value for UNW.
     */
    withdrawExchangeTokens(exchangeID = false, tokenName = false, tokenAmount = 0, ownerAddress = this.unichainJS.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.withdrawExchangeTokens, exchangeID, tokenName, tokenAmount, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'token name',
                type: 'not-empty-string',
                value: tokenName
            },
            {
                name: 'token amount',
                type: 'integer',
                value: tokenAmount,
                gte: 1
            },
            {
                name: 'exchangeID',
                type: 'integer',
                value: exchangeID,
                gte: 0
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            exchange_id: parseInt(exchangeID),
            token_id: fromUtf8(tokenName),
            quant: parseInt(tokenAmount)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/exchangewithdraw', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Trade tokens on a bancor style exchange.
     * Expected value is a validation and used to cap the total amt of token 2 spent.
     * Use "_" for the constant value for UNW.
     */
    tradeExchangeTokens(exchangeID = false,
                        tokenName = false,
                        tokenAmountSold = 0,
                        tokenAmountExpected = 0,
                        ownerAddress = this.unichainJS.defaultAddress.hex,
                        options,
                        callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.tradeExchangeTokens, exchangeID, tokenName, tokenAmountSold, tokenAmountExpected, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'token name',
                type: 'not-empty-string',
                value: tokenName
            },
            {
                name: 'tokenAmountSold',
                type: 'integer',
                value: tokenAmountSold,
                gte: 1
            },
            {
                name: 'tokenAmountExpected',
                type: 'integer',
                value: tokenAmountExpected,
                gte: 1
            },
            {
                name: 'exchangeID',
                type: 'integer',
                value: exchangeID,
                gte: 0
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            exchange_id: parseInt(exchangeID),
            token_id: this.unichainJS.fromAscii(tokenName),
            quant: parseInt(tokenAmountSold),
            expected: parseInt(tokenAmountExpected)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/exchangetransaction', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Update userFeePercentage.
     */
    updateSetting(contractAddress = false,
                  userFeePercentage = false,
                  ownerAddress = this.unichainJS.defaultAddress.hex,
                  options,
                  callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.updateSetting, contractAddress, userFeePercentage, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'contract',
                type: 'address',
                value: contractAddress
            },
            {
                name: 'userFeePercentage',
                type: 'integer',
                value: userFeePercentage,
                gte: 0,
                lte: 100
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            contract_address: toHex(contractAddress),
            consume_user_resource_percent: userFeePercentage
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/updatesetting', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Update energy limit.
     */
    updateEnergyLimit(contractAddress = false,
                      originEnergyLimit = false,
                      ownerAddress = this.unichainJS.defaultAddress.hex,
                      options,
                      callback = false) {

        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        } else if (utils.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.unichainJS.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.updateEnergyLimit, contractAddress, originEnergyLimit, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'contract',
                type: 'address',
                value: contractAddress
            },
            {
                name: 'originEnergyLimit',
                type: 'integer',
                value: originEnergyLimit,
                gte: 0,
                lte: 10_000_000
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            contract_address: toHex(contractAddress),
            origin_energy_limit: originEnergyLimit
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.unichainJS.fullNode.request('wallet/updateenergylimit', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    checkPermissions(permissions, type) {
        if (permissions) {
            if (permissions.type !== type
                || !permissions.permission_name
                || !utils.isString(permissions.permission_name)
                || !utils.isInteger(permissions.threshold)
                || permissions.threshold < 1
                || !permissions.keys
            ) {
                return false
            }
            for (let key of permissions.keys) {
                if (!this.unichainJS.isAddress(key.address)
                    || !utils.isInteger(key.weight)
                    || key.weight > permissions.threshold
                    || key.weight < 1
                    || (type === 2 && !permissions.operations)
                ) {
                    return false
                }
            }
        }
        return true
    }

    updateAccountPermissions(ownerAddress = this.unichainJS.defaultAddress.hex,
                             ownerPermissions = false,
                             witnessPermissions = false,
                             activesPermissions = false,
                             callback = false) {

        if (utils.isFunction(activesPermissions)) {
            callback = activesPermissions;
            activesPermissions = false;
        }

        if (utils.isFunction(witnessPermissions)) {
            callback = witnessPermissions;
            witnessPermissions = activesPermissions = false;
        }

        if (utils.isFunction(ownerPermissions)) {
            callback = ownerPermissions;
            ownerPermissions = witnessPermissions = activesPermissions = false;
        }

        if (!callback)
            return this.injectPromise(this.updateAccountPermissions, ownerAddress, ownerPermissions, witnessPermissions, activesPermissions);

        if (!this.unichainJS.isAddress(ownerAddress))
            return callback('Invalid ownerAddress provided');

        if (!this.checkPermissions(ownerPermissions, 0)) {
            return callback('Invalid ownerPermissions provided');
        }

        if (!this.checkPermissions(witnessPermissions, 1)) {
            return callback('Invalid witnessPermissions provided');
        }

        if (!Array.isArray(activesPermissions)) {
            activesPermissions = [activesPermissions]
        }

        for (let activesPermission of activesPermissions) {
            if (!this.checkPermissions(activesPermission, 2)) {
                return callback('Invalid activesPermissions provided');
            }
        }

        const data = {
            owner_address: ownerAddress
        }
        if (ownerPermissions) {
            data.owner = ownerPermissions
        }
        if (witnessPermissions) {
            data.witness = witnessPermissions
        }
        if (activesPermissions) {
            data.actives = activesPermissions.length === 1 ? activesPermissions[0] : activesPermissions
        }

        this.unichainJS.fullNode.request('wallet/accountpermissionupdate', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    async newTxID(transaction, callback) {

        if (!callback)
            return this.injectPromise(this.newTxID, transaction);

        this.unichainJS.fullNode
            .request(
                'wallet/getsignweight',
                transaction,
                'post'
            )
            .then(newTransaction => {
                newTransaction = newTransaction.transaction.transaction
                if (typeof transaction.visible === 'boolean') {
                    newTransaction.visible = transaction.visible
                }
                callback(null, newTransaction)
            })
            .catch(err => callback('Error generating a new transaction id.'));
    }

    async alterTransaction(transaction, options = {}, callback = false) {
        if (!callback)
            return this.injectPromise(this.alterTransaction, transaction, options);

        if (transaction.signature)
            return callback('You can not extend the expiration of a signed transaction.')

        if (options.data) {
            if (options.dataFormat !== 'hex')
                options.data = this.unichainJS.toHex(options.data);
            options.data = options.data.replace(/^0x/, '')
            if (options.data.length === 0)
                return callback('Invalid data provided');
            transaction.raw_data.data = options.data;
        }

        if (options.extension) {
            options.extension = parseInt(options.extension * 1000);
            if (isNaN(options.extension) || transaction.raw_data.expiration + options.extension <= Date.now() + 3000)
                return callback('Invalid extension provided');
            transaction.raw_data.expiration += options.extension;
        }

        this.newTxID(transaction, callback)
    }

    async extendExpiration(transaction, extension, callback = false) {
        if (!callback)
            return this.injectPromise(this.extendExpiration, transaction, extension);

        this.alterTransaction(transaction, {extension}, callback);
    }

    async addUpdateData(transaction, data, dataFormat = 'utf8', callback = false) {

        if (utils.isFunction(dataFormat)) {
            callback = dataFormat;
            dataFormat = 'utf8';
        }

        if (!callback)
            return this.injectPromise(this.addUpdateData, transaction, data, dataFormat);

        this.alterTransaction(transaction, {data, dataFormat}, callback);
    }

    /* NEW CONTRACT POSBRIGDE */
    /**
     * endpoint: /wallet/posbridgesetup
     * @param {*} owner_address 
     * @param {*} new_owner 
     * @param {*} min_validator 
     * @param {*} validators 
     * @param {*} consensus_rate 
     * @param {*} predicate_native 
     * @param {*} predicate_token
     * @param {*} predicate_nft
     * @param {*} options 
     * @param {*} callback 
     * @returns unsigned transaction data
     */
    posBridgeSetup(owner_address, new_owner, min_validator = 1, validators = [], consensus_rate, predicate_native, predicate_token, predicate_nft, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.setupPosBridge, owner_address, new_owner, min_validator, validators, consensus_rate, predicate_native, predicate_token, predicate_nft, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            new_owner: toHex(new_owner),
            min_validator,
            validators,
            consensus_rate, 
            predicate_native,
            predicate_token, 
            predicate_nft
        };

        let apiPath = 'wallet/posbridgesetup'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * endpoint: /posbridgemaptoken
     * @param {*} owner_address 
     * @param {*} root_chainid 
     * @param {*} root_token [hex address if token, symbol if native]
     * @param {*} child_chainid 
     * @param {*} child_token [hex address]
     * @param {*} type 
     * 1: native
     * 2: erc20
     * 3: erc721]
     * @param {*} options 
     * @param {*} callback 
     * @returns unsigned transaction data
     */
    posBridgeMapToken(owner_address, root_chainid, root_token, child_chainid, child_token, type, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.posBridgeMapToken, owner_address, root_chainid, root_token, child_chainid, child_token, type, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            root_chainid, 
            root_token, 
            child_chainid, 
            child_token, 
            type
        };

        let apiPath = 'wallet/posbridgemaptoken'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * endpoint: /posbridgecleanmaptoken
     * @param {*} owner_address 
     * @param {*} root_chainid 
     * @param {*} root_token 
     * @param {*} child_chainid 
     * @param {*} child_token 
     * @param {*} options 
     * @param {*} callback 
     * @returns unsigned transaction data
     */
    posBridgeCleanMapToken(owner_address, root_chainid, root_token, child_chainid, child_token, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.posBridgeCleanMapToken, owner_address, root_chainid, root_token, child_chainid, child_token, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            root_chainid, 
            root_token, 
            child_chainid, 
            child_token, 
        };

        let apiPath = 'wallet/posbridgecleanmaptoken'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * endpoint: /posbridgedeposit
     * @param {*} owner_address 
     * @param {*} root_token [hex address if token, unw if native]
     * @param {*} child_chainid 
     * @param {*} receive_address 
     * @param {*} data [amount or token id]
     * @param {*} options 
     * @param {*} callback 
     * @returns unsigned transaction data
     */
    posBridgeDeposit(owner_address, root_token, child_chainid, receive_address, data, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.posBridgeDeposit, owner_address, root_token, child_chainid, receive_address, data, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            root_token, 
            child_chainid, 
            receive_address, 
            data
        };

        let apiPath = 'wallet/posbridgedeposit'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * endpoint: /posbridgedepositexec
     * @param {*} owner_address 
     * @param {*} signatures [rlp encoded]
     * @param {*} message [rlp encoded]
     * @param {*} options 
     * @param {*} callback 
     * @returns unsigned transaction data
     */
    posBridgeDepositExec(owner_address, signatures, message, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.posBridgeDepositExec, owner_address, calldata, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            signatures,
            message,
        };

        let apiPath = 'wallet/posbridgedepositexec'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * endpoint: /posbridgewithdraw
     * @param {*} owner_address 
     * @param {*} child_token 
     * @param {*} receive_address 
     * @param {*} data [amount or tokenid]
     * @param {*} options 
     * @param {*} callback 
     * @returns unsigned transaction data 
     */
    posBridgeWithdraw(owner_address, child_token, receive_address, data, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.posBridgeWithdraw, owner_address, child_token, receive_address, data, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            child_token, 
            receive_address, 
            data
        };

        let apiPath = 'wallet/posbridgewithdraw'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * endpoint: /posbridgewithdrawexec
     * @param {*} owner_address 
     * @param {*} signatures [rlp encoded]
     * @param {*} message [rlp encoded]
     * @param {*} options 
     * @param {*} callback 
     * @returns unsigned transaction data 
     */
    posBridgeWithdrawExec(owner_address, signatures, message, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.posBridgeWithdrawExec, owner_address, signatures, message, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            signatures,
            message,
        };

        let apiPath = 'wallet/posbridgewithdrawexec'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
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
    urc721Create(owner_address, symbol, name, total_supply, minter, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.urc721Create, owner_address, symbol, name, total_supply, minter, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            symbol,
            name,
            total_supply, 
            minter
        };

        let apiPath = 'wallet/urc721createcontract'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} to_address 
     * @param {*} uri 
     * @param {*} token_id 
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    urc721Mint(owner_address, address, to_address, uri, token_id, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.urc721Mint, owner_address, address, to_address, uri, token_id, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            to_address: toHex(to_address),
            uri,
            token_id,
        };

        let apiPath = 'wallet/urc721mint'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    urc721RemoveMinter(owner_address, address, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.urc721RemoveMinter, owner_address, address, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
        };

        let apiPath = 'wallet/urc721removeminter'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
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
    urc721AddMinter(owner_address, address, minter, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.urc721AddMinter, owner_address, address, minter, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            minter: toHex(minter),
        };

        let apiPath = 'wallet/urc721addminter'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} options 
     * @param {*} callback 
     * @returns 
     */
    urc721RenounceMinter(owner_address, address, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.urc721RenounceMinter, owner_address, address, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
        };

        let apiPath = 'wallet/urc721renounceminter'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} token_id 
     * @param {*} callback 
     * @returns 
     */
    urc721Burn(owner_address, address, token_id, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.urc721Burn, owner_address, address, token_id, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            token_id,
        };

        let apiPath = 'wallet/urc721burn'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
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
    urc721Approve(owner_address, address, token_id, to, approve, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.urc721Approve, owner_address, address, token_id, to, approve, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            token_id,
            to: toHex(to),
            approve,
        };

        let apiPath = 'wallet/urc721approve'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} to_address 
     * @param {*} approve 
     * @param {*} callback 
     * @returns 
     */
    urc721SetApprovalForAll(owner_address, address, to_address, approve, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.urc721SetApprovalForAll, owner_address, address, to_address, approve, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            to_address: toHex(to_address),
            approve,
        };

        let apiPath = 'wallet/urc721setapprovalforall'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
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
    urc721TransferFrom(owner_address, address, to, token_id, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback){
            return this.injectPromise(this.urc721TransferFrom, owner_address, address, to, token_id, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            to: toHex(to),
            token_id,
        };

        let apiPath = 'wallet/urc721transferfrom'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    urc721BalanceOf(owner_address, address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721BalanceOf, owner_address, address, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
        };

        let apiPath = 'walletsolidity/urc721balanceof'
        this.unichainJS.solidityNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    urc721Name(address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721Name, address, options);
        }

        let requestData = {
            address: toHex(address),
        };

        let apiPath = 'walletsolidity/urc721name'
        this.unichainJS.solidityNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    urc721Symbol(address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721Symbol, address, options);
        }

        let requestData = {
            address: toHex(address),
        };

        let apiPath = 'wallet/urc721symbol'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    urc721TokenUri(address, id, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721TokenUri, address, id, options);
        }

        let requestData = {
            address: toHex(address),
            id,
        };

        let apiPath = 'wallet/urc721tokenuri'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    urc721TotalSupply(address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721TotalSupply, address, options);
        }

        let requestData = {
            address: toHex(address),
        };

        let apiPath = 'walletsolidity/urc721totalsupply'
        this.unichainJS.solidityNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    urc721IsApprovedForAll(owner_address, operator, address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721IsApprovedForAll, owner_address, operator, address, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            operator: toHex(operator),
            address: toHex(address)
        };

        let apiPath = 'wallet/urc721isapprovedforall'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} callback 
     * @returns 
     */
    urc721OwnerOf(address, id, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc721OwnerOf, address, id, options);
        }

        let requestData = {
            address: toHex(address),
            id,
        };

        let apiPath = 'walletsolidity/urc721ownerof'
        this.unichainJS.solidityNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /** NEW CONTRACT URC20 */
    /**
     * 
     * @param {*} owner_address 
     * @param {*} data 
     * @param {*} callback 
     * @returns 
     */
    urc20Create(owner_address, data, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20Create, owner_address, data, options);
        }

        // All data of new token
        const {
            symbol, 
            name, 
            decimals, 
            max_supply, 
            total_supply, 
            start_time, 
            end_time, 
            url, 
            fee, 
            extra_fee_rate, 
            fee_pool, 
            burned, 
            latest_operation_time, 
            lot, 
            fee_pool_origin, 
            exch_unx_num,
            exch_num, 
            exch_enable, 
            critical_update_time, 
            create_acc_fee
        } = data

        let requestData = {
            owner_address: toHex(owner_address),
            symbol, 
            name, 
            decimals, 
            max_supply, 
            total_supply, 
            start_time, 
            end_time, 
            url, 
            fee, 
            extra_fee_rate, 
            fee_pool, 
            burned, 
            latest_operation_time, 
            lot, 
            fee_pool_origin, 
            exch_unx_num,
            exch_num, 
            exch_enable, 
            critical_update_time, 
            create_acc_fee
        };

        let apiPath = 'wallet/urc20createcontract'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
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
    urc20TransferFrom(owner_address, from, to, address, amount, available_time, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20TransferFrom, owner_address, from, to, address, amount, available_time, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            from: toHex(from),
            to: toHex(to),
            address: toHex(address),
            amount, 
            available_time, 
        };

        let apiPath = 'wallet/urc20transferfrom'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
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
    urc20Transfer(owner_address, address, to, amount, available_time, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20Transfer, owner_address, address, to, amount, available_time, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            to: toHex(to),
            amount, 
            available_time, 
        };

        let apiPath = 'wallet/urc20transfer'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
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
    urc20Approve(owner_address, address, spender, amount, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20Approve, owner_address, address, spender, amount, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            spender: toHex(to),
            amount, 
        };

        let apiPath = 'wallet/urc20approve'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} amount 
     * @param {*} callback 
     * @returns 
     */
    urc20Mint(owner_address, address, amount, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20Mint, owner_address, address, amount, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            amount, 
        };

        let apiPath = 'wallet/urc20mint'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} amount 
     * @param {*} callback 
     * @returns 
     */
    urc20Burn(owner_address, address, amount, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20Burn, owner_address, address, amount, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            amount, 
        };

        let apiPath = 'wallet/urc20burn'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} to_address 
     * @param {*} address 
     * @param {*} callback 
     * @returns 
     */
    urc20TransferOwner(owner_address, to_address, address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20TransferOwner, owner_address, to_address, address, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            to_address: toHex(to_address),
            address: toHex(address),
        };

        let apiPath = 'wallet/urc20transferowner'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} amount 
     * @param {*} callback 
     * @returns 
     */
    urc20Exchange(owner_address, address, amount, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20Exchange, owner_address, address, amount, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            amount
        };

        let apiPath = 'wallet/urc20exchange'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} amount 
     * @param {*} callback 
     * @returns 
     */
    urc20ContributePoolFee(owner_address, address, amount, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20ContributePoolFee, owner_address, address, amount, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            amount
        };

        let apiPath = 'wallet/urc20contributepoolfee'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
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
    urc20UpdateParams(owner_address, address, fee, extra_fee_rate, lot, url, total_supply, fee_pool, exch_unx_num, exch_num, create_acc_fee, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20UpdateParams, owner_address, address, fee, extra_fee_rate, lot, url, total_supply, fee_pool, exch_unx_num, exch_num, create_acc_fee, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
            fee, 
            extra_fee_rate, 
            lot, 
            url,
            total_supply, 
            fee_pool, 
            exch_unx_num, 
            exch_num, 
            create_acc_fee
        };

        let apiPath = 'wallet/urc20updateparams'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * 
     * @param {*} owner_address 
     * @param {*} address 
     * @param {*} callback 
     * @returns 
     */
    urc20WithdrawFuture(owner_address, address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20WithdrawFuture, owner_address, address, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
        };

        let apiPath = 'wallet/urc20withdrawfuture'
        this.unichainJS.fullNode.request(apiPath, requestData, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    urc20FutureGet(owner_address, address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20FutureGet, owner_address, address, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
        };

        let apiPath = 'wallet/urc20futureget'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    urc20ContractList(address, symbol, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20ContractList, address, symbol, options);
        }

        let requestData = {
            address: toHex(address),
            symbol,
        };

        let apiPath = 'wallet/urc20contractlist'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    urc20Name(address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20Name, address, options);
        }

        let requestData = {
            address: toHex(address),
        };

        let apiPath = 'wallet/urc20name'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    urc20Symbol(address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20Symbol, address, options);
        }

        let requestData = {
            address: toHex(address),
        };

        let apiPath = 'wallet/urc20symbol'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    urc20Decimals(address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20Decimals, address, options);
        }

        let requestData = {
            address: toHex(address),
        };

        let apiPath = 'wallet/urc20decimals'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    urc20TotalSupply(address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20TotalSupply, address, options);
        }

        let requestData = {
            address: toHex(address),
        };

        let apiPath = 'wallet/urc20totalsupply'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    urc20TotalSupply(address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20TotalSupply, address, options);
        }

        let requestData = {
            address: toHex(address),
        };

        let apiPath = 'wallet/urc20totalsupply'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    urc20BalanceOf(owner_address, address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20BalanceOf, owner_address, address, options);
        }

        let requestData = {
            owner_address: toHex(owner_address),
            address: toHex(address),
        };

        let apiPath = 'wallet/urc20balanceof'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    urc20GetOwner(address, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20GetOwner, address, options);
        }

        let requestData = {
            address: toHex(address),
        };

        let apiPath = 'wallet/urc20getowner'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    urc20Allowance(owner, address, spender, options, callback = false) {
        if (!callback){
            return this.injectPromise(this.urc20Allowance, owner, address, spender, options);
        }

        let requestData = {
            owner: toHex(owner),
            address: toHex(address),
            spender: toHex(spender)
        };

        let apiPath = 'wallet/urc20allowance'
        this.unichainJS.fullNode.request(apiPath, requestData, 'get').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }
}
