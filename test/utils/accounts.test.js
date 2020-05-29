const chai = require('chai');
const {ADDRESS_HEX, ADDRESS_BASE58} = require('../helpers/config');
const unichainJSBuilder = require('../helpers/unichainJSBuilder');

const assert = chai.assert;

describe('UnichainJS.utils.accounts', function () {

    describe('#generateAccount()', function () {

        it("should generate a new account", async function () {
            const unichainJS = unichainJSBuilder.createInstance();

            const newAccount = await unichainJS.utils.accounts.generateAccount();
            assert.equal(newAccount.privateKey.length, 64);
            assert.equal(newAccount.publicKey.length, 130);
            let address = unichainJS.address.fromPrivateKey(newAccount.privateKey);
            assert.equal(address, newAccount.address.base58);

            assert.equal(unichainJS.address.toHex(address), newAccount.address.hex.toLowerCase());
        });
    });
});
