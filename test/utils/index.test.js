const chai = require('chai');
const unichainJSBuilder = require('../helpers/unichainJSBuilder');
const UnichainJS = unichainJSBuilder.UnichainJS;
const BigNumber = require('bignumber.js');

const assert = chai.assert;

describe('UnichainJS.utils', function () {

    describe("#isValidURL()", function () {

        it('should verify good urls', function () {

            const unichainJS = unichainJSBuilder.createInstance();

            assert.isTrue(unichainJS.utils.isValidURL('https://some.example.com:9090/casa?qe=3'))
            assert.isTrue(unichainJS.utils.isValidURL('www.example.com/welcome'))

            assert.isFalse(unichainJS.utils.isValidURL('http:/some.example.com'))

            assert.isFalse(unichainJS.utils.isValidURL(['http://example.com']))

        })

    });

    describe("#isArray()", function () {

        it('should verify that a value is an array', function () {
            const unichainJS = unichainJSBuilder.createInstance();

            assert.isTrue(unichainJS.utils.isArray([]));
            assert.isTrue(unichainJS.utils.isArray([[2], {a: 3}]));

            assert.isFalse(unichainJS.utils.isArray({}));
            assert.isFalse(unichainJS.utils.isArray("Array"));

        })

    });


    describe("#isJson()", function () {

        it('should verify that a value is a JSON string', function () {
            const unichainJS = unichainJSBuilder.createInstance();

            assert.isTrue(unichainJS.utils.isJson('[]'));
            assert.isTrue(unichainJS.utils.isJson('{"key":"value"}'));
            assert.isTrue(unichainJS.utils.isJson('"json"'));

            assert.isFalse(unichainJS.utils.isJson({}));
            assert.isFalse(unichainJS.utils.isJson("json"));

        })

    });

    describe("#isBoolean()", function () {

        it('should verify that a value is a JSON string', function () {
            const unichainJS = unichainJSBuilder.createInstance();

            assert.isTrue(unichainJS.utils.isBoolean(true));
            assert.isTrue(unichainJS.utils.isBoolean('a' == []));

            assert.isFalse(unichainJS.utils.isBoolean({}));
            assert.isFalse(unichainJS.utils.isBoolean("json"));

        })

    });

    describe("#isBigNumber()", function () {

        it('should verify that a value is a JSON string', function () {
            const unichainJS = unichainJSBuilder.createInstance();

            const bigNumber = BigNumber('1234565432123456778765434456777')

            assert.isTrue(unichainJS.utils.isBigNumber(bigNumber));

            assert.isFalse(unichainJS.utils.isBigNumber('0x09e80f665949b63b39f3850127eb29b55267306b69e2104c41c882e076524a1c'));
            assert.isFalse(unichainJS.utils.isBigNumber({}));
            assert.isFalse(unichainJS.utils.isBigNumber("json"));

        })

    });


    describe("#isString()", function () {

        it('should verify that a valyue is a string', function () {
            const unichainJS = unichainJSBuilder.createInstance();

            assert.isTrue(unichainJS.utils.isString('str'));
            assert.isTrue(unichainJS.utils.isString(13..toString()));

            assert.isFalse(unichainJS.utils.isString(2));

        })

    });

    describe("#isFunction()", function () {

        it('should verify that a value is a function', function () {
            const unichainJS = unichainJSBuilder.createInstance();

            assert.isTrue(unichainJS.utils.isFunction(new Function()));
            assert.isTrue(unichainJS.utils.isFunction(() => {
            }));
            assert.isTrue(unichainJS.utils.isFunction(unichainJS.utils.isFunction));

            assert.isFalse(unichainJS.utils.isFunction({function: new Function}));

        })

    });

    describe('#isHex()', function () {
        it('should verify that a string is an hex string', function () {

            const unichainJS = unichainJSBuilder.createInstance();

            let input = '0x1';
            let expected = true;
            assert.equal(unichainJS.utils.isHex(input), expected);

            input = '0x0';
            expected = true;
            assert.equal(unichainJS.utils.isHex(input), expected);

            input = '0x73616c616d6f6e';
            expected = true;
            assert.equal(unichainJS.utils.isHex(input), expected);

            input = '73616c616d6f';
            expected = true;
            assert.equal(unichainJS.utils.isHex(input), expected);

            input = '0x73616c616d6fsz';
            expected = false;
            assert.equal(unichainJS.utils.isHex(input), expected);

            input = 'x898989';
            expected = false;
            assert.equal(unichainJS.utils.isHex(input), expected);

        });

    });

    describe("#isInteger()", function () {

        it('should verify that a value is an integer', function () {
            const unichainJS = unichainJSBuilder.createInstance();

            assert.isTrue(unichainJS.utils.isInteger(2345434));
            assert.isTrue(unichainJS.utils.isInteger(-234e4));

            assert.isFalse(unichainJS.utils.isInteger(3.4));
            assert.isFalse(unichainJS.utils.isInteger('integer'));

        })

    });

    describe("#hasProperty()", function () {

        it('should verify that an object has a specific property', function () {
            const unichainJS = unichainJSBuilder.createInstance();

            assert.isTrue(unichainJS.utils.hasProperty({p: 2}, 'p'));
            assert.isFalse(unichainJS.utils.hasProperty([{p: 2}], 'p'));

            assert.isFalse(unichainJS.utils.hasProperty({a: 2}, 'p'));

        })

    });

    describe("#hasProperties()", function () {

        it('should verify that an object has some specific properties', function () {
            const unichainJS = unichainJSBuilder.createInstance();

            assert.isTrue(unichainJS.utils.hasProperties({p: 2, s: 2}, 'p', 's'));

            assert.isFalse(unichainJS.utils.hasProperties({p: 2, s: 2}, 'p', 'q'));

        })

    });


    describe("#mapEvent()", function () {

        it('should map an event result', function () {
            const unichainJS = unichainJSBuilder.createInstance();

            const event = {
                block_number: 'blockNumber',
                block_timestamp: 'blockTimestamp',
                contract_address: 'contractAddress',
                event_name: 'eventName',
                transaction_id: 'transactionId',
                result: 'result',
                resource_Node: 'resourceNode'
            }

            const expected = {
                block: 'blockNumber',
                timestamp: 'blockTimestamp',
                contract: 'contractAddress',
                name: 'eventName',
                transaction: 'transactionId',
                result: 'result',
                resourceNode: 'resourceNode'
            }

            const mapped = unichainJS.utils.mapEvent(event)
            for(let key in mapped) {
                assert.equal(mapped[key], expected[key])
            }

        })

    });

    describe('#parseEvent', function () {
        // TODO
    });

    describe("#padLeft()", function () {

        it('should return the pad left of a string', function () {
            const unichainJS = unichainJSBuilder.createInstance();

            assert.equal(unichainJS.utils.padLeft('09e80f', '0', 12), '00000009e80f');
            // assert.equal(unichainJS.utils.padLeft(new Function, '0', 32), '0000000function anonymous() {\n\n}');
            assert.equal(unichainJS.utils.padLeft(3.4e3, '0', 12), '000000003400');

        })

    });

    describe("#ethersUtils()", function () {

        it('should import sha256 from ethers and has a string', function () {
            const unichainJS = unichainJSBuilder.createInstance();

            const string = '0x' + Buffer.from('some string').toString('hex');
            const hash = unichainJS.utils.ethersUtils.sha256(string);

            assert.equal(hash, '0x61d034473102d7dac305902770471fd50f4c5b26f6831a56dd90b5184b3c30fc');

        })

    });

});
