const chai = require('chai');
const {FULL_NODE_API} = require('../helpers/config');
const assertThrow = require('../helpers/assertThrow');
const unichainJSBuilder = require('../helpers/unichainJSBuilder');
const UnichainJS = unichainJSBuilder.UnichainJS;
const GetNowBlock = require('../helpers/GetNowBlock');
const BlockLib = require('../helpers/BlockLib');
const jlog = require('../helpers/jlog')

const assert = chai.assert;

describe('UnichainJS.lib.plugin', async function () {

    let unichainJS;

    before(async function () {
        unichainJS = unichainJSBuilder.createInstance();
    });

    describe('#constructor()', function () {

        it('should have been set a full instance in unichainJS', function () {

            assert.instanceOf(unichainJS.plugin, UnichainJS.Plugin);
        });

    });

    describe("#plug GetNowBlock into unichainJS.unx", async function () {

        it('should register the plugin GetNowBlock', async function () {

            const someParameter = 'someValue'

            let result = unichainJS.plugin.register(GetNowBlock, {
                someParameter
            })
            assert.isTrue(result.skipped.includes('_parseToken'))
            assert.isTrue(result.plugged.includes('getCurrentBlock'))
            assert.isTrue(result.plugged.includes('getLatestBlock'))

            result = await unichainJS.unx.getCurrentBlock()
            assert.isTrue(result.fromPlugin)
            assert.equal(result.blockID.length, 64)
            assert.isTrue(/^00000/.test(result.blockID))

            result = await unichainJS.unx.getSomeParameter()
            assert.equal(result, someParameter)

        })

    });

    describe("#plug BlockLib into unichainJS at first level", async function () {

        it('should register the plugin and call a method using a promise', async function () {

            let result = unichainJS.plugin.register(BlockLib)
            assert.equal(result.libs[0], 'BlockLib')
            result = await unichainJS.blockLib.getCurrent()
            assert.isTrue(result.fromPlugin)
            assert.equal(result.blockID.length, 64)
            assert.isTrue(/^00000/.test(result.blockID))

        })

        it('should register and call a method using callbacks', async function () {

            unichainJS.plugin.register(BlockLib)
            return new Promise(resolve => {
                unichainJS.blockLib.getCurrent((err, result) => {
                    assert.isTrue(result.fromPlugin)
                    assert.equal(result.blockID.length, 64)
                    assert.isTrue(/^00000/.test(result.blockID))
                    resolve()
                })
            })
        })

        it('should not register if unichainJS is instantiated with the disablePlugins option', async function () {

            let unichainJS2 = unichainJSBuilder.createInstance({disablePlugins: true});
            let result = unichainJS2.plugin.register(BlockLib);
            assert.isTrue(typeof result.error === 'string');

        })


    });

});
