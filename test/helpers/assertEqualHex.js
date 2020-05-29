const assert = require('chai').assert;
const unichainJSBuilder = require('./unichainJSBuilder');

module.exports = async function (result, string) {

    assert.equal(
        result,
        unichainJSBuilder.getInstance().toHex(string).substring(2)
    )
}
