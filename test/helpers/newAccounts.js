const unichainJSBuilder = require('./unichainJSBuilder');
const unichainJS = unichainJSBuilder.createInstance();

const amount = process.argv[2] || 10;

(async function () {
    await unichainJSBuilder.newTestAccounts(amount)
})()

