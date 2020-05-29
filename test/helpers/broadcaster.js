const unichainJSBuilder = require('../helpers/unichainJSBuilder');

module.exports = async function (func, pk, transaction) {
    const unichainJS = unichainJSBuilder.createInstance();
    if( !transaction) {
        transaction = await func;
    }
    const signedTransaction = await unichainJS.unx.sign(transaction, pk);
    const result = {
        transaction,
        signedTransaction,
        receipt: await unichainJS.unx.sendRawTransaction(signedTransaction)
    };
    return Promise.resolve(result);
}
