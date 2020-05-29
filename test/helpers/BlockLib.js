
const injectPromise = require('injectpromise')

class BlockLib {

    constructor(unichainJS = false) {
        if (!unichainJS)
            throw new Error('Expected instances of UnichainJS and utils');
        this.unichainJS = unichainJS;
        this.injectPromise = injectPromise(this);
    }

    async getCurrent(callback = false) {

        if (!callback)
            return this.injectPromise(this.getCurrent);

        this.unichainJS.fullNode.request('wallet/getnowblock').then(block => {
            block.fromPlugin = true
            callback(null, block);
        }).catch(err => callback(err));
    }

    pluginInterface() {
        return {
            requires: '^2.8.0',
            fullClass: true
        }
    }
}

module.exports = BlockLib
