
let someParameter

class GetNowBlock {

    constructor(unichainJS = false) {
        if (!unichainJS)
            throw new Error('Expected instance of UnichainJS');

        this.unichainJS = unichainJS;
    }

    async someMethod(callback = false) {

        if(!callback)
            return this.injectPromise(this.getCurrentBlock);

        this.unichainJS.fullNode.request('wallet/getnowblock').then(block => {
            block.fromPlugin = true
            callback(null, block);
        }).catch(err => callback(err));
    }

    getSomeParameter() {
        return someParameter;
    }

    pluginInterface(options) {
        if (options.someParameter) {
            someParameter = options.someParameter
        }
        return {
            requires: '^2.2.4',
            components: {
                unw: {
                    // will be overridden
                    getCurrentBlock: this.someMethod,

                    // will be added
                    getLatestBlock: this.someMethod,
                    getSomeParameter: this.getSomeParameter,

                    // will be skipped
                    _parseToken: function () {}


                }
            }
        }
    }
}

module.exports = GetNowBlock
