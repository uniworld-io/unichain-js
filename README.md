
## What is UnichainJS?
 UniChainJS is a javascript library to work with Unichain network. It provides essential functions to manage a wallet, deploy smart contracts, build transactions, broadcast transactions to the network

## How to use
1. Install Unichain-JS by `npm install @uniworld/unichain-js`
2. Import to javascript file `const UniChainJS = require('@uniworld/unichain-js')`
3. Start using library

## Example
```javascript
const UnichainJS = require('@uniworld/unichain-js')

//initiate unichainjs
const unichain = new Unichain({
    fullHost: '127.0.0.1:6636',
    privateKey: 'your_private_key'
})

//check if it is connected
unichain.isConnected((err, data) => {
    if (err) return
    console.log('Connected to network')
})

//Generate account
const account = unichain.utils.accounts.generateAccount()
console.log(account)
/*
    { 
        privateKey:'7D1A95FDB7FDA1A53ABC5438AA85CD1B96070E46E9125B03C947A6839CA63C45',
        publicKey:'04D372E96F523842AAF65DE9A785F244AE68CB789F8949174E3E9041D8DDC52E94AFA1F611F6F5904D59D3D209EC95D16654E675A20BA079DEB89A018384D42FDF',
        address: { 
            base58: 'UYdL2g5bbYmkDTSywSfNRhAmCJJGHyUbEk',
            hex: '4474BFBC5DED85E491E3332FE285D58EEDFE365EDF' 
        } 
    }
*/

//Get transaction 
unichain.unx.getTransaction(txid, (err, tx) => {
    console.log('Transaction:', tx)
})

//Build transaction offline and sending coin
const amount = 1000 
const fromAddress = 'UZQWseP7WEN1R3nukDtLksukSduCvB19eT'
const toAddress = 'UabADyuooKUrVgzzfiH8Q7LpDX7wKpd54t'
const data = {
    to_address: unichain.address.toHex(toAddress),
    owner_address: unichain.address.toHex(fromAddress),
    amount: amount
}
//private key of fromAddress
const testPriKey = '45438936af44f337242b9823df58aed1af559682c2dbc2f40205d2124e9c1133' 
const unsingedTx = await unichain.currentProviders().fullNode.request('wallet/createtransaction', data, 'post')
const signedTx = await unichain.unx.signTransaction(unsingedTx, testPriKey, 0)
const res = await unichain.unx.sendRawTransaction(signedTx)
console.log(res)

//Working with smart contract - for example simple coin smart contract
const contractAddress = 'UdVXfqQ4HAdvCoDqBc8zFjA49NfwvAfS7c'
const contract = unichainJs.contract()
const loadContract = await contract.at(contractAddress)
console.log(loadContract)
const balance = await contract.getBalance('US4CaJ5GPEg4teYiAhNTe53pSW4QN7QrDb').call()
console.log(balance.toNumber())
let res = await contract.sendCoin('UQZjUw5S87G9DsmNFoMPGuaGLJwkxWuUfV', 10).send()
console.log(res)

```

## Contact
### email: 
support@unichain.world
### website:
- [UniChain Website](https://unichain.world)
- [UniWorld Website](https://uniworld.io)
- [UniMe Website](https://unime.world)
- [UniBot Website](https://unibot.org)
