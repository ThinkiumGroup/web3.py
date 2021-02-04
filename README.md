# Web3.py

# 1. Get account info

## method: web3.thk.GetAccount

## params:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| chainId | string | true | chain id |
| address | string | true | account address |

## response:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| address | string | true | account address |
| nonce | int | true | transactions count |  
| balance| bigint | true | balance of tkm |  
| storageRoot| string | false |  | 
|codeHash| string | false |  | 

### example:

```python
response = web3.thk.getAccount('0x0000000000000000000000000000000000000000')
```

response:

```json
{
  "address": "0x0000000000000000000000000000000000000000",
  "nonce": 0,
  "balance": 0,
  "storageRoot": null,
  "codeHash": null
}
```

# 2. send transaction

## method: web3.thk.SendTx

## params:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| Transaction | dict | true | transaction detail |

Transaction：

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| chainId | string | true | chain id |
| fromChainId | string | true | from chain id |
| toChainId | string | true | to chain id |
|from | string | true | from account address |
|to | string | true | receiver address |
| nonce | string | true | transaction count |   
| value | string | true | transfer amount |  
| input | string | true | encoded params |  
| sig | string | true | signature of the transaction |  
| pub | string | true | account public key |  

## response:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| TXhash | string | true | transaction hash |

### example:

```python
transaction = (
    "chainId": "2",
"fromChainId": "2",
"toChainId": "2",
"from": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
"nonce": "1",
"to": "0x0000000000000000000000000000000000000000",
"input": '',
"value": "1111111110"
)
con_sign_tx = web3.thk.signTransaction(con_tx, privarte_key)
response = web3.thk.sendTx(con_sign_tx)
```

response:

```json
{
  "TXhash": "0x22024c2e429196ac76d0e557ac0cf6141f5b500c56fde845582b837c9dab236b"
}
```

# 3. get transaction info by hash

## method: web3.thk.GetTransactionByHash

## params:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| chainId | string | true | chain id |
|hash | string | true | transaction hash |

## response:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| Transaction | dict | true | transaction details |
| root | string | true | Save the current state of the "account" when the receive object is created |
| status | int | true | Transaction status: 1: success, 0: fail |
| logs | array[dict] | false | An array of log objects generated by this transaction |
| transactionHash | string | true | transaction hash |
| contractAddress | string | true | contract address |
| out | string | true | Call to return result data |

Transaction:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| chainID | int| true | chain id |
| from | string | true | from address |
| to | string | true | receiver address |
| nonce | string | true | The number of previous transactions by the originator of the transaction |
| val | string | true | Transfer amount |
| input | string | true | Parameters when calling contracts |

### example:

```python
response = web3.thk.getTxByHash('2', '0x29d7eef512137c55f67a7012e814e5add45ae8b81a9ceb8e754c38e8aa5dee4d');
```

response:

```json
{
  "Transaction": {
    "chainID": 2,
    "from": "0x0000000000000000000000000000000000000000",
    "to": null,
    "nonce": 0,
    "value": 0,
    "input": "0x6080604052600160005534801561001557600080fd5b50600260008190555060a18061002c6000396000f300608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063d46300fd146044575b600080fd5b348015604f57600080fd5b506056606c565b6040518082815260200191505060405180910390f35b600080549050905600a165627a7a72305820c52125523008034b3491540aa03fc856951b8da206b011ac05a0c6b52f61b3c00029"
  },
  "root": null,
  "status": 1,
  "logs": null,
  "transactionHash": "0x24d06cf16cd9aad66a144ad2b1b2e475d936656027cd70eae792459926b4a8c1",
  "contractAddress": "0x0e50cea0402d2a396b0db1c5d08155bd219cc52e",
  "out": "0x"
}
```

# 4. Get chain information

## method: web3.thk.GetStats

## params:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| chainId | string | true | chain id |

## response:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| currentheight |bigint | true |  Current block height |
| txcount | int | true | Total transactions |
| tps | int | true | Transaction Per Second |
| tpsLastEpoch | int | true | Number of transactions in the previous period |
| lives | int | true | Survival time of the chain |
| accountcount | int | true | Number of accounts |
| epochlength | int | true | How many blocks does the current period contain |
| epochduration | int | true | Running time of current period |
| lastepochduration | int | true | Running time of last period |
| currentcomm | array | true | The current members of the chain |

### example:

```python
response = web3.thk.getStats('2')
```

response

```json
{
  "currentheight": 5290,
  "txcount": 5295,
  "tps": 0,
  "tpsLastEpoch": 0,
  "lives": 10714,
  "accountcount": 6,
  "epochlength": 80,
  "epochduration": 162,
  "lastepochduration": 162,
  "currentcomm": [
    "0x96dc94580e0eadd78691807f6eac9759b9964daa8b46da4378902b040e0eb102cb48413308d2131e9e5557321f30ba9287794f689854e6d2e63928a082e79286",
    "0x4ce2edd98452036c804f3f2eeef157672be2ccf647369eb42eb49ab9f428821f9990efde3cf7f16e4c64616c10b673077f4278c6dd2fc6021da8ad0085a522a2"
  ]
}
```

# 5. Obtain the transaction information of the specified account within a certain height range on the corresponding chain

## method: web3.thk.GetTransactions

## params:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| chainId | string | true | chain id |
| address | string | true | account address |
| startHeight | string | true | start height |
| endHeight | string | true | end height |

## response:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| [] | []transactons | true | transaction array |

transactons：

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| chainId | int | true | chain id |
| from | string | true | from address |
| to | string | true | receiver address |
| nonce | int | true | transaction count |
| value | int | true | transfer amount |
| timestamp | int | true | transaction timestamp |
| input | string | true | encode params |
| hash | string | true | transaction hash |

```python
response = web3.thk.getTransactions('2', '50', '70');
```

response:

```json
[
  {
    "chainid": 2,
    "height": 118,
    "from": "0x0000000000000000000000000000000000000000",
    "to": null,
    "nonce": 0,
    "value": 0,
    "timestamp": 1547708801
  },
  {
    "chainid": 2,
    "height": 3831,
    "from": "0x0000000000000000000000000000000000000000",
    "to": null,
    "nonce": 1,
    "value": 0,
    "timestamp": 1547716293
  }
]
```

# 6. call transaction

## method: web3.thk.CallTransaction

## params:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| Transaction | dict | true | transaction detail |

## params:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| chainId | string | true | chain id |
| fromChainId | string | true | from chain |
| toChainId | string | true | to chain |
| from | string | true | from account address |
| to | string | true | receiver address |
| nonce | string | true | transactions count of account |
| value | string | true | transfer amount |
| input | string | true | encoded params |

## response:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| out | string | true | call result |

## example:

```python
response = web3.thk.callTransaction('2', '0x0000000000000000000000000000000000000000',
                                    '0x0e50cea0402d2a396b0db1c5d08155bd219cc52e', '22', '0',
                                    '0xe98b7f4d0000000000000000000000000000000000000000000000000000000000000001');
```

response:

```json
{
  "Transaction": {
    "chainID": 2,
    "from": "0x0000000000000000000000000000000000000000",
    "to": "0x0e50cea0402d2a396b0db1c5d08155bd219cc52e",
    "nonce": 2,
    "value": 0,
    "input": "0xe98b7f4d0000000000000000000000000000000000000000000000000000000000000001"
  },
  "root": null,
  "status": 0,
  "logs": null,
  "transactionHash": "0x9936cab441360985fc9e27904f0767c1c39fe8e0edb83709a0cdad52470a4592",
  "contractAddress": "0x0000000000000000000000000000000000000000",
  "out": "0x"
}
```

# 7. get block info

## method: web3.thk.GetBlockHeader

## params:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| chainId | string | true | chain id |
| height | string | true | the block height |

## response:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| hash | string | true | block hash |
| previoushash | string | true | previous block hash |
| chainid | int | true | chain id |
| height | int | true | block height |
| mergeroot | string | true | Merge other chain transfer data hash |
| deltaroot | string | true | inter-chain transfer hash |
| stateroot | string | true | state-hash |
| txcount | int | true | transaction count |
| timestamp | int | true | timestamp |

## example:

```
response = web3.thk.getBlockHeader('2', '30');
```

response:

```json
{
  "hash": "0x71603186004fd46d32cda0780c4f4cf77ce13b396b1b8132b2c632173441b9d2",
  "previoushash": "0xd0f6e9c89eb6be655632911e3743b5a994423c3526653dc55b62ebea3ff56c43",
  "chainid": 2,
  "height": 30,
  "mergeroot": "0xdddfde85423a0d7da064c1b5a8cc1ff18d4a209027ef95ecceae0e6ed8f7c1af",
  "deltaroot": "0xdddfde85423a0d7da064c1b5a8cc1ff18d4a209027ef95ecceae0e6ed8f7c1af",
  "stateroot": "0x0b672749b02da6bf8f3aa50238140ce7fae5af3e926d4eb06d4cfb707a90702e",
  "txcount": 1,
  "timestamp": 1547777358
}
```

# 8. Gets the transaction of the specified block

## method: web3.thk.getBlockTxs

## params:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| chainId | string | true | chain id |
| height | string | true | the block height |
| page | string | true | page index |
| size | string | true | size of the page |

## response:

| name | type | required| description |
| :------:| :------: | :------: | :------: |
| elections | dict | true |  |
| accountchanges | array | true | tansaction info |

accountchanges:

| name | type | required| description | 
| :------:| :------: | :------: | :------: |
| chainid | string | true | chain id |
| height | int| true | start height |
| from | string| true | from account address |
| to | string| true | receiver address |
| nonce | int| true | transactions count |
| value | int| true | transfer amount | 
| timestamp | int| true | transaction timestamp |

## example:

```python
response = web3.thk.getBlockTxs('2', '30', '1', '10');
```

response:

```json
{
  "elections": null,
  "accountchanges": [
    {
      "chainid": 2,
      "height": 30,
      "from": "0x4fa1c4e6182b6b7f3bca273390cf587b50b47311",
      "to": "0x4fa1c4e6182b6b7f3bca273390cf587b50b47311",
      "nonce": 30,
      "value": 1,
      "timestamp": 1547777358
    }
  ]
}
```