import json
import time
import subprocess

from web3 import Web3, HTTPProvider, account

FULL_NODE_HOSTS = 'http://rpctest.thinkium.org'
provider = HTTPProvider(FULL_NODE_HOSTS)
web3 = Web3(provider)

privateKey = "0x8e5b44b6cee8fa05092b4b5a8843aa6b0ec37915a940c9b5938e88a7e6fdd83a"
address = "0xf167a1c5c5fab6bddca66118216817af3fa86827"

privateKey2 = "0xc614545a9f1d9a2eeda26836e42a4c11631f25dc3d0dcc37fe62a89c4ff293d1"
address2 = "0x5dfcfc6f4b48f93213dad643a50228ff873c15b9"


def __init__():
    private_key = get_private_key()
    print("private_key:" + private_key.hex())
    web3.thk.defaultPrivateKey = private_key
    web3.thk.defaultAddress = address
    web3.thk.defaultChainId = "1"


def get_private_key():
    ret = web3.thk.account.encrypt(privateKey, "123456")

    # print("keyFile", ret)
    key_file = open("./keystore/key1", "w")
    key_file.write(json.dumps(ret))
    key_file.close()

    with open("./keystore/key1") as key_file:
        encrypted_key = key_file.read()
        encrypted_key_obj = json.loads(encrypted_key)
        print("encrypted_key_obj", encrypted_key_obj)
        private_key = web3.thk.account.decrypt(encrypted_key_obj, '123456')

    return private_key


def test_transfer():
    account = web3.thk.getAccount(web3.thk.defaultAddress)
    check_error(account)
    tx = {
        "chainId": web3.thk.defaultChainId,
        "fromChainId": web3.thk.defaultChainId,
        "toChainId": web3.thk.defaultChainId,
        "from": web3.thk.defaultAddress,
        "nonce": str(account["nonce"]),
        "to": address2,
        "input": '',
        "useLocal": False,
        "extra": '',
        "value": "123321"
    }
    signed_tx = web3.thk.signTransaction(tx, web3.thk.defaultPrivateKey)
    print("signed_tx:", signed_tx)
    res = web3.thk.sendTx(signed_tx)
    print("res:", res)
    check_error(res)
    time.sleep(5)

    tx_info = web3.thk.getTxByHash(web3.thk.defaultChainId, res["TXhash"])
    print("tx_info:", tx_info)
    check_error(tx_info)


def check_error(dict):
    if "errMsg" in dict and len(dict["errMsg"]) != 0:
        raise Exception(dict["errMsg"])


def test_check_solc():
    try:
        solc_path = subprocess.check_output(['which', 'solc']).strip()
        print(solc_path)
    except subprocess.CalledProcessError:
        raise Exception('solc binary not found')

    solc_version = subprocess.check_output(['solc', '--version']).strip()
    print(solc_version)


def compile_contract(file_paths, contract_name):
    print('\n\n\ntest_compile_contract()')
    test_check_solc()
    import os
    f = os.popen('solc --combined-json bin,abi,userdoc,devdoc,metadata --optimize ' + file_paths)
    ret = f.read()
    print(ret)
    hello_contract_abi = open("./resource/" + contract_name + ".json", "w")
    hello_contract_abi.write(ret)
    hello_contract_abi.close()
    contracts = json.loads(ret)['contracts']
    the_contract = contracts[file_paths + ':' + contract_name]

    return {
        'abi': the_contract['abi'],
        'byte_code': the_contract['bin'],
    }


def deploy_contract_1():
    contract_abi_byte_code = compile_contract('./resource/HelloWorld.sol', 'HelloWorld')
    tx = {
        "chainId": web3.thk.defaultChainId,
        "fromChainId": web3.thk.defaultChainId,
        "toChainId": web3.thk.defaultChainId,
        "from": web3.thk.defaultAddress,
        "nonce": "0",
        "to": "",
        "input": contract_abi_byte_code['byte_code'],
        "useLocal": False,
        "extra": "",
        "value": "0"
    }
    account = web3.thk.getAccount(web3.thk.defaultAddress)
    check_error(account)
    tx["nonce"] = str(account["nonce"])
    signed_tx = web3.thk.signTransaction(tx, web3.thk.defaultPrivateKey)
    print("signed_tx=", signed_tx)
    res = web3.thk.sendTx(signed_tx)
    print("res:", res)
    check_error(res)

    time.sleep(5)

    tx_info = web3.thk.getTxByHash(web3.thk.defaultChainId, res["TXhash"])
    print("tx_info:", tx_info)
    check_error(tx_info)

    contract_address = tx_info['contractAddress']
    return contract_address


def deploy_contract_2():
    contract_abi_byte_code = compile_contract('./resource/Greeter.sol', 'Greeter')
    abi = contract_abi_byte_code['abi']
    contract_bin = contract_abi_byte_code['byte_code']

    greeter_contract = web3.thk.contract(abi=abi, bytecode=contract_bin)

    print('\n\n\ngreeter_contract.constructor().transact()()')
    res = greeter_contract.constructor().transact()
    print("res=", res)
    check_error(res)

    tx_info = web3.thk.waitForTransactionReceipt(web3.thk.defaultChainId, res["TXhash"])
    print("tx_info=", tx_info)
    check_error(tx_info)
    if tx_info["status"] == 1:
        print("deploy success")
    else:
        raise Exception("error")
    print("contractAddress=", tx_info['contractAddress'])  # 0x7bfc43d33052d760fd2254f35a010ce59e4381c7


def call_contract():
    abi = '[{"constant":false,"inputs":[{"name":"_greeting","type":"string"}],"name":"setGreeting","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"greet","outputs":[{"name":"ret","type":"string[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"greeting","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"}]'
    greeter = web3.thk.contract(
        address='0x44f9a35666840fdddf043a8f6ca3f352744bc8eb',
        abi=abi,
    )
    account = web3.thk.getAccount(address)

    tx = greeter.functions.setGreeting("hello world").buildTx({
        "chainId": web3.thk.defaultChainId,
        "fromChainId": web3.thk.defaultChainId,
        "toChainId": web3.thk.defaultChainId,
        "from": web3.thk.defaultAddress,
        "nonce": str(account["nonce"]),
        "useLocal": False,
        "extra": ""
    })
    signed_tx = web3.thk.signTransaction(tx, web3.thk.defaultPrivateKey)
    res = web3.thk.sendTx(signed_tx)
    check_error(res)
    time.sleep(5)

    tx_info = web3.thk.getTxByHash(web3.thk.defaultChainId, res["TXhash"])
    print("tx_info:", tx_info)
    check_error(tx_info)

    result = greeter.functions.greet().call()
    print("result:", result)

    account = web3.thk.getAccount(address)
    tx = greeter.functions.greet().buildTx({
        "chainId": web3.thk.defaultChainId,
        "fromChainId": web3.thk.defaultChainId,
        "toChainId": web3.thk.defaultChainId,
        "from": web3.thk.defaultAddress,
        "nonce": str(account["nonce"])
    })
    signed_tx = web3.thk.signTransaction(tx, web3.thk.defaultPrivateKey)
    tx_info = web3.thk.callTransaction(signed_tx)
    check_error(tx_info)
    print("tx_info:", tx_info)


def call_contract_2():
    abi = '[{"constant":true,"inputs":[],"name":"getAge","outputs":[{"internalType":"uint256","name":"data","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getNickname","outputs":[{"internalType":"string","name":"data","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"string","name":"data","type":"string"}],"name":"setNickname","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"}]'
    hello = web3.thk.contract(
        address='0x28ac56f3818252289384b639eb91148f9cd65cb8',
        abi=abi,
    )
    account = web3.thk.getAccount(address)

    tx = hello.functions.setNickname("hello world").buildTx({
        "chainId": web3.thk.defaultChainId,
        "fromChainId": web3.thk.defaultChainId,
        "toChainId": web3.thk.defaultChainId,
        "from": web3.thk.defaultAddress,
        "nonce": str(account["nonce"]),
        "useLocal": False,
        "extra": ""
    })
    signed_tx = web3.thk.signTransaction(tx, web3.thk.defaultPrivateKey)
    res = web3.thk.sendTx(signed_tx)
    check_error(res)
    time.sleep(5)

    tx_info = web3.thk.getTxByHash(web3.thk.defaultChainId, res["TXhash"])
    print("tx_info:", tx_info)
    check_error(tx_info)

    result = hello.functions.getNickname().call()
    print("result:", result)


def create_account():
    from eth_utils import (
        keccak,
    )
    from web3._utils.encoding import (
        to_bytes,
    )

    from eth_utils import (
        to_hex,
    )
    from eth_keys import (
        keys
    )

    # acct = web3.account.Account.create('KEYSMASH FJAFJKLDSKF7JKFDJ 1530')
    acct = account.Account.privateKeyToAccount(keccak(to_bytes(text="456")))

    private_key = to_hex(acct.privateKey)
    print("privateKey:", private_key)

    pk = keys.PrivateKey(acct.privateKey)
    public_key = "0x04" + pk.public_key.to_hex()[2:]

    print("public_key:", pk.public_key.to_hex()[2:])
    print("public_key:", public_key)

    print(acct.address)
    print("address:", acct.address)


if __name__ == "__main__":
    __init__()
    # print('\n\n\ntest_compile_contract()')
    # contract_abi_byte_code = compile_contract('./resource/HelloWorld.sol', 'HelloWorld')
    # print('contract_abi_byte_code:', contract_abi_byte_code)
    #
    # print('\n\n\ntest_transfer()')
    # test_transfer()
    #
    # print('\n\n\ndeploy_contract_1()')
    # contractAddress = deploy_contract_1()
    # print(contractAddress)  # 0x32998203e8ae9ace424b8773037e8ca16c2d31eb
    #
    # print('\n\n\ndeploy_contract_2()')
    # deploy_contract_2()

    # print('\n\n\ncall_contract()')
    # call_contract()

    # print('\n\n\ncall_contract_2()')
    # call_contract_2()

    print('\n\n\ncreate_account()')
    create_account()
