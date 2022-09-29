# Cryptowrench 🔑🔮

This is a set of tools that I created to learn and play around with blockchains and cryptocurrencies in general.

Install with:
```
pip -m install cryptowrench
```

Feel free to use it for your own projects.

## 📖 Examples
* [Create a new wallet](https://github.com/omirete/cryptowrench#create-a-new-wallet)
* [Import an existing wallet (from mnemonic words)](https://github.com/omirete/cryptowrench#import-an-existing-wallet-from-mnemonic-words)
* [Import an existing wallet (from seed)](https://github.com/omirete/cryptowrench#import-an-existing-wallet-from-seed)

### Create a new wallet
```python
from cryptowrench.wallet import Wallet

# This will create a root wallet automatically
root_wallet = Wallet()

# Now you can show the mnemonic words generated. Store them in a safe place!
# They will help you recover your wallet if you ever lose your computer. You can
# also use them to import this wallet into a different wallet application.
print(root_wallet.words)

# IMPORTANT NOTE: You should never use your root wallet to sign transactions
# directly. Instead, you are supposed to use it to generate multiple "child
# wallets" using the method introduced in BIP 32 (see: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
# These child wallets are the ones you should use for receiving and sending
# transactions.

# Enough talk! Let's create our first child wallet!
child_wallet = root_wallet.hd_wallet("m/84'/0'/0'/0/0")

# That's it :)

# These are your keys (in serialized format). For details on key serialization,
# see: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
print(child_wallet.serialized_extended_private_key)
print(child_wallet.serialized_extended_public_key)

# Now let's see your bitcoin address so people can send you lots of BTCs.
print(child_wallet.address.bitcoin.P2WPKH_wit0)
```

### Import an existing wallet (from mnemonic words)
```python
from cryptowrench.wallet import Wallet

# IMPORTANT: Do not use the following words to generate your wallet because they
# are not random and they are publicly available in the internet. If you do it,
# you will lose all your money and axe-throwing monkeys will descend from the
# skies to hunt you down.
words = 'fetch pool sight try enhance squirrel must range rotate maple resemble forest'
# If your wallet had a password, you should pass it to the Wallet class as well.
pwd = ''

# This will import a root wallet from the provided mnemonic and password.
root_wallet = Wallet(mnemonic=words, passphrase=pwd)

# This is the first child wallet.
child_wallet = root_wallet.hd_wallet("m/84'/0'/0'/0/0")
print(f"P2WPKH0:  {child_wallet.address.bitcoin.P2WPKH_wit0}")

# You can also generate old wallet formats, like this:

# Original bitcoin wallet format (P2PKH or Pay-to-PubKey-Hash).
# How to recognize them? They start with the number 1.
# NOTE: it is not recommended to use this wallet format nowadays because it uses
# the most amount of space inside a transaction and is therefore the most
# "expensive" address type.
child_wallet = root_wallet.hd_wallet("m/44'/0'/0'/0/0")
print(f"P2PKH:    {child_wallet.address.bitcoin.P2PKH}")

# BIP 13 bitcoin wallet format (P2SH or Pay-to-Script-Hash).
# How to recognize them? They start with the number 3.
# NOTE: to better understand what these addresses enable in the bitcoin
# blockchain, refert to the original BIP that introduced them:
# https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
# Also you can take a look at BIP 16, which introduced the corresponding new
# transaction type: https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
child_wallet = root_wallet.hd_wallet("m/49'/0'/0'/0/0")
print(f"P2SH:     {child_wallet.address.bitcoin.P2SH}")

# Finally, if your seed comes from an Ethereum wallet, you can also peek into
# those addresses as well:
child_wallet = root_wallet.hd_wallet("m/44'/60'/0'/0/0")
print(f"Ethereum: {child_wallet.address.ethereum}")
```

### Import an existing wallet (from seed)
```python
from cryptowrench.wallet import Wallet

# IMPORTANT: Do not use the following seed to generate your wallet because is
# not random and it is publicly available in the internet. If you do it, you
# will lose all your money and angry elephants will eat all your crops.
# Make sure the seed is in bytes.
seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

# This will import a root wallet from the provided seed.
root_wallet = Wallet(seed=seed)

# This is the first child wallet.
child_wallet = root_wallet.hd_wallet("m/44'/60'/0'/0/0")
print(f"Ethereum:  {child_wallet.address.ethereum}")
```

## ⚠ Disclaimer
Although I try my best to make these tools as correct and reliable as possible, `please for the love of dinosaurs` do not rely on them for storing your money. Use a proper wallet for that instead (see: [ethereum.org/en/wallets/](https://ethereum.org/en/wallets) for some fully featured ones).

That said, this library has been tested against publicly available test vectors (i.e. from [bip32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors) and [bip39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#Test_vectors), among others), which means that it should be mostly correct for those functionalities. Expect more tests to be added in the future, and see [`run_tests.py`](https://github.com/omirete/cryptowrench/blob/master/run_tests.py) if you would like to run these tests yourself.

## 🤝 Colaborate :)
Please create issues/pull requests/feature requests where needed. I'm also looking to collaborate in other open source projects, so let me know if you would like to talk!
