from cryptowrench.wallet import Wallet

# IMPORTANT: Do not use the following seed to generate your wallet because is
# not random and it is publicly available in the internet. If you do it, you
# will lose all your money and axe-throwing monkeys will descend from the skies
# to hunt you down.
# Make sure the seed is in bytes.
seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

# This will import a root wallet from the provided seed.
root_wallet = Wallet(seed=seed)

# IMPORTANT NOTE: You should never use your root wallet to sign transactions
# directly. Instead, you are supposed to use it to generate multiple "child
# wallets" using the method introduced in BIP 32 (see:
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
# These child wallets are the ones you should use for receiving and sending
# transactions.

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
