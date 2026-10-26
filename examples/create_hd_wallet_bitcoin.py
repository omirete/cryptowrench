from cryptowrench.wallet import Wallet

# This will create a master wallet automatically
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

# Enough talk! Let's create our first child wallets!

# BIP 32 style
bip32_wallet = root_wallet.hd_wallet("m/0/0")
print('BIP 32 Address:', bip32_wallet.address.bitcoin.P2PKH)

# BIP 44 style
bip44_wallet = root_wallet.hd_wallet("m/44'/0'/0'/0/0")
print('BIP 44 Address:', bip44_wallet.address.bitcoin.P2PKH)

# BIP 49 style
bip49_wallet = root_wallet.hd_wallet("m/49'/0'/0'/0/0")
print('BIP 49 Address:', bip49_wallet.address.bitcoin.P2SH)

# BIP 84 style
bip84_wallet = root_wallet.hd_wallet("m/84'/0'/0'/0/0")
print('BIP 84 Address:', bip84_wallet.address.bitcoin.P2WPKH_wit0)

# BIP 141 style
bip141_wallet = root_wallet.hd_wallet("m/0/0")
print('BIP 141 Address:', bip141_wallet.address.bitcoin.P2SH)

# These are your keys (in serialized format). For details on key serialization,
# see: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format

bip44_keys = root_wallet.hd_wallet("m/44'/0'/0'/0")
print("BIP 44 private key:", bip44_keys.serialized_extended_private_key)
print("BIP 44 public key:", bip44_keys.serialized_extended_public_key)

# That's it :)
