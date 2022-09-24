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

# Enough talk! Let's create our first child wallet!
child_wallet = root_wallet.hd_wallet("m/44'/60'/0'/0/0")

# That's it :)

# These are your keys (in serialized format). For details on key serialization,
# see: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
print(child_wallet.serialized_extended_private_key)
print(child_wallet.serialized_extended_public_key)

# Now let's see your ethereum address so people can send you lots of ETH.
print(child_wallet.address.ethereum)
