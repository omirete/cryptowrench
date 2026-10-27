from cryptowrench.wallet import Wallet
from cryptowrench.wallet.helpers.adresses.ethereum import checksum as ethereum_checksum
from test_mnemonics import test_vectors_mnemonic

test_vectors = [
    {
        # Vector 1
        "seed": '000102030405060708090a0b0c0d0e0f',
        "derivation_paths": [
            {
                "path": "m",
                "expected_serialized_pub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                "expected_serialized_priv": "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
            },
            {
                "path": "m/0'",
                "expected_serialized_pub": "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                "expected_serialized_priv": "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
            },
            {
                "path": "m/0'/1",
                "expected_serialized_pub": "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
                "expected_serialized_priv": "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
            },
            {
                "path": "m/0'/1/2'",
                "expected_serialized_pub": "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
                "expected_serialized_priv": "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
            },
            {
                "path": "m/0'/1/2'/2",
                "expected_serialized_pub": "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                "expected_serialized_priv": "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
            },
            {
                "path": "m/0'/1/2'/2/1000000000",
                "expected_serialized_pub": "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
                "expected_serialized_priv": "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
            }
        ],
    },
    {
        # Vector 2
        "seed": 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
        "derivation_paths": [
            {
                "path": "m",
                "expected_serialized_pub": "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
                "expected_serialized_priv": "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
            },
            {
                "path": "m/0",
                "expected_serialized_pub": "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
                "expected_serialized_priv": "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
            },
            {
                "path": "m/0/2147483647'",
                "expected_serialized_pub": "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
                "expected_serialized_priv": "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
            },
            {
                "path": "m/0/2147483647'/1",
                "expected_serialized_pub": "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
                "expected_serialized_priv": "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
            },
            {
                "path": "m/0/2147483647'/1/2147483646'",
                "expected_serialized_pub": "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
                "expected_serialized_priv": "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
            },
            {
                "path": "m/0/2147483647'/1/2147483646'/2",
                "expected_serialized_pub": "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
                "expected_serialized_priv": "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
            }
        ]
    },
    {
        # Vector 3
        # These cases test for the retention of leading zeros. See https://github.com/bitpay/bitcore-lib/issues/47 and https://github.com/iancoleman/bip39/issues/58 for more information. 
        "seed": '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be',
        "derivation_paths": [
            {
                "path": "m",
                "expected_serialized_pub": "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
                "expected_serialized_priv": "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
            },
            {
                "path": "m/0'",
                "expected_serialized_pub": "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
                "expected_serialized_priv": "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
            }
        ]
    },
    {
        # Vector 4
        # These cases test for the retention of leading zeros. See https://github.com/btcsuite/btcutil/issues/172 for more information. 
        "seed": '3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678',
        "derivation_paths": [
            {
                "path": "m",
                "expected_serialized_pub": "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
                "expected_serialized_priv": "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"
            },
            {
                "path": "m/0'",
                "expected_serialized_pub": "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
                "expected_serialized_priv": "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"
            },
            {
                "path": "m/0'/1'",
                "expected_serialized_pub": "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
                "expected_serialized_priv": "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"
            }
        ]
    },
]

test_ethereum_address_checksums = [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]

# Test hd derivation by path
for test_vector in test_vectors:
    print("Testing vector with seed: " + test_vector["seed"])
    seed = bytes.fromhex(test_vector["seed"])
    master_wallet = Wallet(seed=seed)
    case = 0
    for child_wallet_spec in test_vector["derivation_paths"]:
        case += 1
        print(f" - Testing case {case}...")
        derivation_path = child_wallet_spec["path"]
        expected_serialized_priv = child_wallet_spec["expected_serialized_priv"]
        expected_serialized_pub = child_wallet_spec["expected_serialized_pub"]
        
        child_wallet = master_wallet.hd_wallet(derivation_path)
        
        ext_priv = child_wallet.serialized_extended_private_key.decode('utf-8')
        ext_pub = child_wallet.serialized_extended_public_key.decode('utf-8')

        assert ext_priv == expected_serialized_priv, "Test failed."
        assert ext_pub == expected_serialized_pub, "Test failed."
        
        print(" -- \033[32mok\033[0m")

# Test mnemonic and seeds
print("Will now test for mnemonic and seed wallet generation.")
case = 0
for test_vars in test_vectors_mnemonic["english"]:
    case += 1
    print(f" - Testing case {case}...")
    
    passphrase = test_vars[0]
    test_entropy = test_vars[1]
    expected_mnemonic = test_vars[2]
    expected_seed = test_vars[3]
    expected_ext_priv = test_vars[4]
    wallet = Wallet(mnemonic=expected_mnemonic, passphrase=passphrase)
    
    seed = wallet.seed.hex()
    
    child_wallet = wallet.hd_wallet('m')
    ext_priv = child_wallet.serialized_extended_private_key.decode('utf-8')
    
    assert seed == expected_seed, f"Failed test. Expected seed {expected_seed} but obtained {seed}."
    assert ext_priv == expected_ext_priv, f"Failed test. Expected extented private key {expected_ext_priv} but obtained {ext_priv}."
    print(" -- \033[32mok\033[0m")

print("Will now test Ethereum address checksums...")
case = 0
for address in test_ethereum_address_checksums:
    case += 1
    print(f" - Testing case {case}...")
    checksum_encoded = ethereum_checksum(address)
    assert checksum_encoded == address, f"{checksum_encoded} != expected {address}"
    print(" -- \033[32mok\033[0m")
