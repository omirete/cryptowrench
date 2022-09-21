from cryptowrench.wallet.helpers.adresses.ethereum import checksum as ethereum_checksum

def test_ethereum_address_checksum(address: str):
    checksum_encoded = ethereum_checksum(address)
    assert checksum_encoded == address, f"{checksum_encoded} != expected {address}"
    return True

# Test that ethereum address checksum
def run_tests():
    print(test_ethereum_address_checksum("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"))
    print(test_ethereum_address_checksum("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"))
    print(test_ethereum_address_checksum("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"))
    print(test_ethereum_address_checksum("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"))