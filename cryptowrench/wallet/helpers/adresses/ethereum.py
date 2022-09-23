from ..hashfuncs import keccak256, keccak256_str

# class EthereumAddressHandler():
#     def __init__(self) -> None:
#         pass
    
    

def address_ethereum(uncompressed_public_key: bytes) -> str:
    
    # Remember uncompressed public key has format:
    # prefix + x + y
    # where prefix = '04' (or byte \x04)
    # Ignore the '04' at the start of uncompressed keys:
    public_key_bytes = uncompressed_public_key[1:]

    keccak_hash = keccak256(public_key_bytes)
    wallet = '0x' + keccak_hash[-20:].hex()
    return checksum(wallet)

def checksum(address: str):
    
    address_lower = address.lower()

    checksummed_buffer = ""
    # Treat the hex address as ascii/utf-8 for keccak256 hashing
    hashed_address = keccak256(address_lower[2:].encode('utf-8')).hex()

    # Iterate over each character in the hex address
    for nibble_index, character in enumerate(address_lower[2:]):

        if character in "0123456789":
            # We can't upper-case the decimal digits
            checksummed_buffer += character
        elif character in "abcdef":
            # Check if the corresponding hex digit (nibble) in the hash is 8 or higher
            hashed_address_nibble = int(hashed_address[nibble_index], 16)
            if hashed_address_nibble > 7:
                checksummed_buffer += character.upper()
            else:
                checksummed_buffer += character
        else:
            raise Exception(
                f"Unrecognized hex character {character!r} at position {nibble_index}"
            )

    return "0x" + checksummed_buffer