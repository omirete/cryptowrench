from hashlib import sha256
from binascii import unhexlify
import datetime as dt, time as t
from typing import Literal, Union

def littleEndian(hex_str):
    aux = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    aux.reverse()
    return ''.join(aux)

def get_seconds_since_1970(datetime_str):
    date = dt.datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%SZ')
    date_1970 = dt.datetime(1970, 1, 1, 0, 0, 0)
    return int((date-date_1970).total_seconds())

def get_target_from_nBits(bits: int):
    target_packed = hex(bits)[2:]
    target_first_two_bytes = int(target_packed[:2], 16)
    target_rest = int(target_packed[2:], 16)
    return hex(target_rest*2**(8*(target_first_two_bytes-3)))

def get_hash_from_header(block_header_as_binary: bytes):
    iter_1 = sha256(block_header_as_binary).digest()
    iter_2 = bytearray(sha256(iter_1).digest())
    iter_2.reverse()
    return '0x' + iter_2.hex()

def validate_block_hash(version: str, hash_previous_block: str, hash_merkle_root: str, time: str, bits: int, nonce: str) -> bool:
    version = littleEndian(hex(version)[2:].zfill(8))
    hashPrevBlock = littleEndian(hash_previous_block)
    hashMerkleRoot = littleEndian(hash_merkle_root)
    time  = littleEndian(hex(get_seconds_since_1970(time))[2:])
    bits_hex  = littleEndian(hex(bits)[2:])
    nonce = littleEndian(hex(nonce)[2:])
    header_hex = version + hashPrevBlock + hashMerkleRoot + time + bits_hex + nonce
    header_bin = unhexlify(header_hex)

    calculated_hash = get_hash_from_header(header_bin)
    
    target = get_target_from_nBits(bits)
    
    if int(calculated_hash, 16) < int(target, 16):
        # Block hash meets the target.
        return True
    else:
        # Block hash does not meet the target.
        return False

def find_block_nonce(version: int, hash_previous_block: str, hash_merkle_root: str, time: str, bits: int) -> Union[str, Literal[False]]:
    start_time = t.time()
    
    target = get_target_from_nBits(bits)

    version_hex = littleEndian(hex(version)[2:].zfill(8))
    hashPrevBlock = littleEndian(hash_previous_block)
    hashMerkleRoot = littleEndian(hash_merkle_root)
    time_hex  = littleEndian(hex(get_seconds_since_1970(time))[2:])
    bits_hex  = littleEndian(hex(bits)[2:])

    header_hex_incomplete = version_hex + hashPrevBlock + hashMerkleRoot + time_hex + bits_hex
    
    # It will loop sequentially over all possible values of the nonce until it
    # finds the magic value that makes the hash meet the target, if it exists
    # for the given parameters. If it doesn't exist, it will return False,
    # meaning the user will have to change some parameters (usually the
    # timestamp) and try again.
    magic_nonce_found = False
    for i in range(0xffffffff):
        nonce = i.to_bytes(4, 'little').hex()
        header_binary = unhexlify(header_hex_incomplete + nonce)
        calculated_hash = get_hash_from_header(header_binary)
        
        if int(calculated_hash, 16) < int(target, 16):
            end_time = t.time()
            magic_nonce_found = True
            print('Nonce found:     ' + str(i))
            print('Time needed (s): ' + str(end_time-start_time))
            print('Block hash:      ' + str(calculated_hash))
            break
    if magic_nonce_found:
        return nonce
    return False