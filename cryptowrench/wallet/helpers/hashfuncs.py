import hashlib
from Crypto.Hash import keccak

def get_hash160(value) -> bytes:
    iter_1 = hashlib.new('sha256', value).digest()
    iter_2 = hashlib.new('ripemd160', iter_1).digest()
    return iter_2

def keccak256(value: bytes) -> bytes:
    return keccak.new(
        data=value,
        digest_bits=256).digest()

def keccak256_str(value: str) -> bytes:
    return keccak.new(
        data=value.encode('utf-8'),
        digest_bits=256).digest()
