from ecdsa import SigningKey, SECP256k1
from ecdsa.ecdsa import curve_secp256k1

def _bip32_uncompress_elliptic_point(compressed_point: bytes):
    assert len(compressed_point) == 33, 'Invalid compressed point.'
    first_byte = compressed_point[0].to_bytes(length=1, byteorder='big')
    assert first_byte == b'\x02' or first_byte == b'\x03', 'Invalid compressed point.'

    x = compressed_point[1:]
    flag_is_y_even = True if first_byte == b'\x02' else False # Don't need to test for \x03 because this is already done at the begining of the function in an assert statement.
    
    def get_y(x, a, b, p, flag_is_y_even):
        # y^2 = x^3 + a*x + b
        # y = sqrt(x^3 + a*x + b)
        y_squared = (pow(x, 3, p) + a*x + b) % p
        y = pow(y_squared, (p + 1) // 4, p)
        
        if y % 2 == 0:
            y_even = y
            y_odd = -y % p
        else:
            y_even = -y % p
            y_odd = y
        
        return y_even if flag_is_y_even == True else y_odd

    # For SECP256k1, the parameters 'a', 'b' and 'p' are:
    a = curve_secp256k1.a()
    b = curve_secp256k1.b()
    p = curve_secp256k1.p()

    x_int = int.from_bytes(x, byteorder='big')
    y_int = get_y(x_int, a, b, p, flag_is_y_even)

    y = y_int.to_bytes(32, byteorder='big')

    return (x, y)

def _bip32_point(value_as_bytes):
    # Returns the coordinate pair resulting from EC point multiplication
    # (repeated application of the EC group operation) of the secp256k1 base
    # point with the integer p.
    a = SigningKey.from_string(
        string=value_as_bytes,
        curve=SECP256k1)
    
    b = a.get_verifying_key().to_string()
    
    x = b[:32]
    y = b[32:]

    return (x, y)

def _bip32_serialize_point(P, return_compressed=True):
    # Serializes the coordinate pair P = (x, y) as a byte sequence using SEC1's
    # compressed form: (0x02 or 0x03) || ser256(x), where the header byte
    # depends on the parity of the omitted y coordinate.
    x = P[0]
    y = P[1]
    
    assert len(x) == 32 and len(y) == 32, 'Point coordinates are not 32 bytes each.'

    if return_compressed == True:
        y_as_int = int.from_bytes(y, byteorder='big')
        prefix = b'\x02' if y_as_int % 2 == 0 else b'\x03'
        return prefix + x
    else:
        return b'\x04' + x + y

