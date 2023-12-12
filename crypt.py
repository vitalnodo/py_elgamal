from typing import List, Tuple
from raw_crypt import raw_encrypt, raw_decrypt
from KeyPair import KeyPair
from MODP import Parameters, MODP2048

# CMS (Cryptographic Message Syntax). 
# This pads with the same value as the number of padding bytes. 
def pad(msg: bytes, block_length: int) -> bytes:
    padding_length = (block_length - len(msg)) % block_length
    return msg + bytes([padding_length] * padding_length)

def has_padding(padded_msg: bytes, block_length: int) -> bool:
    padding_length = padded_msg[-1]
    return padded_msg[-padding_length:] == bytes([padding_length] * padding_length)

def unpad(padded_msg: bytes, block_length: int) -> bytes:
    if has_padding(padded_msg, block_length):
        return padded_msg[:-padded_msg[-1]]
    return padded_msg

def encrypt(parameters: Parameters, b: int, m: bytes) -> List[Tuple[int, int]]:
    block_byte_length = parameters.p.bit_length() // 8
    res = []
    for i in range(0, len(m), block_byte_length):
        block = m[i:i + block_byte_length]
        padded_block = pad(block, block_byte_length)
        encrypted = raw_encrypt(parameters, b, int.from_bytes(padded_block, 'big'))
        res.append(encrypted)
    return res

def decrypt(parameters: Parameters, a: int, cipher: List[Tuple[int, int]]) -> bytes:
    block_byte_length = (parameters.p.bit_length() + 7) // 8
    res = b""
    for c in cipher:
        decrypted = raw_decrypt(parameters, a, c)
        block_bytes = decrypted.to_bytes(block_byte_length, 'big')
        res += unpad(block_bytes, block_byte_length)
    return res
