from typing import Tuple

from MODP import Parameters
from utils import randrange

""" b public key, m message """
def raw_encrypt(parameters: Parameters, b: int, m: int) -> Tuple[int, int]:
    p = parameters.p
    g = parameters.g
    k = randrange(1, p)
    x = pow(g, k, p)
    y = (pow(b,k,p) * (m % p)) % p
    return (x,y)

def raw_decrypt(parameters: Parameters, a: int, cipher: Tuple[int, int]):
    p = parameters.p
    x, y = cipher
    s = pow(x, a, p)
    m = ((y % p) * pow(s, -1, p)) % p
    return m
