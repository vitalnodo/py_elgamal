import hashlib
from typing import Tuple
from math import gcd

from MODP import Parameters
from utils import randrange

H = hashlib.sha256

""" a private key, m message """
def sign(parameters: Parameters, a: int, m: bytes) -> Tuple[int, int]:
    p = parameters.p
    p_sub_1 = p-1
    g = parameters.g
    k = randrange(1, p)
    while gcd(k, p_sub_1) != 1:
        k = randrange(1, p)
    r = pow(g, k, p)
    H_m = int(H(m).hexdigest(), 16)
    s = ((H_m - a*r) % p_sub_1 * pow(k, -1, p_sub_1)) % p_sub_1
    return (r,s)

""" b public key, m message """
def verify(parameters: Parameters, b: int, m: bytes, 
    signature: Tuple[int, int]) -> bool:
    p = parameters.p
    p_sub_1 = p-1
    g = parameters.g
    r,s = signature
    y = pow(b, -1, p)
    H_m = int(H(m).hexdigest(), 16)
    u1 = (H_m * pow(s, -1, p_sub_1)) % p_sub_1
    u2 = (r * pow(s, -1, p_sub_1)) % p_sub_1
    v = (pow(g, u1, p) * pow(y, u2, p)) % p
    return r == v

# Обчисліть обернений елемент до відкритого ключа: y = b^(-1) mod p.
# Обчисліть першу складову перевірки: u1 = (H(m) * s^(-1)) mod (p-1).
# Обчисліть другу складову перевірки: u2 = (r * s^(-1)) mod (p-1).
# Обчисліть перевірочне значення: v = (g^u1 * y^u2) mod p.
# Підпис вважається вірним, якщо v = r.
