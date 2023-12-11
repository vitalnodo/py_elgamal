from MODP import Parameters
from utils import randrange

class KeyPair:
    """private key"""
    __a: int
    """public key"""
    __b: int

    def __init__(self, parameters: Parameters):
        self.__a = randrange(1, parameters.p-1)
        self.__b = pow(parameters.g, self.__a, parameters.p)

    def get_private(self):
        return self.__a

    def get_public(self):
        return self.__b
