import MODP
from KeyPair import KeyPair
from raw_crypt import encrypt, decrypt
from sign import sign, verify

if __name__ == "__main__":
    parameters = MODP.MODP2048
    keypair = KeyPair(parameters)
    print("Verifying cipher...")
    cipher = encrypt(parameters, keypair.get_public(), 10563)
    assert decrypt(parameters, keypair.get_private(), cipher) == 10563
    print("Verying signature...")
    signature = sign(parameters, keypair.get_private(), b"raining cats")
    assert verify(parameters, keypair.get_public(), 
        b"raining cats", signature) == True
