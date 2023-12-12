import MODP
from KeyPair import KeyPair
from raw_crypt import raw_encrypt, raw_decrypt
from crypt import encrypt, decrypt
from sign import sign, verify

if __name__ == "__main__":
    parameters = MODP.MODP2048
    keypair = KeyPair(parameters)
    a, b = keypair.get_private(), keypair.get_public()
    print("Verifying cipher...")
    cipher = raw_encrypt(parameters, b, 10563)
    assert raw_decrypt(parameters, a, cipher) == 10563
    print("Veryfying signature...")
    signature = sign(parameters, a, b"raining cats")
    assert verify(parameters, b, 
        b"raining cats", signature) == True
    print("Veryfying cipher with padding...")
    inp = "В Бахчисараї фельд'єґер зумів одягнути ящірці жовтий капюшон!" * 100
    encrypted = encrypt(parameters, b, inp.encode("utf8"))
    assert decrypt(parameters, a, encrypted).decode("utf8") == inp