import os
from Crypto.PublicKey import RSA

class KeyManager:

    def save_pem(path, key_bytes):
        with open(path, "wb") as f:
            f.write(key_bytes)

    def load_pem(path):
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            return f.read()

    def generate_rsa(bits):
        key = RSA.generate(bits)
        priv = key.export_key()
        pub = key.publickey().export_key()
        return priv, pub, key, key.publickey()