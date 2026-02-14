from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

class Signature:
    def __init__(self, private_key_obj=None, public_key_obj=None):
        self.priv = private_key_obj
        self.pub = public_key_obj

    
    def sign(self, data_bytes):
        h = SHA256.new(data_bytes)
        return pkcs1_15.new(self.priv).sign(h)

    # verifying signature 
    def verify(self, data_bytes, signature):
        h = SHA256.new(data_bytes)
        try:
            pkcs1_15.new(self.pub).verify(h, signature)
            return True
        except:
            return False