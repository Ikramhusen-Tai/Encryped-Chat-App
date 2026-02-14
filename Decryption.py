from Crypto.Cipher import AES, PKCS1_OAEP

class Decryption:
    def __init__(self, rsa_private_key_obj):
        self.rsa_priv = rsa_private_key_obj

    def hybrid_decrypt(self, enc_aes_key, nonce, ciphertext, tag):
        
        # RSA decrypt AES key
        rsa_cipher = PKCS1_OAEP.new(self.rsa_priv)
        aes_key = rsa_cipher.decrypt(enc_aes_key)

        # AES decrypt message
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        return cipher_aes.decrypt_and_verify(ciphertext, tag)