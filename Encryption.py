from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

AES_KEY_BYTES = 32
NONCE_BYTES = 12

class Encryption:
    def __init__(self, rsa_public_key_obj):
        self.rsa_pub = rsa_public_key_obj

    def hybrid_encrypt(self, plaintext_bytes: bytes):
        # generating AES key
        aes_key = get_random_bytes(AES_KEY_BYTES)

        # encrypting message with AES and Nonce
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=get_random_bytes(NONCE_BYTES))
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext_bytes)
        nonce = cipher_aes.nonce

        # encrypt AES key using RSA-OAEP
        rsa_cipher = PKCS1_OAEP.new(self.rsa_pub)
        enc_aes_key = rsa_cipher.encrypt(aes_key)

        # returning values that will be send to other user
        return enc_aes_key, nonce, ciphertext, tag
    
    