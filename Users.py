import os
from Crypto.PublicKey import RSA
from KeyManager import KeyManager

class Users:
    def __init__(self, name):
        self.name = name

        # RSA encryption keypair
        self.enc_priv = None
        self.enc_pub = None
        self.enc_key_obj = None
        self.enc_pub_obj = None

        # RSA signing keypair
        self.sig_priv = None
        self.sig_pub = None
        self.sig_key_obj = None
        self.sig_pub_obj = None

    def has_keys(self):
        return all([
            self.enc_priv, self.enc_pub,
            self.sig_priv, self.sig_pub
        ])

    def generate_keys(self, bits):
        # Encryption keypair
        priv, pub, priv_obj, pub_obj = KeyManager.generate_rsa(bits)
        self.enc_priv = priv
        self.enc_pub = pub
        self.enc_key_obj = priv_obj
        self.enc_pub_obj = pub_obj

        KeyManager.save_pem(f"{self.name}_enc_private.pem", priv)
        KeyManager.save_pem(f"{self.name}_enc_public.pem", pub)

        # Signing keypair
        s_priv, s_pub, s_priv_obj, s_pub_obj = KeyManager.generate_rsa(bits)
        self.sig_priv = s_priv
        self.sig_pub = s_pub
        self.sig_key_obj = s_priv_obj
        self.sig_pub_obj = s_pub_obj

        KeyManager.save_pem(f"{self.name}_sig_private.pem", s_priv)
        KeyManager.save_pem(f"{self.name}_sig_public.pem", s_pub)

        return True

    def load_keys_if_exist(self):
        try:
            # Encryption keys
            enc_priv = KeyManager.load_pem(f"{self.name}_enc_private.pem")
            enc_pub = KeyManager.load_pem(f"{self.name}_enc_public.pem")

            if enc_priv and enc_pub:
                self.enc_priv = enc_priv
                self.enc_pub = enc_pub
                self.enc_key_obj = RSA.import_key(enc_priv)
                self.enc_pub_obj = RSA.import_key(enc_pub)

            # Signing keys
            sig_priv = KeyManager.load_pem(f"{self.name}_sig_private.pem")
            sig_pub = KeyManager.load_pem(f"{self.name}_sig_public.pem")

            if sig_priv and sig_pub:
                self.sig_priv = sig_priv
                self.sig_pub = sig_pub
                self.sig_key_obj = RSA.import_key(sig_priv)
                self.sig_pub_obj = RSA.import_key(sig_pub)

            return self.has_keys()
        except:
            return False