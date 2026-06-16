import os

import rsa

KEY_DIR = os.path.join("cipher", "rsa", "keys")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "privateKey.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "publicKey.pem")


class RSACipher:
    """He ma hoa RSA: tao khoa, ma hoa/giai ma, ky va xac thuc chu ky."""

    def __init__(self):
        if not os.path.exists(KEY_DIR):
            os.makedirs(KEY_DIR)

    def generate_keys(self):
        public_key, private_key = rsa.newkeys(1024)
        with open(PUBLIC_KEY_PATH, "wb") as p:
            p.write(public_key.save_pkcs1("PEM"))
        with open(PRIVATE_KEY_PATH, "wb") as p:
            p.write(private_key.save_pkcs1("PEM"))

    def load_keys(self):
        with open(PRIVATE_KEY_PATH, "rb") as p:
            private_key = rsa.PrivateKey.load_pkcs1(p.read())
        with open(PUBLIC_KEY_PATH, "rb") as p:
            public_key = rsa.PublicKey.load_pkcs1(p.read())
        return private_key, public_key

    def encrypt(self, message, key):
        return rsa.encrypt(message.encode("ascii"), key)

    def decrypt(self, ciphertext, key):
        try:
            return rsa.decrypt(ciphertext, key).decode("ascii")
        except rsa.DecryptionError:
            return False

    def sign(self, message, key):
        return rsa.sign(message.encode("ascii"), key, "SHA-256")

    def verify(self, message, signature, key):
        try:
            rsa.verify(message.encode("ascii"), signature, key)
            return True
        except rsa.VerificationError:
            return False