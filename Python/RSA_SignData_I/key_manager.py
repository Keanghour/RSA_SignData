from cryptography.hazmat.primitives import serialization
import base64

RSA_PUBLIC_KEY_PATH = 'Keys/public_key.pem'
RSA_PRIVATE_KEY_PATH = 'Keys/private_key.pem'

def load_public_key():
    with open(RSA_PUBLIC_KEY_PATH, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

def load_private_key():
    with open(RSA_PRIVATE_KEY_PATH, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

def get_aes_key(base64_key):
    key_bytes = base64.b64decode(base64_key)
    return key_bytes
