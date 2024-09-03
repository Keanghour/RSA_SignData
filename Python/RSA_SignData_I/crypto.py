from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64

def encrypt_aes(data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    # PKCS7 padding
    padding_len = 16 - len(data) % 16
    padded_data = data + chr(padding_len) * padding_len
    encrypted_data = encryptor.update(padded_data.encode('utf-8')) + encryptor.finalize()
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_aes(encrypted_data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    decoded_data = base64.b64decode(encrypted_data)
    decrypted_padded_data = decryptor.update(decoded_data) + decryptor.finalize()
    # PKCS7 padding removal
    padding_len = decrypted_padded_data[-1]
    return decrypted_padded_data[:-padding_len].decode('utf-8')

def encrypt_aes_key(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted_key).decode('utf-8')

def decrypt_aes_key(encrypted_key, private_key):
    decoded_encrypted_key = base64.b64decode(encrypted_key)
    aes_key = private_key.decrypt(
        decoded_encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return aes_key

def sign_data(data, private_key):
    # Create a signer object using SHA256withRSA and PKCS1v15 padding
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PKCS1v15(),  # PKCS1v15 padding
        hashes.SHA256()      # SHA-256 hash algorithm
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_data(data, signature_base64, public_key):
    signature = base64.b64decode(signature_base64)
    try:
        public_key.verify(
            signature,
            data.encode('utf-8'),
            padding.PKCS1v15(),  # PKCS1v15 padding
            hashes.SHA256()      # SHA-256 hash algorithm
        )
        return True
    except Exception as e:
        print("Verification failed:", e)  # Print the exception to understand the error
        return False
