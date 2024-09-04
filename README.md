# RSA_AES_SignData2 Class

The `RSA_AES_SignData2` class provides utilities for securely managing and processing data using RSA and AES cryptography. It includes methods for key management, data encryption, and digital signatures. Below is a breakdown of its functionalities:

## 1. Public/Private Key Management

- **Load Public Key**: `getPublicKey(String path)`  
  Reads a PEM-encoded public key from a file and converts it to a `PublicKey` object.

- **Load Private Key**: `getPrivateKey(String path)`  
  Reads a PEM-encoded private key from a file and converts it to a `PrivateKey` object.

## 2. AES Key Management

- **Convert Base64 Encoded AES Key**: `getAESKey(String base64Key)`  
  Converts a Base64-encoded AES key string into a `SecretKey` object.

- **Encrypt AES Key with RSA Public Key**: `encryptAESKey(String key, String pathPublicKey)`  
  Encrypts an AES key using RSA and a public key, returning the encrypted key in Base64 format.

- **Decrypt AES Key with RSA Private Key**: `decryptAESKey(String encryptedKey, String pathPrivateKey)`  
  Decrypts an AES key using RSA and a private key, returning the `SecretKey` object.

## 3. AES Encryption/Decryption

- **Encrypt Data with AES**: `encryptAES(String data, String key)`  
  Encrypts plaintext data using AES encryption with a specified key, returning the encrypted data in Base64 format.

- **Decrypt Data with AES**: `decryptAES(String encryptedData, SecretKey secretKey)`  
  Decrypts Base64-encoded encrypted data using AES with a specified `SecretKey`, returning the plaintext.

## 4. Digital Signatures

- **Sign Data with RSA Private Key**: `signData(String data, String pathPrivateKey)`  
  Creates a digital signature for data using RSA and a private key, returning the signature in Base64 format.

- **Verify Data Signature with RSA Public Key**: `verifyData(String data, String signatureBase64, String pathPublicKey)`  
  Verifies a digital signature using RSA and a public key, returning `true` if the signature is valid and `false` otherwise.

## Key Points

- **AES (Advanced Encryption Standard)**: A symmetric encryption algorithm used for encrypting and decrypting data.
- **RSA (Rivest-Shamir-Adleman)**: An asymmetric encryption algorithm used for encrypting keys and signing data.
- **PEM Format**: A base64 encoded format with header and footer lines used for storing keys.
