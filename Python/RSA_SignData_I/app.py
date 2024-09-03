from flask import Flask, request, jsonify
from crypto import encrypt_aes, decrypt_aes, encrypt_aes_key, decrypt_aes_key, sign_data, verify_data
from key_manager import load_public_key, load_private_key, get_aes_key

app = Flask(__name__)

AES_KEY_BASE64 = "8w4tsmc30GjwOiqNR53VKQHlNu7CzXjWFBPJTLgOx2E="

@app.route('/encrypt_and_sign', methods=['POST'])
def encrypt_and_sign():
    try:
        data = request.json.get('data')
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        public_key = load_public_key()
        private_key = load_private_key()
        aes_key = get_aes_key(AES_KEY_BASE64)

        # Encrypt the data using AES
        encrypted_data = encrypt_aes(data, aes_key)

        # Encrypt the AES key using RSA
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

        # Sign the encrypted data
        signature = sign_data(encrypted_data, private_key)

        return jsonify({
            'encrypted_data': encrypted_data,
            'encrypted_aes_key': encrypted_aes_key,
            'signature': signature
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify_and_decrypt', methods=['POST'])
def verify_and_decrypt():
    try:
        encrypted_data = request.json.get('encrypted_data')
        signature = request.json.get('signature')
        encrypted_aes_key = request.json.get('encrypted_aes_key')

        if not encrypted_data or not signature or not encrypted_aes_key:
            return jsonify({'error': 'Missing parameters'}), 400

        public_key = load_public_key()
        private_key = load_private_key()

        # Verify the signature
        is_signature_valid = verify_data(encrypted_data, signature, public_key)

        if not is_signature_valid:
            return jsonify({'error': 'Signature verification failed'}), 400

        # Decrypt the AES key using RSA
        aes_key = decrypt_aes_key(encrypted_aes_key, private_key)

        # Decrypt the data using AES
        decrypted_data = decrypt_aes(encrypted_data, aes_key)

        return jsonify({
            'signature_valid': is_signature_valid,
            'decrypted_data': decrypted_data
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=6001)
