package Java.JAR;

import javax.crypto.SecretKey;

public class sample {
    public static void main(String[] args) {
        try {

            // set keys
            String pathPublicKey = "";
            String pathPrivateKey = "";
            String key = "8w4tsmc30GjwOiqNR53VKQHlNu7CzXjWFBPJTLgOx2E=";

            // Sample data to encrypt
            String data = "Hello Testing";

            // Encrypt the data
            String encryptedData = signData.encryptAES(data, key);
            System.out.println("Encrypted Data: " + encryptedData);

            String encryptedAESKey = signData.encryptAESKey(key, pathPublicKey);
            System.out.println("Encrypted AES Key: " + encryptedAESKey);

            String signature = signData.signData(data, pathPrivateKey);
            System.out.println("Data Signature: " + signature);

            // Decrypt the data
            SecretKey decryptedAESKey = signData.decryptAESKey(encryptedAESKey, pathPrivateKey);
            String decryptedData = signData.decryptAES(encryptedData, decryptedAESKey);
            System.out.println("Decrypted Data: " + decryptedData);

            boolean isSignatureValid = signData.verifyData(data, signature, pathPublicKey);
            System.out.println("Signature Valid: " + isSignatureValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}