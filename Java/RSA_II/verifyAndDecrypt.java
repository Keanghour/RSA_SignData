package Java.RSA_II;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class verifyAndDecrypt {

    // Load the public key from a PEM file
    private static PublicKey getPublicKey(String path) throws Exception {
        String publicKeyPEM = new String(Files.readAllBytes(Paths.get(path)));
        publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    // Load the private key from a PEM file
    private static PrivateKey getPrivateKey(String path) throws Exception {
        String privateKeyPEM = new String(Files.readAllBytes(Paths.get(path)));
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    // Convert Base64 encoded AES key to SecretKey object
    private static SecretKey getAESKey(String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(keyBytes, "AES");
    }

    // Decrypt data using AES
    public static String decryptAES(String encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedData = cipher.doFinal(decodedData);
        return new String(decryptedData, "UTF-8");
    }

    // Decrypt AES key using RSA private key
    public static SecretKey decryptAESKey(String encryptedKey, String pathPrivateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        PrivateKey privateKey = getPrivateKey(pathPrivateKey);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedKey = Base64.getDecoder().decode(encryptedKey);
        byte[] keyBytes = cipher.doFinal(decodedKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    // Verify data signature using RSA public key
    public static boolean verifyData(String data, String signatureBase64, String pathPublicKey) throws Exception {
        PublicKey publicKey = getPublicKey(pathPublicKey);
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data.getBytes("UTF-8"));
        byte[] signature = Base64.getDecoder().decode(signatureBase64);
        return verifier.verify(signature);
    }

    public static void main(String[] args) {
        try {
            // Paths and key data
            String pathPublicKey = "public_key.pem";
            String pathPrivateKey = "private_key.pem";

            // Sample data to decrypt
            String encryptedData = "226hF3MYBcIzawDhqWS0HQ==";
            String encryptedAESKey = "WsNLyW6fB1W18c1uPc8kR78RiVZO4ddReEOv4f2Nkf7vue5o7+ZN9DQIwmtb6WJMcGnrPnainqWB8GfDG3n9N4BVLOGZ7DaVnN199GglQqppTKJ4Rcng4jOOmeTdeBULcQa+j5VbB8QoT9RMnnkfpgu3pufld6k0UYHmcW8iHrlfM6Vr8OYNtwtN7+LbLAnrG/Mn8Vqsrkc9KkzV3qevbAZmxiUvWTBgwwukbxRUuOdYNZbc71Cu29tHZhNRmYmMDwQpbJsCTRzlXOM8sBB9o+A1hmzEIT88q9cYyLTzfX1dtwPRLgfWt3l7nbsUaAryDpRScyqx7i/dX6R22Thzrg==";
            String signature = "HAKk0ywO61Syqj6R/Qvnw2HIVPK6oXFcAymtTRc8pOeR02NiC7d6nNtMBxy3jjIeaT6xVrrxEt+SWam7cA1Un497uuDHNqVn0XdPqEo0m8rDN+N1Phv0gsVqgrj3PH4hk7YXEwaRjQo9cEXJKV3snjcdzHs8042oaPEyLY9eF3EW5HPkh/SSLgRdZWS51wwbpoI6O86NyqUcAjGQxXV5QDQQSxihsOpPhRFMkJhFSLssnvajzit5xHGwDDSxQ5d04PeGSO6F9cKayw+boJSmEDmJktOG2m6mYrkBFvFvZBsUhqUbH8u3JKcfjClmAVAvqRVD4/bWDwLqyPVB+DWBfw==";

            // Decrypt the AES key and data
            SecretKey decryptedAESKey = decryptAESKey(encryptedAESKey, pathPrivateKey);
            String decryptedData = decryptAES(encryptedData, decryptedAESKey);
            System.out.println("Decrypted Data: " + decryptedData);

            boolean isSignatureValid = verifyData(decryptedData, signature, pathPublicKey);
            System.out.println("Signature Valid: " + isSignatureValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
