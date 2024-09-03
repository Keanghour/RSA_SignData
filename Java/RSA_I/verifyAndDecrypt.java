package Java.RSA_I;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class verifyAndDecrypt {

    private static final String RSA_PUBLIC_KEY_PATH = "public_key.pem";
    private static final String RSA_PRIVATE_KEY_PATH = "private_key.pem";

    // Load the public key from a PEM file
    public static PublicKey getPublicKey() throws Exception {
        String publicKeyPEM = new String(Files.readAllBytes(Paths.get(RSA_PUBLIC_KEY_PATH)));
        publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    // Load the private key from a PEM file
    public static PrivateKey getPrivateKey() throws Exception {
        String privateKeyPEM = new String(Files.readAllBytes(Paths.get(RSA_PRIVATE_KEY_PATH)));
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    // Convert Base64 encoded AES key to SecretKey object
    public static SecretKey getAESKey(String base64Key) {
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
    public static SecretKey decryptAESKey(String encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedKey = Base64.getDecoder().decode(encryptedKey);
        byte[] keyBytes = cipher.doFinal(decodedKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    // Verify data signature using RSA public key
    public static boolean verifyData(String data, String signatureBase64, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data.getBytes("UTF-8"));
        byte[] signature = Base64.getDecoder().decode(signatureBase64);
        return verifier.verify(signature);
    }

    public static void main(String[] args) {
        try {
            // Sample data to verify and decrypt (replace with actual values)
            String encryptedData = "226hF3MYBcIzawDhqWS0HQ==";
            String encryptedAESKey = "HwNJ+hBbpKaSTrcjljdiG2INKrRDES5LzTwJRpeQBhOJGk+z0lUJApvKdoTSMpaB2nT+LuE7W/c/91dFhxnyCrLrIwcO895StD9sULcCE3nkbpUXgWCQ8xM66QVvBhFQALlByb4xoVd2KN6V6kYl5U3agy3mFOGIINXsWmOgF18tT0FULiacVSj7Bj2E6/kt8NGe8Sjk26P34f0szse6XFzSr68Vvd0z5eFCTjC/zZTsMIeW7fFuLISFYVA+zG3y0NOn19Q1jw7VG9DKHC+SDyUUo3TtPvpaUYo4dQkEoX3AGEqriM4gf9mkqVp6xzF955q/09A1HejJTvHyWDj0Wg==";
            String signature = "HAKk0ywO61Syqj6R/Qvnw2HIVPK6oXFcAymtTRc8pOeR02NiC7d6nNtMBxy3jjIeaT6xVrrxEt+SWam7cA1Un497uuDHNqVn0XdPqEo0m8rDN+N1Phv0gsVqgrj3PH4hk7YXEwaRjQo9cEXJKV3snjcdzHs8042oaPEyLY9eF3EW5HPkh/SSLgRdZWS51wwbpoI6O86NyqUcAjGQxXV5QDQQSxihsOpPhRFMkJhFSLssnvajzit5xHGwDDSxQ5d04PeGSO6F9cKayw+boJSmEDmJktOG2m6mYrkBFvFvZBsUhqUbH8u3JKcfjClmAVAvqRVD4/bWDwLqyPVB+DWBfw==";
            String data = "Hello Testing"; // Original data to compare

            // Load keys
            PublicKey publicKey = getPublicKey();
            PrivateKey privateKey = getPrivateKey();

            // Decrypt AES key and data
            SecretKey decryptedAESKey = decryptAESKey(encryptedAESKey, privateKey);
            String decryptedData = decryptAES(encryptedData, decryptedAESKey);
            System.out.println("Decrypted Data: " + decryptedData);

            // Verify signature
            boolean isSignatureValid = verifyData(data, signature, publicKey);
            System.out.println("Signature Valid: " + isSignatureValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
