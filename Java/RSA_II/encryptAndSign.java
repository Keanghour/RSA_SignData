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

public class encryptAndSign {

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

    // Encrypt data using AES
    public static String encryptAES(String data, String key) throws Exception {
        SecretKey secretKey = getAESKey(key);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // Encrypt AES key using RSA public key
    public static String encryptAESKey(String key, String pathPublicKey) throws Exception {
        SecretKey aesKey = getAESKey(key);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        PublicKey publicKey = getPublicKey(pathPublicKey);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    // Sign data using RSA private key
    public static String signData(String data, String pathPrivateKey) throws Exception {
        PrivateKey privateKey = getPrivateKey(pathPrivateKey);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(data.getBytes("UTF-8"));
        byte[] signature = signer.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public static void main(String[] args) {
        try {
            // Paths and key data
            String pathPublicKey = "public_key.pem";
            String pathPrivateKey = "private_key.pem";
            String key = "8w4tsmc30GjwOiqNR53VKQHlNu7CzXjWFBPJTLgOx2E=";

            // Sample data to encrypt
            String data = "Hello Testing";

            // Encrypt the data
            String encryptedData = encryptAES(data, key);
            System.out.println("Encrypted Data: " + encryptedData);

            String encryptedAESKey = encryptAESKey(key, pathPublicKey);
            System.out.println("Encrypted AES Key: " + encryptedAESKey);

            String signature = signData(data, pathPrivateKey);
            System.out.println("Data Signature: " + signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
