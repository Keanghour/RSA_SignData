package Java.JAR;

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

public class signData {

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

    // Decrypt data using AES
    public static String decryptAES(String encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedData = cipher.doFinal(decodedData);
        return new String(decryptedData, "UTF-8");
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

    // Decrypt AES key using RSA private key
    public static SecretKey decryptAESKey(String encryptedKey, String pathPrivateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        PrivateKey privateKey = getPrivateKey(pathPrivateKey);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedKey = Base64.getDecoder().decode(encryptedKey);
        byte[] keyBytes = cipher.doFinal(decodedKey);
        return new SecretKeySpec(keyBytes, "AES");
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

    // Verify data signature using RSA public key
    public static boolean verifyData(String data, String signatureBase64, String pathPublicKey) throws Exception {
        PublicKey publicKey = getPublicKey(pathPublicKey);
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data.getBytes("UTF-8"));
        byte[] signature = Base64.getDecoder().decode(signatureBase64);
        return verifier.verify(signature);
    }

}
