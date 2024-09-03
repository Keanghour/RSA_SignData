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

public class encryptAndSign {

    private static final String RSA_PUBLIC_KEY_PATH = "public_key.pem";
    private static final String RSA_PRIVATE_KEY_PATH = "private_key.pem";
    private static final String AES_KEY_BASE64 = "8w4tsmc30GjwOiqNR53VKQHlNu7CzXjWFBPJTLgOx2E=";

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

    // Encrypt data using AES
    public static String encryptAES(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // Encrypt AES key using RSA public key
    public static String encryptAESKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    // Sign data using RSA private key
    public static String signData(String data, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(data.getBytes("UTF-8"));
        byte[] signature = signer.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public static void main(String[] args) {
        try {
            // Load keys
            PublicKey publicKey = getPublicKey();
            PrivateKey privateKey = getPrivateKey();
            SecretKey aesKey = getAESKey(AES_KEY_BASE64);

            // Sample data to encrypt
            String data = "Hello Testing";

            // Encrypt and sign the data
            String encryptedData = encryptAES(data, aesKey);
            System.out.println("Encrypted Data: " + encryptedData);

            String encryptedAESKey = encryptAESKey(aesKey, publicKey);
            System.out.println("Encrypted AES Key: " + encryptedAESKey);

            String signature = signData(data, privateKey);
            System.out.println("Data Signature: " + signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
