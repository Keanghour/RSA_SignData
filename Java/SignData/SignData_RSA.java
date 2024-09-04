import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
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

public class RSA_AES_SignData3 {

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

    // Generate a new random AES key
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Choose key size (128, 192, or 256 bits)
        return keyGen.generateKey();
    }

    // Convert AES key to Base64 encoded string
    public static String encodeAESKeyToBase64(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    // Convert Base64 encoded AES key to SecretKey object
    public static SecretKey decodeAESKeyFromBase64(String base64Key) {
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

    // Decrypt data using AES
    public static String decryptAES(String encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedData = cipher.doFinal(decodedData);
        return new String(decryptedData, "UTF-8");
    }

    // Encrypt AES key using RSA public key
    public static String encryptAESKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    // Decrypt AES key using RSA private key
    public static SecretKey decryptAESKey(String encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedKey = Base64.getDecoder().decode(encryptedKey);
        byte[] keyBytes = cipher.doFinal(decodedKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    // Sign data using RSA private key
    public static String signData(String data, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(data.getBytes("UTF-8"));
        byte[] signature = signer.sign();
        return Base64.getEncoder().encodeToString(signature);
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
            // Load keys
            PublicKey publicKey = getPublicKey();
            PrivateKey privateKey = getPrivateKey();

            // Generate a new AES key
            SecretKey aesKey = generateAESKey();
            String aesKeyBase64 = encodeAESKeyToBase64(aesKey);
            System.out.println("Generated AES Key (Base64): " + aesKeyBase64);

            // Sample data to encrypt
            String data = "Keys random";

            // Encrypt and decrypt the data
            String encryptedData = encryptAES(data, aesKey);
            System.out.println("Encrypted Data: " + encryptedData);

            String encryptedAESKey = encryptAESKey(aesKey, publicKey);
            System.out.println("Encrypted AES Key: " + encryptedAESKey);

            String signature = signData(data, privateKey);
            System.out.println("Data Signature: " + signature);

            SecretKey decryptedAESKey = decryptAESKey(encryptedAESKey, privateKey);
            String decryptedData = decryptAES(encryptedData, decryptedAESKey);
            System.out.println("Decrypted Data: " + decryptedData);

            boolean isSignatureValid = verifyData(data, signature, publicKey);
            System.out.println("Signature Valid: " + isSignatureValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
