import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class aes_encrypt {

    public static void main(String[] args)
            throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException,
            IOException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableKeyException {

        /* programatically configure pkcs11 provider */
        String configName = "/usr/local/lib/softhsm/pkcs11.cfg";
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(configName);
        Security.addProvider(p);

        char [] pin = {'1', '2', '3', '4', '5', '6'};//token pin
        KeyStore HSM_Based_JavaKeyStore = KeyStore.getInstance("PKCS11", "SunPKCS11-SoftHSMv2"); // crypto-provider is called: SunPKCS11-LunaSA5
        HSM_Based_JavaKeyStore.load(null, pin);//open a session to the HSM

        String s = "Hello there. How are you? Have a nice day.";//some data to encrypt

        // Load the SecretKey from the HSM by label
        SecretKey aesKey = (SecretKey) HSM_Based_JavaKeyStore.getKey("db-encryption-secret", pin);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[16]);

        // Encrypt cipher
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunPKCS11-SoftHSMv2");
        encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParameterSpec);

        // Encrypt
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, encryptCipher);
        cipherOutputStream.write(s.getBytes());
        cipherOutputStream.flush();
        cipherOutputStream.close();
        byte[] encryptedBytes = outputStream.toByteArray();

        // Decryption cipher
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunPKCS11-SoftHSMv2");

        decryptCipher.init(Cipher.DECRYPT_MODE, aesKey,ivParameterSpec);

        // Decrypt data
        outputStream = new ByteArrayOutputStream();
        ByteArrayInputStream inStream = new ByteArrayInputStream(encryptedBytes);
        CipherInputStream cipherInputStream = new CipherInputStream(inStream, decryptCipher);
        byte[] buf = new byte[1024];
        int bytesRead;
        while ((bytesRead = cipherInputStream.read(buf)) >= 0) {
            outputStream.write(buf, 0, bytesRead);
        }

        System.out.println("Result: " + new String(outputStream.toByteArray()));

    }

}