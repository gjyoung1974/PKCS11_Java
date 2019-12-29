import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class generate_symmetric_key {

    public static void main(String[] args)
            throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException,
            IOException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableKeyException {

        char [] pin = {'1', '2', '3', '4'};//token pin

        /* programatically configure pkcs11 provider */
        String configName = "/usr/local/lib/softhsm/pkcs11.cfg";
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(configName);
        Security.addProvider(p);

        KeyStore hsm = KeyStore.getInstance("PKCS11", "SunPKCS11-SoftHSMv2"); // crypto-provider is called: SunPKCS11-LunaSA5
        hsm.load(null, pin);//open a session to the HSM

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", hsm.getProvider());
        SecureRandom secureRandom = new SecureRandom();
        int keyBitSize = 256;

        keyGenerator.init(keyBitSize, secureRandom);
        SecretKey key = keyGenerator.generateKey();

        KeyStore.SecretKeyEntry secret = new KeyStore.SecretKeyEntry(key);
        hsm.setEntry("db-encryption-secret", secret, null);

        System.out.println(key);
    }
}