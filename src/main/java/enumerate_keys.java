import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class enumerate_keys {

    public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, InvalidKeyException, SignatureException {

        /* programatically configure pkcs11 provider */
        String configName = "/usr/local/lib/softhsm/pkcs11.cfg";
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(configName);
        Security.addProvider(p);

        char [] pin = {'1', '2', '3', '4'};//token pin
        KeyStore HSM_Based_JavaKeyStore = KeyStore.getInstance("PKCS11","SunPKCS11-SoftHSMv2"); //crypto-provider is called: SunPKCS11-SoftHSMv2
        HSM_Based_JavaKeyStore.load(null, pin);

        System.out.println("crypto objects contained on HSM: ");
        //list all the certificate objects on the HSM
        Enumeration<?> aliases = HSM_Based_JavaKeyStore.aliases();
        while (aliases.hasMoreElements()) {
            Object alias = aliases.nextElement();
            try {
                Key key0 = HSM_Based_JavaKeyStore.getKey(alias.toString(),pin);
                System.out.println("Name: " + alias.toString() + " | Algorithm: " + key0.getAlgorithm());

            } catch (Exception e) {
                continue;
            }
        }

    }

}