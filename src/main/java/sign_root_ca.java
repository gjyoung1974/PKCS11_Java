import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

class sign_root_ca {
    public static void main(String args[]) throws Exception {

        char [] pin = {'1', '2', '3', '4'};//token pin

        /* programatically configure pkcs11 provider */
        String configName = "/usr/local/lib/softhsm/pkcs11.cfg";
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(configName);
        Security.addProvider(p);

        KeyStore hsm = KeyStore.getInstance("PKCS11", "SunPKCS11-SoftHSMv2"); // crypto-provider is called: SunPKCS11-LunaSA5
        hsm.load(null, pin);//open a session to the HSM

        // Load the key store
        KeyStore ks = KeyStore.getInstance("PKCS11", p);
        ks.load(null, pin);

        // Generate the key
        SecureRandom sr = new SecureRandom();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", p);
        keyGen.initialize(4096, sr);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey pk = keyPair.getPrivate();

        // Java API requires a certificate chain
        X509Certificate[] chain = generateV3Certificate(keyPair, p);

        ks.setKeyEntry("ROOTCA", pk, "1234".toCharArray(), chain);
        ks.store(null);

        System.out.println(chain[0]);
    }

    public static X509Certificate[] generateV3Certificate(KeyPair pair, Provider p) throws InvalidKeyException, NoSuchProviderException, SignatureException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        /* programatically configure pkcs11 provider */
        Security.addProvider(p);

        BigInteger serialNumber = new BigInteger(256, new Random());
        Calendar cal = Calendar.getInstance();

        // cal.add(cal.getTime());
        Date startDate = cal.getTime();
        Date expiryDate = cal.getTime();
        expiryDate.setYear(expiryDate.getYear() + 30);
        X500Principal dnName = new X500Principal("CN=ACME ROOT Certification Authority, OU=ACME Certification Authorities, O=ACME, C=US");

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(dnName);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setSubjectDN(dnName); // note: same as issuer
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSA");

        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.cRLSign));

        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = certGen.generateX509Certificate(pair.getPrivate(), "SunPKCS11-SoftHSMv2");

        return chain;
    }
}