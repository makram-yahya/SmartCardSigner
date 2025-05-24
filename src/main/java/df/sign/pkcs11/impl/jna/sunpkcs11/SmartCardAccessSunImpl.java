package df.sign.pkcs11.impl.jna.sunpkcs11;

import df.sign.pkcs11.SmartCardAccessI;
import df.sign.pkcs11.CertificateData;

import java.io.Console;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.Provider;

public class SmartCardAccessSunImpl implements SmartCardAccessI {

    private static final String CFG_PATH = new java.io.File("config/akis.cfg").getAbsolutePath();
    private KeyStore keystore;
    private Provider pkcs11Provider;

    @Override
    public long[] connectToLibrary(String library) throws Exception {
        pkcs11Provider = new sun.security.pkcs11.SunPKCS11(CFG_PATH);
        Security.addProvider(pkcs11Provider);
        keystore = KeyStore.getInstance("PKCS11", pkcs11Provider);
        return new long[]{0}; // Dummy slot ID
    }

    @Override
    public long getPinMinLength(long slotID) {
        return 4;
    }

    @Override
    public long getPinMaxLength(long slotID) {
        return 8;
    }

    public void init() throws Exception {
        pkcs11Provider = new sun.security.pkcs11.SunPKCS11(CFG_PATH);
        Security.addProvider(pkcs11Provider);

        Console console = System.console();
        if (console == null) {
            throw new RuntimeException("Console not available. Cannot securely prompt for PIN.");
        }

        char[] pin = console.readPassword("Enter smart card PIN: ");
        KeyStore ks = KeyStore.getInstance("PKCS11", pkcs11Provider);
        ks.load(null, pin);
        this.keystore = ks;
    }

    @Override
    public ArrayList<CertificateData> getCertificateList(long slotID) throws Exception {
        if (keystore == null) {
            init();
        } else {
            try {
                keystore.aliases();
            } catch (java.security.KeyStoreException e) {
                Console console = System.console();
                char[] pin;

                if (console != null) {
                    pin = console.readPassword("Enter smart card PIN: ");
                } else {
                    System.out.print("Enter smart card PIN (visible): ");
                    java.util.Scanner scanner = new java.util.Scanner(System.in);
                    pin = scanner.nextLine().toCharArray();
                }

                keystore.load(null, pin);
            }
        }

        ArrayList<CertificateData> certs = new ArrayList<>();
        Enumeration<String> aliases = keystore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            if (keystore.isKeyEntry(alias)) {
                X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
                CertificateData certData = new CertificateData(alias, cert);
                certData.certLABEL = alias.getBytes("UTF-8");
                certs.add(certData);
            }
        }

        return certs;
    }

    @Override
    public long login(long slotID, String pin) throws Exception {
        keystore.load(null, pin.toCharArray());
        return 1; // Dummy session ID
    }

    @Override
    public byte[] signData(long sessionID, byte[] certId, byte[] certLabel, byte[] dataToHashAndSign) throws Exception {
        String alias = new String(certLabel, "UTF-8");

        if (!keystore.containsAlias(alias)) {
            throw new Exception("Certificate alias not found in keystore: " + alias);
        }

        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, null);
        String keyAlg = privateKey.getAlgorithm();
        String algorithm;

        switch (keyAlg) {
            case "RSA":
                algorithm = "NONEwithRSA";
                break;
            case "EC":
                algorithm = "NONEwithECDSA";
                break;
            default:
                throw new Exception("Unsupported key algorithm: " + keyAlg);
        }

        Signature signature = Signature.getInstance(algorithm, pkcs11Provider);
        signature.initSign(privateKey);
        signature.update(dataToHashAndSign);
        return signature.sign();
    }

    @Override
    public void closeSession(long sessionID) {
        // Cleanup if needed
    }

    @Override
    public void disconnectLibrary() {
        // Cleanup if needed
    }
}
