package df.sign.pkcs11.impl.jna.sunpkcs11;

import df.sign.pkcs11.SmartCardAccessI;
import df.sign.pkcs11.CertificateData;

import java.io.Console;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

public class SmartCardAccessSunImpl implements SmartCardAccessI {

    private static final String CFG_PATH = "C:/Users/mukar/OneDrive/Desktop/akis.cfg";
    private KeyStore keystore;

    @Override
    public long[] connectToLibrary(String library) throws Exception {
        sun.security.pkcs11.SunPKCS11 pkcs11Provider = new sun.security.pkcs11.SunPKCS11(CFG_PATH);
        Security.addProvider(pkcs11Provider);

        keystore = KeyStore.getInstance("PKCS11", pkcs11Provider);

        return new long[]{0}; // Dummy slot ID
    }

    @Override
    public long getPinMinLength(long slotID) {
        return 4; // Return a safe default or implement actual logic
    }

    @Override
    public long getPinMaxLength(long slotID) {
        return 8; // Return a safe default or implement actual logic
    }

    public void init() throws Exception {
        System.out.println("🔧 Starting SmartCardAccessSunImpl.init()...");

        try {
            // Load SunPKCS11 provider from your .cfg file
            sun.security.pkcs11.SunPKCS11 pkcs11Provider = new sun.security.pkcs11.SunPKCS11(CFG_PATH);
            Security.addProvider(pkcs11Provider);
            System.out.println("📦 PKCS#11 provider added from: " + CFG_PATH);

            // Prompt for PIN using Java Console
            Console console = System.console();
            if (console == null) {
                System.err.println("❌ Console not available. Try running in a terminal (not inside IDE).");
                throw new RuntimeException("Console not available. Cannot securely prompt for PIN.");
            }

            char[] pin = console.readPassword("🔐 Enter smart card PIN: ");
            System.out.println("🔑 PIN entered.");

            // Load keystore from the provider
            KeyStore ks = KeyStore.getInstance("PKCS11", pkcs11Provider);
            ks.load(null, pin);
            this.keystore = ks;

            System.out.println("✅ Keystore successfully loaded. Ready for use.");

            // DEBUG: List aliases
            System.out.println("🔍 Checking for aliases in the keystore...");
            Enumeration<String> aliases = keystore.aliases();
            if (!aliases.hasMoreElements()) {
                System.out.println("⚠ No aliases found in keystore.");
            } else {
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    System.out.println("📌 Alias found: " + alias);
                }
            }

        } catch (Exception e) {
            System.err.println("❌ Failed to initialize smart card keystore.");
            e.printStackTrace();
            throw e;
        }
    }


    @Override
    public ArrayList<CertificateData> getCertificateList(long slotID) throws Exception {
        if (keystore == null) {
            System.out.println("⚠ Keystore is null. Calling init()...");
            init();
        } else {
            System.out.println("✅ Keystore is already initialized. Type: " + keystore.getType());
        }

        ArrayList<CertificateData> certs = new ArrayList<>();
        Enumeration<String> aliases = keystore.aliases();

        if (!aliases.hasMoreElements()) {
            System.out.println("⚠ No aliases found in keystore.");
        }

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("📌 Found alias: " + alias);

            if (keystore.isKeyEntry(alias)) {
                X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
                CertificateData certData = new CertificateData(alias, cert);
                certData.certLABEL = alias.getBytes("UTF-8");
                certs.add(certData);
                System.out.println("✅ Added cert: " + cert.getSubjectX500Principal());
            } else {
                System.out.println("⚠ Alias is not a KeyEntry: " + alias);
            }
        }

        System.out.println("📤 Done. Total certs: " + certs.size());
        return certs;
    }



    @Override
    public long login(long slotID, String pin) throws Exception {
        keystore.load(null, pin.toCharArray());
        return 1; // Dummy session ID
    }

    @Override
    public byte[] signData(long sessionID, byte[] certId, byte[] certLabel, byte[] data) throws Exception {
        // Implement actual signing logic here
        throw new UnsupportedOperationException("signData not yet implemented");
    }

    @Override
    public void closeSession(long sessionID) {
        // Optional: cleanup if needed
    }

    @Override
    public void disconnectLibrary() {
        // Optional: cleanup if needed
    }
}
