package df.sign.pkcs11;

import java.security.cert.X509Certificate;
import java.util.ArrayList;

public class CertificateData {
    public String id;
    public String dll;
    public long slot;
    public byte[] certID;
    public byte[] certLABEL;
    public X509Certificate cert;
    public ArrayList<CertificateData> alternativeCertificateList = new ArrayList<>();

    // ✅ Constructor for compatibility with SmartCardAccessSunImpl
    public CertificateData(String alias, X509Certificate cert) {
        this.id = alias;
        this.cert = cert;
    }

    @Override
    public int hashCode() {
        return cert.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof CertificateData))
            return o == this;
        return ((CertificateData) o).cert.equals(this.cert);
    }
}
