package com.valencia.cryptoutils.certs;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemReader;

import com.valencia.jutils.app.NumberConstants;

/**
 * Utilities for generating and saving security certificates and key pairs. The current implementation uses Bouncy Castle.
 * 
 * @author Gabriel Valencia, gee4vee@me.com
 */
public class CertificateUtils {

    public static final String DEFAULT_KEY_ALGORITHM = "RSA";
    public static final int DEFAULT_RSA_KEY_SIZE = 4096;
    public static final int DEFAULT_CERT_VALIDITY_YEARS = 5;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Returns a new RSA 4096-bit key pair.
     * 
     * @throws Exception
     */
    public static KeyPair generateKeyPair() throws Exception {
        return generateKeyPair(DEFAULT_RSA_KEY_SIZE, DEFAULT_KEY_ALGORITHM);
    }

    /**
     * Returns a new RSA key pair with the specified key size.
     * 
     * @param keySize
     *            The size of the key in bits.
     * 
     * @throws Exception
     */
    public static KeyPair generateKeyPair(int keySize) throws Exception {
        return generateKeyPair(keySize, DEFAULT_KEY_ALGORITHM);
    }

    /**
     * Returns a new key pair using the specified algorithm and key size.
     * 
     * @param keySize
     *            The size of the key in bits.
     * @param algorithm
     *            The name of the algorithm to use as defined by {@link KeyPairGenerator}.
     * 
     * @throws Exception
     */
    public static KeyPair generateKeyPair(int keySize, String algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(keySize, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    /**
     * Generates a new self-signed certificate with a newly generated RSA 4096-bit key pair using the specified subject.
     * 
     * @param subjectDN
     * @param isCA
     *            If <code>true</code>, the certificate is for a self-signed certificate authority.
     * 
     * @throws Exception
     */
    public static X509Certificate selfSignedCertificateX509v3(String subjectDN, boolean isCA) throws Exception {
        KeyPair keyPair = generateKeyPair();
        return selfSignedCertificateX509v3(keyPair, subjectDN, isCA);
    }

    /**
     * Returns a new self-signed X.509v3 certificate using the specified key pair and subject DN. The certificate will be valid for
     * {@link #DEFAULT_CERT_VALIDITY_YEARS} years.
     * 
     * @param keyPair
     * @param subjectDN
     * @param isCA
     *            If <code>true</code>, the certificate is for a self-signed certificate authority.
     * 
     * @throws OperatorCreationException
     * @throws CertificateException
     * @throws IOException
     */
    public static X509Certificate selfSignedCertificateX509v3(KeyPair keyPair, String subjectDN, boolean isCA)
            throws OperatorCreationException, CertificateException, IOException {
        return selfSignedCertificateX509v3(keyPair, subjectDN, DEFAULT_CERT_VALIDITY_YEARS, isCA);
    }

    /**
     * Returns a new self-signed X.509v3 certificate using the specified key pair.
     * 
     * @param keyPair
     * @param subjectDN
     * @param validityYears
     *            The number of years for which the certificate is valid.
     * @param isCA
     *            If <code>true</code>, the certificate is for a self-signed certificate authority.
     * 
     * @throws OperatorCreationException
     * @throws CertificateException
     * @throws IOException
     */
    public static X509Certificate selfSignedCertificateX509v3(KeyPair keyPair, String subjectDN, int validityYears, boolean isCA)
            throws OperatorCreationException, CertificateException, IOException {
        KeyUsage usage = new KeyUsage(
                KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.cRLSign);
        return selfSignedCertificateX509v3(keyPair, subjectDN, validityYears, usage, isCA);
    }

    /**
     * 
     * Returns a new self-signed X.509v3 certificate using the specified key pair.
     * 
     * @param keyPair
     * @param subjectDN
     * @param validityYears
     * @param usage
     *            The kind of usage that is to be allowed for the certificate key.
     * @param isCA
     *            If <code>true</code>, the certificate is for a self-signed certificate authority.
     * 
     * @throws CertIOException
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    public static X509Certificate selfSignedCertificateX509v3(KeyPair keyPair, String subjectDN, int validityYears, KeyUsage usage,
            boolean isCA) throws CertIOException, OperatorCreationException, CertificateException {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        // Using the current timestamp as the certificate serial number
        BigInteger certSerialNumber = new BigInteger(Long.toString(now));

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, validityYears);

        Date endDate = calendar.getTime();

        X500Name dnName = new X500Name(subjectDN);
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName,
                subjectPublicKeyInfo);
        certificateBuilder.addExtension(Extension.keyUsage, false, usage).addExtension(Extension.basicConstraints, isCA,
                new BasicConstraints(isCA));

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);
        certificateBuilder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

        // Use appropriate signature algorithm based on your keyPair algorithm.
        String signatureAlgorithm = "SHA256WithRSA";
        Provider bcProvider = new BouncyCastleProvider();
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(bcProvider).build(keyPair.getPrivate());
        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
        X509Certificate selfSignedCert = new JcaX509CertificateConverter().getCertificate(certificateHolder);

        return selfSignedCert;
    }

    /**
     * Returns a new self-signed X.509v3 certificate using the specified information after saving the certificate and key pair to a PKCS#12
     * format key store file with the specified file name. The certificate will expire 5 years from now.
     * 
     * @param generatedKeyPair
     *            The certificate's key pair.
     * @param subjectDN
     *            The subject of the certificate.
     * @param filename
     *            The path to the file that will contain the data.
     * @param alias
     *            The alias of the entry in the key store.
     * @param password
     *            The password to set on the generated file.
     * @param isCA
     *            If <code>true</code>, the certificate is for a self-signed certificate authority.
     * 
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws OperatorCreationException
     */
    public static X509Certificate selfSignedCertificateX509v3ToPKCS12(KeyPair generatedKeyPair, String subjectDN, String filename,
            String alias, char[] password, boolean isCA) throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, OperatorCreationException {
        return selfSignedCertificateX509v3ToPKCS12(generatedKeyPair, subjectDN, filename, alias, password, DEFAULT_CERT_VALIDITY_YEARS,
                isCA);
    }

    /**
     * Returns a new self-signed X.509v3 certificate using the specified information after saving the certificate and key pair to a PKCS#12
     * format key store file with the specified file name. The certificate will expire the specified number of years from now.
     * 
     * @param generatedKeyPair
     *            The certificate's key pair.
     * @param subjectDN
     *            The subject of the certificate.
     * @param filename
     *            The path to the file that will contain the data.
     * @param alias
     *            TODO
     * @param password
     *            The password to set on the generated file.
     * @param validityYears
     *            The lifetime of the certificate before it expires.
     * @param isCA
     *            If <code>true</code>, the certificate is for a self-signed certificate authority.
     * 
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws OperatorCreationException
     */
    public static X509Certificate selfSignedCertificateX509v3ToPKCS12(KeyPair generatedKeyPair, String subjectDN, String filename,
            String alias, char[] password, int validityYears, boolean isCA) throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, OperatorCreationException {

        X509Certificate selfSignedCertificate = selfSignedCertificateX509v3(generatedKeyPair, subjectDN, validityYears, isCA);
        saveToPKCS12(selfSignedCertificate, generatedKeyPair, filename, alias, password);

        return selfSignedCertificate;
    }

    /**
     * Returns a new PKCS#10 certificate signing request (CSR).
     * 
     * @param requestSubject
     *            The principal subject for the signing request.
     * @param requestKeyPair
     *            The key pair for the request.
     * 
     * @throws IOException
     * @throws OperatorCreationException
     */
    public static PKCS10CertificationRequest createCSR(X500Name requestSubject, KeyPair requestKeyPair)
            throws IOException, OperatorCreationException {
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        // create the signer using the private key of the certificate being used to sign.
        AsymmetricKeyParameter keyParam = PrivateKeyFactory.createKey(requestKeyPair.getPrivate().getEncoded());
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(requestKeyPair.getPublic().getEncoded());
        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(keyParam);

        PKCS10CertificationRequestBuilder reqBuilder = new PKCS10CertificationRequestBuilder(requestSubject, keyInfo);
        PKCS10CertificationRequest req = reqBuilder.build(signer);
        return req;
    }

    /**
     * Reads the PKCS#10 CSR from the specified reader containing the PEM-encoded CSR data.
     * 
     * @param pemcsr
     *            A reader containing PEM-encoded CSR.
     * 
     * @throws IOException
     */
    public static PKCS10CertificationRequest readCSR(Reader pemcsr) throws IOException {
        PKCS10CertificationRequest csr;
        try (PemReader reader = new PemReader(pemcsr)) {
            csr = new PKCS10CertificationRequest(reader.readPemObject().getContent());
        }
        return csr;
    }

    /**
     * Given a key store containing a certificate authority (CA) private key and certificate and a Reader containing a PEM-encoded
     * Certificate Signing Request (CSR), sign the CSR with that private key and return the signed certificate as a PEM-encoded PKCS#7
     * signedData object. The returned value can be written to a file and imported into a Java <code>KeyStore</code> with "keytool -import
     * -trustcacerts -alias subjectalias -file file.pem"
     *
     * @param pemcsr
     *            A Reader from which will be read a PEM-encoded CSR file (begins with "-----BEGIN NEW CERTIFICATE REQUEST-----").
     * @param validity
     *            The number of days for which the certificate will be valid.
     * @param caKeystore
     *            The key store containing the CA signing key.
     * @param caAlias
     *            The alias of the CA signing key in the key store.
     * @param caPassword
     *            The password of the CA signing key in the key store.
     *
     * @return a String containing the PEM-encoded signed Certificate (begins "-----BEGIN PKCS #7 SIGNED DATA-----")
     */
    public static String signCSR(Reader pemcsr, int validity, KeyStore caKeystore, String caAlias, char[] caPassword) throws Exception {
        PrivateKey cakey = (PrivateKey) caKeystore.getKey(caAlias, caPassword);
        X509Certificate cacert = (X509Certificate) caKeystore.getCertificate(caAlias);
        PKCS10CertificationRequest csr = readCSR(pemcsr);

        return signCSR(csr, validity, cacert, cakey);
    }

    /**
     * Signs the specified certification signing request using the specified certificate authority certificate and private key.
     * 
     * @param csr
     *            The certification signing request.
     * @param validity
     *            The number of days for which the certificate will be valid.
     * @param cacert
     *            The certificate of the certifying authority.
     * @param cakey
     *            The private key of the certifying authority's certificate.
     * 
     * @return a String containing the PEM-encoded signed Certificate (begins "-----BEGIN PKCS #7 SIGNED DATA-----")
     * 
     * @throws CertIOException
     * @throws IOException
     * @throws OperatorCreationException
     * @throws CertificateEncodingException
     * @throws CMSException
     * @throws UnsupportedEncodingException
     */
    public static String signCSR(PKCS10CertificationRequest csr, int validity, X509Certificate cacert, PrivateKey cakey)
            throws CertIOException, IOException, OperatorCreationException, CertificateEncodingException, CMSException,
            UnsupportedEncodingException {
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        X500Name issuer = new X500Name(cacert.getSubjectX500Principal().getName());
        BigInteger serial = new BigInteger(32, new SecureRandom());
        Date from = new Date();
        Date to = new Date(System.currentTimeMillis() + (validity * NumberConstants.DAY_MS));

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, serial, from, to, csr.getSubject(),
                csr.getSubjectPublicKeyInfo())
                        .addExtension(Extension.basicConstraints, false, new BasicConstraints(false))
                        .addExtension(Extension.subjectKeyIdentifier, false,
                                new SubjectKeyIdentifier(csr.getSubjectPublicKeyInfo().getEncoded()))
                        .addExtension(Extension.authorityKeyIdentifier, false,
                                new AuthorityKeyIdentifier(
                                        new GeneralNames(
                                                new GeneralName(X500Name.getInstance(cacert.getSubjectX500Principal().getEncoded()))),
                                        cacert.getSerialNumber()))
                        .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(cakey.getEncoded()));
        X509CertificateHolder holder = certBuilder.build(signer);
        byte[] certencoded = holder.toASN1Structure().getEncoded();

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        signer = new JcaContentSignerBuilder("SHA256withRSA").build(cakey);
        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, cacert));
        generator.addCertificate(new X509CertificateHolder(certencoded));
        generator.addCertificate(new X509CertificateHolder(cacert.getEncoded()));
        CMSTypedData content = new CMSProcessableByteArray(certencoded);
        CMSSignedData signeddata = generator.generate(content, true);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write("-----BEGIN PKCS7-----\n".getBytes("ISO-8859-1"));
        out.write(Base64.getEncoder().encode(signeddata.getEncoded()));
        out.write("\n-----END PKCS7-----\n".getBytes("ISO-8859-1"));
        out.close();
        return new String(out.toByteArray(), "ISO-8859-1");
    }

    /**
     * Convert the specified public key into a PEM-format string.
     * 
     * @param pk
     *            The public key.
     * 
     * @throws IOException
     */
    public static String toPEM(PublicKey pk) throws IOException {
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
        pemWriter.writeObject(pk);
        pemWriter.close();
        return stringWriter.toString();
    }

    /**
     * Convert the specified private key into a PEM-format string.
     * 
     * @param pk
     *            The private key.
     * 
     * @throws IOException
     */
    public static String toPEM(PrivateKey pk) throws IOException {
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
        pemWriter.writeObject(pk);
        pemWriter.close();
        return stringWriter.toString();
    }

    /**
     * Convert the specified certificate into a PEM-format string.
     * 
     * @param certificate
     *            The signed certificate.
     * 
     * @throws IOException
     */
    public static String toPEM(X509Certificate certificate) throws IOException {
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        return stringWriter.toString();
    }

    /**
     * Convert the specified certificate into a PEM-format string.
     * 
     * @param csr
     *            The certificate signing request.
     * 
     * @throws IOException
     */
    public static String toPEM(PKCS10CertificationRequest csr) throws IOException {
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
        pemWriter.writeObject(csr);
        pemWriter.close();
        return stringWriter.toString();
    }

    public static PublicKey readPublicKey(File pemKeyFile, String password) throws IOException {
        // reads your key file
        try (PEMParser pemParser = new PEMParser(new FileReader(pemKeyFile))) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            KeyPair kp;
            if (object instanceof PEMEncryptedKeyPair) {
                // Encrypted key - we will use provided password
                PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;
                // uses the password to decrypt the key
                PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
                kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
            } else {
                // Unencrypted key - no password needed
                PEMKeyPair ukp = (PEMKeyPair) object;
                kp = converter.getKeyPair(ukp);
            }

            return kp.getPublic();
        }
    }

    public static PrivateKey readPrivateKey(File pemKeyFile, String password) throws IOException {
        // reads your key file
        try (PEMParser pemParser = new PEMParser(new FileReader(pemKeyFile))) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            KeyPair kp;
            if (object instanceof PEMEncryptedKeyPair) {
                // Encrypted key - we will use provided password
                PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;
                // uses the password to decrypt the key
                PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
                kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
            } else {
                // Unencrypted key - no password needed
                PEMKeyPair ukp = (PEMKeyPair) object;
                kp = converter.getKeyPair(ukp);
            }

            return kp.getPrivate();
        }
    }

    public static KeyPair loadFromPKCS12(String filename, char[] password) throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, IOException, UnrecoverableEntryException {
        KeyStore pkcs12KeyStore = KeyStore.getInstance("PKCS12");

        try (FileInputStream fis = new FileInputStream(filename);) {
            pkcs12KeyStore.load(fis, password);
        }

        KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(password);
        Entry entry = pkcs12KeyStore.getEntry("owlstead", param);
        if (!(entry instanceof PrivateKeyEntry)) {
            throw new KeyStoreException("That's not a private key!");
        }
        PrivateKeyEntry privKeyEntry = (PrivateKeyEntry) entry;
        PublicKey publicKey = privKeyEntry.getCertificate().getPublicKey();
        PrivateKey privateKey = privKeyEntry.getPrivateKey();
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Saves the specified certificate and key pair to the file with the specified name in PKCS#12 format. The specified password will be
     * used to protect the key store.
     * 
     * @param selfSignedCertificate
     * @param generatedKeyPair
     * @param filename
     * @param alias
     *            The alias to use in the key store for the private key.
     * @param password
     *            The password with which to protect the key store.
     * 
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     */
    public static void saveToPKCS12(Certificate selfSignedCertificate, KeyPair generatedKeyPair, String filename, String alias,
            char[] password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, FileNotFoundException {
        KeyStore pkcs12KeyStore = KeyStore.getInstance("PKCS12");
        pkcs12KeyStore.load(null, null);
        KeyStore.Entry entry = new PrivateKeyEntry(generatedKeyPair.getPrivate(), new Certificate[] { selfSignedCertificate });
        KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(password);
        pkcs12KeyStore.setEntry(alias, entry, param);

        try (FileOutputStream fos = new FileOutputStream(filename)) {
            pkcs12KeyStore.store(fos, password);
        }
    }

    /**
     * Save the specified certificate in a Java Key Store (JKS) file.
     * 
     * @param selfSignedCertificate
     *            The certificate to save.
     * @param generatedKeyPair
     *            The certificate's key pair.
     * @param filename
     *            The name of the file.
     * @param alias
     *            The alias for the certificate entry.
     * @param password
     *            The password for the JKS file.
     * 
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     */
    public static void saveToJKS(Certificate selfSignedCertificate, KeyPair generatedKeyPair, String filename, String alias,
            char[] password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, FileNotFoundException {
        KeyStore jksKeyStore = KeyStore.getInstance("JKS");
        jksKeyStore.load(null, null);
        KeyStore.Entry entry = new PrivateKeyEntry(generatedKeyPair.getPrivate(), new Certificate[] { selfSignedCertificate });
        KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(password);
        jksKeyStore.setEntry(alias, entry, param);

        try (FileOutputStream fos = new FileOutputStream(filename)) {
            jksKeyStore.store(fos, password);
        }
    }

    /**
     * Save the specified certificate as a trusted certificate in a Java Key Store (JKS) file.
     * 
     * @param selfSignedCertificate
     *            The certificate to save.
     * @param generatedKeyPair
     *            The certificate's key pair.
     * @param filename
     *            The name of the file.
     * @param alias
     *            The alias for the certificate entry.
     * @param password
     *            The password for the JKS file.
     * 
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     */
    public static void saveToJKSTrustedCert(Certificate selfSignedCertificate, KeyPair generatedKeyPair, String filename, String alias,
            char[] password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, FileNotFoundException {
        KeyStore jksKeyStore = KeyStore.getInstance("JKS");
        jksKeyStore.load(null, null);
        // this causes it to be a trusted certificate.
        jksKeyStore.setCertificateEntry(alias, selfSignedCertificate);

        try (FileOutputStream fos = new FileOutputStream(filename)) {
            jksKeyStore.store(fos, password);
        }
    }

    /**
     * Returns a RDN for the specified component display name and value.
     * 
     * @param displayName
     *            The component's display name.
     * @param rdnValue
     *            The component's value.
     */
    public static RDN getRDN(String displayName, String rdnValue) {
        ASN1ObjectIdentifier attrType = OidDisplayNameMapping.getOidForDisplayName(displayName);
        ASN1Encodable attrValue = KseX500NameStyle.INSTANCE.stringToValue(attrType, rdnValue);
        AttributeTypeAndValue typeAndValue = new AttributeTypeAndValue(attrType, attrValue);
        RDN newRDN = new RDN(typeAndValue);
        return newRDN;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Generating test self-signed key pair...");
        KeyPair generatedKeyPair = generateKeyPair(4096, DEFAULT_KEY_ALGORITHM);

        System.out.println("Generating test self-signed certificate from key pair...");
        String filename = "test_gen_self_signed.pkcs12";
        char[] password = "test".toCharArray();
        boolean isCA = false;
        X509Certificate certificate = selfSignedCertificateX509v3ToPKCS12(generatedKeyPair, "CN=owlstead", filename, "owlstead", password,
                5, isCA);

        System.out.println("Validating certificate...");
        KeyPair retrievedKeyPair = loadFromPKCS12(filename, password);
        // you can validate by generating a signature and verifying it or by
        // comparing the moduli by first casting to RSAPublicKey, e.g.:
        RSAPublicKey pubKey = (RSAPublicKey) generatedKeyPair.getPublic();
        RSAPrivateKey privKey = (RSAPrivateKey) retrievedKeyPair.getPrivate();
        System.out.println(pubKey.getModulus().equals(privKey.getModulus()));

        System.out.println("*** Certificate private key");
        System.out.println(toPEM(generatedKeyPair.getPrivate()));
        System.out.println("*** Certificate public key");
        System.out.println(toPEM(generatedKeyPair.getPublic()));
        System.out.println("*** Certificate");
        System.out.println(toPEM(certificate));

        System.out.println("Creating certificate signing request for new certificate...");
        KeyPair newKeyPair = generateKeyPair();
        PKCS10CertificationRequest csr = createCSR(X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded()), newKeyPair);
        System.out.println("*** CSR");
        String csrPEM = toPEM(csr);
        File csrFile = new File("test_csr.pem");
        FileUtils.write(csrFile, csrPEM, "UTF-8");
        System.out.println(csrPEM);
        System.out.println("Signing new certificate with first certificate...");
        String newCertPEM = signCSR(csr, 1, certificate, privKey);
        System.out.println("*** Signed CSR");
        System.out.println(newCertPEM);
        File newCertFile = new File("test_newcert.pem");
        FileUtils.write(newCertFile, newCertPEM, "UTF-8");

        System.out.println("Saving new Trusted Certificate into a JKS...");
        isCA = true;
        generatedKeyPair = generateKeyPair(4096, DEFAULT_KEY_ALGORITHM);
        certificate = selfSignedCertificateX509v3ToPKCS12(generatedKeyPair, "CN=valencia", filename, "valencia", password, 5, isCA);
        saveToJKSTrustedCert(certificate, generatedKeyPair, "test_trusted_cert.jks", "valencia", password);
    }
}
