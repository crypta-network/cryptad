package network.crypta.crypt;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.node.NodeStarter;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.StringCallback;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utilities for initializing and using SSL/TLS for the embedded HTTP server.
 *
 * <p>This class wires SSL/TLS from configuration: it loads a PKCS#12 keystore from the configured
 * path, generates and stores a self-signed ECDSA certificate when the keystore does not exist, and
 * creates an {@link javax.net.ssl.SSLContext} to back {@link ServerSocket} creation.
 *
 * <p>All methods are static and mutate shared state. Call {@link #init(SubConfig)} once during
 * single-threaded startup before invoking {@link #available()}, {@link #getHSTSHeader()}, or {@link
 * #createServerSocket()}.
 */
public class SSL {
  private static final Logger LOG = LoggerFactory.getLogger(SSL.class);

  private static final String KEY_ALGORITHM = "EC";
  private static final int KEY_SIZE = 256;
  private static final String SIG_ALGORITHM = "SHA256WithECDSA";

  // 10 years, expressed in seconds (avoid int overflow during multiplication)
  private static final long CERTIFICATE_LIFETIME = 10L * 365 * 24 * 60 * 60; // 10 years
  private static final String CERTIFICATE_CN = "Crypta";
  private static final String CERTIFICATE_OU = "Crypta";

  private static final String CHAIN_ALIAS = "freenet";
  private static final String DEFAULT_SECRET = "freenet";

  private SSL() {
    throw new IllegalStateException("Utility class");
  }

  private static volatile boolean enable;
  private static KeyStore keystore;
  private static ServerSocketFactory ssf;
  private static String keyStorePath;
  private static String keyStorePass;
  private static String keyPass;
  private static int hstsMaxAge;

  /**
   * Returns whether SSL/TLS support is initialized.
   *
   * @return {@code true} if a {@link ServerSocketFactory} backed by an initialized SSL context is
   *     available; {@code false} otherwise.
   */
  public static boolean available() {
    return (ssf != null);
  }

  /**
   * Returns the value for the {@code Strict-Transport-Security} header.
   *
   * <p>When SSL is enabled, initialized, and a positive max-age is configured, this returns {@code
   * "max-age=<seconds>"}. Otherwise an empty string is returned to indicate that the header should
   * not be sent.
   *
   * @return the header value without the name (e.g., {@code "max-age=31536000"}), or an empty
   *     string when HSTS is disabled or SSL is not available.
   */
  public static String getHSTSHeader() {
    if (enable && available() && hstsMaxAge > 0) return "max-age=" + hstsMaxAge;
    else return "";
  }

  /**
   * Initializes SSL/TLS support from configuration.
   *
   * <p>This registers callbacks for SSL-related settings, loads the PKCS#12 keystore from the
   * configured path, and attempts to create an {@link SSLContext}. If the keystore file is absent,
   * a new self-signed ECDSA certificate is generated and stored using the configured passwords. Any
   * failure during initialization is logged and leaves SSL disabled.
   *
   * <p>Recognized settings (keys are registered on {@code sslConfig}): - {@code sslEnable}
   * (boolean): master switch; default {@code false}. - {@code sslKeyStore} (string): keystore path;
   * default {@code "datastore/certs"}. - {@code sslKeyStorePass} (string): keystore password. -
   * {@code sslKeyPass} (string): private key password. - {@code sslHSTS} (int): HSTS max-age in
   * seconds; {@code 0} disables.
   *
   * @param sslConfig configuration section used to register and read SSL settings.
   */
  public static void init(SubConfig sslConfig) {
    int configItemOrder = 0;

    // Register SSL-related configuration keys and their callbacks.
    sslConfig.register(
        "sslEnable",
        false,
        configItemOrder++,
        true,
        true,
        "SSL.enable",
        "SSL.enable",
        enableCallback());

    sslConfig.register(
        "sslKeyStore",
        "datastore/certs",
        configItemOrder++,
        true,
        true,
        "SSL.keyStore",
        "SSL.keyStoreLong",
        keyStorePathCallback());

    sslConfig.register(
        "sslKeyStorePass",
        DEFAULT_SECRET,
        configItemOrder++,
        true,
        true,
        "SSL.keyStorePass",
        "SSL.keyStorePass",
        keyStorePassCallback());

    sslConfig.register(
        "sslKeyPass",
        DEFAULT_SECRET,
        configItemOrder++,
        true,
        true,
        "SSL.keyPass",
        "SSL.keyPass",
        keyPassCallback());

    sslConfig.register(
        "sslHSTS", 0, configItemOrder, true, true, "SSL.HSTS", "SSL.HSTSLong", hstsCallback());

    enable = sslConfig.getBoolean("sslEnable");
    keyStorePath = sslConfig.getString("sslKeyStore");
    keyStorePass = sslConfig.getString("sslKeyStorePass");
    keyPass = sslConfig.getString("sslKeyPass");
    hstsMaxAge = sslConfig.getInt("sslHSTS");

    try {
      keystore = KeyStore.getInstance("PKCS12");
      loadKeyStore();
      createSSLContext();
    } catch (Exception e) {
      LOG.error("Keystore cannot be loaded, SSL will be disabled", e);
    } finally {
      if (enable && !available()) {
        LOG.error("SSL cannot be enabled!");
      } else if (enable) {
        LOG.info("SSL is enabled.");
      }
      sslConfig.finishedInitialization();
    }
  }

  private static BooleanCallback enableCallback() {
    return new BooleanCallback() {

      @Override
      public Boolean get() {
        return enable;
      }

      @Override
      public void set(Boolean newValue) throws InvalidConfigValueException {
        if (!get().equals(newValue)) {
          enable = newValue;
          if (enable)
            try {
              loadKeyStoreAndCreateCertificate();
              createSSLContext();
            } catch (Exception e) {
              enable = false;
              LOG.error("SSL could not be enabled", e);
              throwConfigError("SSL could not be enabled", e);
            }
          else {
            ssf = null;
            try {
              keystore.load(null, keyStorePass.toCharArray());
            } catch (Exception _) {
              // Just clear the key store
            }
          }
        }
      }
    };
  }

  private static StringCallback keyStorePathCallback() {
    return new StringCallback() {

      @Override
      public String get() {
        return keyStorePath;
      }

      @Override
      public void set(String newKeyStore) throws InvalidConfigValueException {
        if (!newKeyStore.equals(get())) {
          String oldKeyStore = keyStorePath;
          keyStorePath = newKeyStore;
          try {
            loadKeyStore();
          } catch (Exception e) {
            keyStorePath = oldKeyStore;
            LOG.error("Keystore file could not be changed", e);
            throwConfigError("Keystore file could not be changed", e);
          }
        }
      }
    };
  }

  private static StringCallback keyStorePassCallback() {
    return new StringCallback() {

      @Override
      public String get() {
        return keyStorePass;
      }

      @Override
      public void set(String newKeyStorePass) throws InvalidConfigValueException {
        if (!newKeyStorePass.equals(get())) {
          String oldKeyStorePass = keyStorePass;
          keyStorePass = newKeyStorePass;
          try {
            storeKeyStore();
          } catch (Exception e) {
            keyStorePass = oldKeyStorePass;
            LOG.error("Keystore password could not be changed", e);
            throwConfigError("Keystore password could not be changed", e);
          }
        }
      }
    };
  }

  private static StringCallback keyPassCallback() {
    return new StringCallback() {

      @Override
      public String get() {
        return keyPass;
      }

      @Override
      public void set(String newKeyPass) throws InvalidConfigValueException {
        if (!newKeyPass.equals(get())) {
          String oldKeyPass = keyPass;
          keyPass = newKeyPass;
          try {
            Certificate[] chain = keystore.getCertificateChain(CHAIN_ALIAS);
            Key privKey = keystore.getKey(CHAIN_ALIAS, oldKeyPass.toCharArray());
            keystore.setKeyEntry(CHAIN_ALIAS, privKey, keyPass.toCharArray(), chain);
            createSSLContext();
          } catch (Exception e) {
            keyPass = oldKeyPass;
            LOG.error("Private key password could not be changed", e);
            throwConfigError("Private key password could not be changed", e);
          }
        }
      }
    };
  }

  private static IntCallback hstsCallback() {
    return new IntCallback() {

      @Override
      public Integer get() {
        return hstsMaxAge;
      }

      @Override
      public void set(Integer newHSTSMaxAge) throws InvalidConfigValueException {
        if (newHSTSMaxAge < 0)
          throwConfigError("HSTS Max age must be not less than 0", new IllegalArgumentException());
        else hstsMaxAge = newHSTSMaxAge;
      }
    };
  }

  /**
   * Creates a new SSL-enabled {@link ServerSocket}.
   *
   * @return a socket created by the current SSL {@link ServerSocketFactory}.
   * @throws IOException if SSL is not initialized or the socket cannot be created.
   */
  public static ServerSocket createServerSocket() throws IOException {
    if (ssf == null) throw new IOException("SSL not initialized");
    return ssf.createServerSocket();
  }

  /**
   * Loads the keystore from disk without creating a certificate when the file is missing.
   *
   * <p>Used during early startup when generating a certificate may not be desirable (e.g., before
   * sufficient entropy is available).
   *
   * @throws NoSuchAlgorithmException if the keystore integrity check algorithm is unavailable.
   * @throws CertificateException if the keystore contains an invalid certificate.
   * @throws IOException if the keystore cannot be read.
   */
  private static void loadKeyStore()
      throws NoSuchAlgorithmException, CertificateException, IOException {
    if (enable) {
      // Keystore and private keys are password-protected; load existing or create an empty store.
      try (FileInputStream fis = new FileInputStream(keyStorePath)) {
        keystore.load(fis, keyStorePass.toCharArray());
      } catch (FileNotFoundException _) {
        // Keystore file is absent: initialize an empty keystore (no certificate yet).
        keystore.load(null, keyStorePass.toCharArray());
      }
    }
  }

  /** Loads the keystore and creates a self-signed certificate when the file is missing. */
  private static void loadKeyStoreAndCreateCertificate()
      throws NoSuchAlgorithmException,
          CertificateException,
          IOException,
          IllegalArgumentException,
          KeyStoreException,
          UnrecoverableKeyException,
          KeyManagementException,
          NoSuchProviderException,
          OperatorCreationException {
    if (enable) {
      // Load existing keystore or generate a fresh one with a self-signed certificate.
      try (FileInputStream fis = new FileInputStream(keyStorePath)) {
        keystore.load(fis, keyStorePass.toCharArray());
      } catch (FileNotFoundException _) {
        createSelfSignedCertificate();
      }
    }
  }

  /** Creates a self-signed certificate and stores it in the current keystore. */
  private static void createSelfSignedCertificate()
      throws NoSuchAlgorithmException,
          CertificateException,
          IOException,
          IllegalArgumentException,
          KeyStoreException,
          UnrecoverableKeyException,
          KeyManagementException,
          NoSuchProviderException,
          OperatorCreationException {
    // Start with an empty keystore and generate a fresh key pair + certificate.
    keystore.load(null, keyStorePass.toCharArray());
    // Based on
    // https://stackoverflow.com/questions/29852290/self-signed-x509-certificate-with-bouncy-castle-in-java

    // Generate a key pair.
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, "BC");
    keyPairGenerator.initialize(KEY_SIZE, NodeStarter.getGlobalSecureRandom());
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    // Build a certificate.
    X500Name issuer = new X500Name("CN=" + CERTIFICATE_CN + ", OU=" + CERTIFICATE_OU);
    BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
    Date notBefore = new Date(System.currentTimeMillis());
    Date notAfter = new Date(System.currentTimeMillis() + CERTIFICATE_LIFETIME * 1000);
    JcaX509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic());
    certBuilder.addExtension(
        Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

    ContentSigner signer = new JcaContentSignerBuilder(SIG_ALGORITHM).build(keyPair.getPrivate());
    X509CertificateHolder certHolder = certBuilder.build(signer);
    X509Certificate cert =
        new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    PrivateKey privKey = keyPair.getPrivate();
    Certificate[] chain = new Certificate[1];
    chain[0] = cert;
    keystore.setKeyEntry(CHAIN_ALIAS, privKey, keyPass.toCharArray(), chain);
    storeKeyStore();
    createSSLContext();
  }

  private static void storeKeyStore()
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
    if (enable) {
      try (FileOutputStream fos = new FileOutputStream(keyStorePath)) {
        keystore.store(fos, keyStorePass.toCharArray());
      }
    }
  }

  private static void createSSLContext()
      throws NoSuchAlgorithmException,
          UnrecoverableKeyException,
          KeyStoreException,
          KeyManagementException {
    if (enable) {
      if (keystore.size() == 0) {
        // No entries present; cannot create an SSL context.
        return;
      }
      // Create key managers sourced from the keystore.
      KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
      // Initialize the KeyManagerFactory with the keystore and key password.
      kmf.init(keystore, keyPass.toCharArray());
      // Create the SSLContext used to produce the ServerSocketFactory.
      SSLContext sslc = SSLContext.getInstance("TLSv1.2");
      // Initialize the SSLContext with our key managers; default trust managers and randomness.
      sslc.init(kmf.getKeyManagers(), null, null);
      ssf = sslc.getServerSocketFactory();
    }
  }

  private static void throwConfigError(String message, Throwable cause)
      throws InvalidConfigValueException {
    String causeMsg = cause.getMessage();
    if (causeMsg == null) {
      causeMsg = cause.toString();
    }
    throw new InvalidConfigValueException("%s: %s".formatted(message, causeMsg));
  }
}
