package network.crypta.crypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ECDH {
  private static final Logger LOG = LoggerFactory.getLogger(ECDH.class);

  public final Curves curve;
  private final KeyPair key;

  public enum Curves {
    // rfc5903 or rfc6460: it's NIST's random/prime curves : suite B
    // Order matters. Append to the list, do not re-order.
    P256("secp256r1", 91, 32),
    P384("secp384r1", 120, 48),
    P521("secp521r1", 158, 66);

    public final ECGenParameterSpec spec;
    private KeyPairGenerator keygenCached;
    private final Provider kgProvider;
    private final Provider kfProvider;
    private final Provider kaProvider;

    /** Expected size of a pubkey */
    public final int modulusSize;

    /** Expected size of the derived secret (in bytes) */
    public final int derivedSecretSize;

    /** Verify KeyPairGenerator and KeyFactory work correctly */
    private static KeyPair selftest(KeyPairGenerator kg, KeyFactory kf, int modulusSize)
        throws InvalidKeySpecException {
      KeyPair key = kg.generateKeyPair();
      PublicKey pub = key.getPublic();
      PrivateKey pk = key.getPrivate();
      byte[] pubkey = pub.getEncoded();
      byte[] pkey = pk.getEncoded();
      if (pubkey.length > modulusSize || pubkey.length == 0)
        throw new IllegalStateException(
            "Unexpected pubkey length: " + pubkey.length + "!=" + modulusSize);
      PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(pubkey));
      if (!Arrays.equals(pub2.getEncoded(), pubkey))
        throw new InvalidKeySpecException("Pubkey encoding mismatch");
      kf.generatePrivate(new PKCS8EncodedKeySpec(pkey));
      // Private key encoding check intentionally omitted.
      return key;
    }

    private static void selftestGenSecret(KeyPair key, KeyAgreement ka) throws InvalidKeyException {
      ka.init(key.getPrivate());
      ka.doPhase(key.getPublic(), true);
      ka.generateSecret();
    }

    Curves(String name, int modulusSize, int derivedSecretSize) {
      this.spec = new ECGenParameterSpec(name);
      KeyAgreement ka = null;
      KeyFactory kf = null;
      KeyPairGenerator kg = null;
      // Ensure providers class is initialized; also log which provider instance is visible.
      LOG.trace("BouncyCastle provider: {}", JceLoader.BouncyCastle);
      try {
        KeyPair key;
        KgKfResult kgkf = initKgKfAndSelftest(this.spec, modulusSize);
        kg = kgkf.kg;
        kf = kgkf.kf;
        key = kgkf.key;

        KaResult kaResult = initKeyAgreementAndSelftest(key);
        ka = kaResult.ka();

        if (kaResult.fellBackToBouncyCastle()) {
          KgKfPair pair = initBcKgKf(this.spec, this.spec.getName());
          kg = pair.kg();
          kf = pair.kf();
        }
      } catch (NoSuchAlgorithmException e) {
        LOG.error("Key agreement initialization failed: NoSuchAlgorithmException", e);
      } catch (InvalidKeySpecException e) {
        LOG.error("Key agreement initialization failed: InvalidKeySpecException", e);
      } catch (InvalidKeyException e) {
        LOG.error("Key agreement initialization failed: InvalidKeyException", e);
      } catch (InvalidAlgorithmParameterException e) {
        LOG.error("Key agreement initialization failed: InvalidAlgorithmParameterException", e);
      }
      this.modulusSize = modulusSize;
      this.derivedSecretSize = derivedSecretSize;

      this.kgProvider = (kg != null) ? kg.getProvider() : null;
      this.kfProvider = (kf != null) ? kf.getProvider() : null;
      this.kaProvider = (ka != null) ? ka.getProvider() : null;
      LOG.info("{}: using {} for KeyPairGenerator(EC)", name, kgProvider);
      LOG.info("{}: using {} for KeyFactory(EC)", name, kfProvider);
      LOG.info("{}: using {} for KeyAgreement(ECDH)", name, kaProvider);
    }

    private record KgKfResult(KeyPairGenerator kg, KeyFactory kf, KeyPair key) {}

    private record KgKfPair(KeyPairGenerator kg, KeyFactory kf) {}

    private record KaResult(KeyAgreement ka, boolean fellBackToBouncyCastle) {}

    private static KgKfResult initKgKfAndSelftest(ECGenParameterSpec spec, int modulusSize)
        throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeySpecException {
      KeyPairGenerator kg = null;
      KeyFactory kf;
      KeyPair key;
      try {
        kg = KeyPairGenerator.getInstance("EC");
        kf = KeyFactory.getInstance("EC");
        kg.initialize(spec);
        key = selftest(kg, kf, modulusSize);
      } catch (Exception e) {
        LOG.warn(
            "default KeyPairGenerator provider ({}) is broken, falling back to BouncyCastle",
            (kg != null ? kg.getProvider() : null),
            e);
        kg = KeyPairGenerator.getInstance("EC", JceLoader.BouncyCastle);
        kf = KeyFactory.getInstance("EC", JceLoader.BouncyCastle);
        kg.initialize(spec);
        key = selftest(kg, kf, modulusSize);
      }
      return new KgKfResult(kg, kf, key);
    }

    private static KgKfPair initBcKgKf(ECGenParameterSpec spec, String curveName) {
      try {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("EC", JceLoader.BouncyCastle);
        KeyFactory kf = KeyFactory.getInstance("EC", JceLoader.BouncyCastle);
        kg.initialize(spec);
        LOG.info(
            "{}: provider fallback active — using BouncyCastle for KeyPairGenerator/KeyFactory",
            curveName);
        return new KgKfPair(kg, kf);
      } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
        LOG.error(
            "Failed to initialize EC KeyPairGenerator/KeyFactory with BouncyCastle after"
                + " KeyAgreement fallback",
            ex);
        return new KgKfPair(null, null);
      }
    }

    private static KaResult initKeyAgreementAndSelftest(KeyPair key)
        throws NoSuchAlgorithmException, InvalidKeyException {
      KeyAgreement ka = null;
      boolean fellBack = false;
      try {
        ka = KeyAgreement.getInstance("ECDH");
        selftestGenSecret(key, ka);
      } catch (Exception e) {
        LOG.warn(
            "default KeyAgreement provider ({}) is broken or incompatible with KeyPairGenerator,"
                + " falling back to BouncyCastle",
            (ka != null ? ka.getProvider() : null),
            e);
        ka = KeyAgreement.getInstance("ECDH", JceLoader.BouncyCastle);
        selftestGenSecret(key, ka);
        fellBack = true;
      }
      return new KaResult(ka, fellBack);
    }

    private synchronized KeyPairGenerator getKeyPairGenerator() {
      if (keygenCached != null) return keygenCached;
      KeyPairGenerator kg = null;
      try {
        kg = KeyPairGenerator.getInstance("EC", kgProvider);
        kg.initialize(spec);
      } catch (NoSuchAlgorithmException e) {
        LOG.error("Error getting EC KeyPairGenerator", e);
      } catch (InvalidAlgorithmParameterException e) {
        LOG.error("Invalid algorithm parameters for EC KeyPairGenerator", e);
      }
      keygenCached = kg;
      return kg;
    }

    public synchronized KeyPair generateKeyPair() {
      return getKeyPairGenerator().generateKeyPair();
    }

    @Override
    public String toString() {
      return spec.getName();
    }
  }

  /**
   * Initialize the ECDH Exchange: this will draw some entropy
   *
   * @param curve
   */
  public ECDH(Curves curve) {
    this.curve = curve;
    this.key = curve.generateKeyPair();
  }

  /**
   * Completes the ECDH exchange: this is CPU intensive.
   *
   * @param pubkey the peer public key; when {@code null}, this method returns {@code null}
   * @return the raw ECDH shared secret or {@code null} on failure (including {@code null} input).
   *     The returned value must be fed into a KDF before use.
   */
  @SuppressWarnings("java:S1168")
  public byte[] getAgreedSecret(ECPublicKey pubkey) {
    try {
      if (pubkey == null) {
        LOG.warn("getAgreedSecret called with null public key");
        return null;
      }
      KeyAgreement ka;
      ka = KeyAgreement.getInstance("ECDH", curve.kaProvider);
      ka.init(key.getPrivate());
      ka.doPhase(pubkey, true);

      return ka.generateSecret();
    } catch (InvalidKeyException e) {
      LOG.error("Invalid ECDH key", e);
    } catch (NoSuchAlgorithmException e) {
      LOG.error("ECDH algorithm not available", e);
    }
    return null;
  }

  public ECPublicKey getPublicKey() {
    return (ECPublicKey) key.getPublic();
  }

  /**
   * Returns an ECPublicKey from bytes obtained using ECPublicKey.getEncoded()
   *
   * @param data
   * @return ECPublicKey or null if it fails
   */
  public static ECPublicKey getPublicKey(byte[] data, Curves curve) {
    ECPublicKey remotePublicKey = null;
    try {
      X509EncodedKeySpec ks = new X509EncodedKeySpec(data);
      KeyFactory kf = KeyFactory.getInstance("EC", curve.kfProvider);
      remotePublicKey = (ECPublicKey) kf.generatePublic(ks);

    } catch (NoSuchAlgorithmException e) {
      LOG.error("EC KeyFactory unavailable", e);
    } catch (InvalidKeySpecException e) {
      LOG.error("Invalid EC public key spec", e);
    }

    return remotePublicKey;
  }

  /**
   * Initialize the key pair generators, which in turn will create the global SecureRandom, which
   * may block waiting for entropy from /dev/random on unix-like systems. So this should be called
   * on startup during the "may block for entropy" stage. Note that because this can block, we still
   * have to do lazy initialisation: We do NOT want to have it blocking *at time of loading the
   * classes*, as this will likely appear as the node completely failing to load. Running this after
   * fproxy has started, with a warning timer, allows us to tell the user what is going on if it
   * takes a while.
   */
  public static void blockingInit() {
    Curves.P256.getKeyPairGenerator();
    // Not used at present. BouncyCastle uses a single PRNG. If these use separate PRNGs,
    // we need to init them explicitly.
  }

  /** Return the public key as a byte[] in network format */
  public byte[] getPublicKeyNetworkFormat() {
    byte[] ret = getPublicKey().getEncoded();
    if (ret.length == curve.modulusSize) {
      return ret;
    } else if (ret.length > curve.modulusSize) {
      throw new IllegalStateException(
          "Encoded public key too long: should be "
              + curve.modulusSize
              + " bytes but is "
              + ret.length);
    } else {
      LOG.warn("Padding public key from {} to {} bytes", ret.length, curve.modulusSize);
      // Current behavior intentionally returns the original, unpadded bytes.
      return ret;
    }
  }
}
