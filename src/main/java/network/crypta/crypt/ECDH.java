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

/**
 * Performs Elliptic Curve Diffie-Hellman key agreement for a single key pair.
 *
 * <p>This class owns a fixed {@link java.security.KeyPair} generated for a selected {@link Curves}
 * entry and exposes helpers to serialize the public key and derive a raw shared secret for a peer.
 * Callers typically construct an instance per session or connection, exchange public keys, and then
 * invoke {@link #getAgreedSecret(ECPublicKey)} once to derive bytes that are fed into a separate
 * KDF. The implementation relies on provider selection performed by {@link Curves}, which performs
 * self-tests and may fall back to BouncyCastle when the default providers are incompatible.
 *
 * <p>Instances are effectively immutable after construction: the key pair and curve metadata do not
 * change. The only mutable state is a cached provider-specific generator inside {@link Curves}
 * which is synchronized there. Use one {@code ECDH} instance per participant and avoid reusing a
 * shared secret across multiple contexts.
 *
 * <ul>
 *   <li>Generates and holds a curve-specific key pair.
 *   <li>Provides public key bytes in standard X.509 form.
 *   <li>Derives a raw ECDH secret for a peer public key.
 * </ul>
 *
 * @see Curves
 * @see #getAgreedSecret(ECPublicKey)
 */
public class ECDH {
  private static final Logger LOG = LoggerFactory.getLogger(ECDH.class);

  /**
   * Selected curve parameters for this instance and its underlying key material.
   *
   * <p>This value is set at construction time and never changes. It determines the EC parameters,
   * expected encoded key sizes, and which providers were selected after the curve self-tests.
   */
  public final Curves curve;

  private final KeyPair key;

  /**
   * Supported named curves with provider-specific initialization and size metadata.
   *
   * <p>Each constant corresponds to an NIST prime curve and records the expected encoded public key
   * length along with the derived shared secret length. The constructor eagerly initializes
   * KeyPairGenerator, KeyFactory, and KeyAgreement providers, running a self-test to ensure the
   * default provider behaves correctly. When that self-test fails, the code falls back to
   * BouncyCastle and logs which provider is selected.
   *
   * <p>The enum also exposes a cached {@link KeyPairGenerator}. Access is synchronized to avoid
   * repeated initialization, so caller code can safely request new key pairs without redoing the
   * provider setup.
   *
   * <ul>
   *   <li>Encapsulates curve names and EC parameter specs.
   *   <li>Tracks expected modulus and shared secret lengths.
   *   <li>Performs provider self-tests and fallback handling.
   * </ul>
   */
  @SuppressWarnings("ImmutableEnumChecker")
  public enum Curves {
    // rfc5903 or rfc6460: it's NIST's random/prime curves: suite B
    // Order matters. Append to the list, do not re-order.
    /**
     * NIST P-256 curve with a 91-byte X.509 encoding and 32-byte shared secret.
     *
     * <p>Use this curve for the smallest key size in this enum while still providing widely
     * supported ECDH interoperability. The size values are used for validation and network-format
     * comparisons; callers should still apply a KDF before use.
     */
    P256("secp256r1", 91, 32),
    /**
     * NIST P-384 curve with a 120-byte X.509 encoding and 48-byte shared secret.
     *
     * <p>This curve offers a higher security margin than P-256 at the cost of larger keys and more
     * CPU time during agreement. The sizes reflect the encoded public key and raw secret length
     * used by the implementation.
     */
    P384("secp384r1", 120, 48),
    /**
     * NIST P-521 curve with a 158-byte X.509 encoding and 66-byte shared secret.
     *
     * <p>Select this curve when the highest strength is required and larger payloads are
     * acceptable. The encoded public key size is checked by {@link #getPublicKeyNetworkFormat()} to
     * detect unexpected output lengths.
     */
    P521("secp521r1", 158, 66);

    /**
     * EC parameter spec derived from the curve name for provider initialization.
     *
     * <p>This spec is used to initialize {@link KeyPairGenerator} and other EC primitives. It is
     * immutable and shared by all calls for the curve, so callers can treat it as a stable,
     * read-only description of the EC domain parameters.
     */
    public final ECGenParameterSpec spec;

    private KeyPairGenerator keygenCached;
    private final Provider kgProvider;
    private final Provider kfProvider;
    private final Provider kaProvider;

    /**
     * Expected size of the encoded public key in bytes for this curve.
     *
     * <p>The value is used to validate the X.509 encoding returned from provider APIs. The encoded
     * length can vary between providers, so this value is checked to detect out-of-range output and
     * to guide logging when smaller encodings appear.
     */
    public final int modulusSize;

    /**
     * Expected size of the raw derived secret in bytes for this curve.
     *
     * <p>This value is used by callers to validate ECDH output length expectations. The secret is
     * raw ECDH output and must be processed by a KDF before use as a symmetric key.
     */
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
      // Ensure the providers class is initialized; also log which provider instance is visible.
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

    /**
     * Generates a new EC key pair using the cached provider for this curve.
     *
     * <p>The first call lazily initializes the {@link KeyPairGenerator} with the stored curve spec;
     * later calls reuse the cached instance. If provider initialization failed during enum
     * construction, this call may throw a runtime exception when the generator is missing. The
     * returned key pair is independent of any other instance and is safe to retain for the lifetime
     * of a session.
     *
     * @return a newly generated {@link KeyPair} for the selected curve and provider.
     */
    public synchronized KeyPair generateKeyPair() {
      return getKeyPairGenerator().generateKeyPair();
    }

    @Override
    public String toString() {
      return spec.getName();
    }
  }

  /**
   * Initializes a new ECDH instance with a freshly generated key pair for the given curve.
   *
   * <p>Construction triggers key pair generation, which can draw entropy from the configured
   * provider and may block depending on the system entropy source. The resulting key pair is stored
   * for the life of this instance and used for all later ECDH operations. Callers typically create
   * one instance per peer exchange and discard it after the session key material has been derived.
   *
   * @param curve the curve parameters and provider selection to use for key generation; must not be
   *     {@code null} and should match peers that will exchange public keys.
   */
  public ECDH(Curves curve) {
    this.curve = curve;
    this.key = curve.generateKeyPair();
  }

  /**
   * Computes the raw ECDH shared secret for the given peer public key.
   *
   * <p>The agreement step allocates a new {@link KeyAgreement} instance each call, initializes it
   * with this instance's private key, and completes the ECDH phase using the provided public key.
   * The returned bytes are the raw ECDH output and must be passed through a KDF before use as a
   * symmetric key. This method is CPU intensive and will return {@code null} if the input is {@code
   * null} or if the provider rejects the key.
   *
   * @param pubkey the peer public key to combine with this instance's private key; must be an EC
   *     key on the same curve, or {@code null} to indicate no agreement is possible.
   * @return the raw ECDH shared secret bytes, or {@code null} when input is {@code null} or
   *     agreement fails due to provider errors.
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

  /**
   * Returns the public key associated with this instance's key pair.
   *
   * <p>The returned key is the EC public component generated at construction time. Callers can use
   * it for key exchange or serialize it via {@link #getPublicKeyNetworkFormat()} or {@link
   * #getPublicKey(byte[], Curves)}. The key object is owned by this instance but is safe to share
   * as it is immutable.
   *
   * @return the EC public key for this instance.
   */
  public ECPublicKey getPublicKey() {
    return (ECPublicKey) key.getPublic();
  }

  /**
   * Reconstructs an EC public key from X.509-encoded bytes.
   *
   * <p>This helper uses the curve's selected {@link KeyFactory} provider to decode the key bytes
   * that were previously produced by {@link ECPublicKey#getEncoded()}. If decoding fails, the
   * method logs the error and returns {@code null}. The curve parameter guides which provider is
   * used; callers should ensure the bytes correspond to the same curve or agreement will fail.
   *
   * @param data the X.509-encoded EC public key bytes; must not be {@code null} and should be in
   *     the provider's expected format.
   * @param curve the curve metadata and provider selection to use for decoding; must match the
   *     curve used to create the encoded key.
   * @return the decoded {@link ECPublicKey}, or {@code null} when decoding fails.
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
   * Pre-initializes key pair generators to allow the entropy collection at startup.
   *
   * <p>Initializing EC key generators may create the JVM-wide {@code SecureRandom}, which can block
   * while gathering entropy from {@code /dev/random} on Unix-like systems. Call this during a
   * controlled startup stage where blocking is acceptable so the rest of the application does not
   * appear hung. The method still leaves generators lazily initialized inside {@link Curves}, but
   * it eagerly warms the most commonly used curve to make later ECDH operations fast and
   * non-blocking.
   */
  public static void blockingInit() {
    Curves.P256.getKeyPairGenerator();
    // Not used at present. BouncyCastle uses a single PRNG. If these use separate PRNGs,
    // we need to init them explicitly.
  }

  /**
   * Returns the public key as an encoded byte array suitable for network transport.
   *
   * <p>The bytes are the X.509 encoding produced by the current provider. When the encoding is
   * longer than the expected {@link Curves#modulusSize}, this method throws an exception because
   * the output is not safe to send. When the encoding is shorter than expected, the method logs a
   * warning but intentionally returns the unpadded bytes to preserve current behavior. Callers
   * should treat the returned array as immutable.
   *
   * @return the encoded public key bytes in X.509 form, with length checks applied.
   * @throws IllegalStateException when the provider returns a public key encoding longer than the
   *     expected size for the curve.
   */
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
