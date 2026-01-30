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
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import network.crypta.node.FSParseException;
import network.crypta.support.Base64;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ECDSA utilities for generating EC key pairs, signing, and verifying signatures.
 *
 * <p>This class wraps JCA/JCE primitives and selects providers defensively. It attempts to
 * initialize {@link KeyPairGenerator}, {@link KeyFactory}, and {@link Signature} for a given curve,
 * falling back to BouncyCastle when the default providers are unavailable or incompatible.
 * Signatures are produced in DER format and verification tolerates padded input (network format) by
 * decoding the actual DER length.
 *
 * <p>Instances hold a generated key pair unless constructed from a serialized {@link
 * SimpleFieldSet}. All methods are thread-safe unless stated otherwise.
 */
public class ECDSA {
  private static final Logger LOG = LoggerFactory.getLogger(ECDSA.class);

  private static final String MSG_NO_SUCH_ALGO = "NoSuchAlgorithmException : ";
  private static final String LOG_USING = ": using ";

  /** The selected curve for this instance. Never {@code null}. */
  public final Curves curve;

  private final KeyPair key;

  @SuppressWarnings("ImmutableEnumChecker")
  public enum Curves {
    /**
     * Supported NIST prime curves (a.k.a. Suite B). The order is part of the external format;
     * append new values only at the end to preserve ordinal stability.
     */
    P256("secp256r1", "SHA256withECDSA", 91, 72),
    P384("secp384r1", "SHA384withECDSA", 120, 104),
    P521("secp521r1", "SHA512withECDSA", 158, 139);

    public final ECGenParameterSpec spec;
    private final KeyPairGenerator keygen;

    /** The signature algorithm name, including the hash (e.g., {@code SHA256withECDSA}). */
    public final String defaultHashAlgorithm;

    /**
     * Expected size in bytes of the X.509 SubjectPublicKeyInfo encoding for a public key of this
     * curve. Used to sanity-check inputs.
     */
    public final int modulusSize;

    /**
     * Maximum size in bytes for a DER-encoded ECDSA signature used by the wire format after
     * padding. Signers may re-try if a produced signature exceeds this bound.
     */
    public final int maxSigSize;

    private final Provider kfProvider;
    private final Provider sigProvider;

    /**
     * Verifies that {@link KeyPairGenerator} and {@link KeyFactory} can round-trip encode/decode a
     * generated key pair for the given curve.
     *
     * @throws InvalidKeySpecException when a generated key cannot be reconstructed
     */
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
        throw new IllegalStateException("Pubkey encoding mismatch");
      kf.generatePrivate(new PKCS8EncodedKeySpec(pkey));
      return key;
    }

    /**
     * Signs and immediately verifies an empty message to ensure the {@link Signature} instance is
     * usable with the provided key pair.
     */
    private static void selftestSign(KeyPair key, Signature sig)
        throws SignatureException, InvalidKeyException {
      sig.initSign(key.getPrivate());
      byte[] sign = sig.sign();
      sig.initVerify(key.getPublic());
      boolean verified = sig.verify(sign);
      if (!verified) throw new IllegalStateException("Verification failed");
    }

    /** Constructs enum value with curve parameters and performs provider self-tests. */
    Curves(String name, String defaultHashAlgorithm, int modulusSize, int maxSigSize) {
      this.spec = new ECGenParameterSpec(name);
      Signature sig = null;
      KeyFactory kf = null;
      KeyPairGenerator kg = null;
      // Ensure provider class is initialized
      LOG.debug("Provider loaded: {}", JceLoader.BouncyCastle);
      try {
        ProvidersResult pr = initKeyPairAndFactories(this.spec, modulusSize);
        kg = pr.kg;
        kf = pr.kf;
        KeyPair key = pr.key;

        SigResult sr = ensureSignatureCompatible(defaultHashAlgorithm, this.spec, key, kg, kf);
        sig = sr.sig;
        kg = sr.kg;
        kf = sr.kf;
      } catch (NoSuchAlgorithmException e) {
        LOG.error(MSG_NO_SUCH_ALGO + "{}", e.getMessage(), e);
      } catch (InvalidAlgorithmParameterException e) {
        LOG.error("InvalidAlgorithmParameterException : {}", e.getMessage(), e);
      } catch (InvalidKeyException | InvalidKeySpecException | SignatureException e) {
        throw new IllegalStateException(e);
      }
      Provider kgProvider = (kg != null) ? kg.getProvider() : null;
      this.kfProvider = (kf != null) ? kf.getProvider() : null;
      this.sigProvider = (sig != null) ? sig.getProvider() : null;
      this.keygen = kg;
      this.defaultHashAlgorithm = defaultHashAlgorithm;
      this.modulusSize = modulusSize;
      this.maxSigSize = maxSigSize;
      LOG.info("{}" + LOG_USING + "{} for KeyPairGenerator(EC)", name, kgProvider);
      LOG.info("{}" + LOG_USING + "{} for KeyFactory(EC)", name, kfProvider);
      LOG.info("{}" + LOG_USING + "{} for Signature({})", name, sigProvider, defaultHashAlgorithm);
    }

    private record ProvidersResult(KeyPairGenerator kg, KeyFactory kf, KeyPair key) {}

    private static ProvidersResult initKeyPairAndFactories(ECGenParameterSpec spec, int modulusSize)
        throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeySpecException {
      KeyPairGenerator kg = null;
      KeyFactory kf;
      KeyPair key;
      try {
        // check if default EC keys work correctly
        kg = KeyPairGenerator.getInstance("EC");
        kf = KeyFactory.getInstance("EC");
        kg.initialize(spec);
        key = selftest(kg, kf, modulusSize);
      } catch (Exception e) { // fallback to BouncyCastle
        LOG.warn(
            "default KeyPairGenerator provider ({}) is broken, falling back to BouncyCastle",
            kg != null ? kg.getProvider() : null,
            e);
        kg = KeyPairGenerator.getInstance("EC", JceLoader.BouncyCastle);
        kf = KeyFactory.getInstance("EC", JceLoader.BouncyCastle);
        kg.initialize(spec);
        key = selftest(kg, kf, modulusSize);
      }
      return new ProvidersResult(kg, kf, key);
    }

    private record SigResult(Signature sig, KeyPair key, KeyPairGenerator kg, KeyFactory kf) {}

    private static SigResult ensureSignatureCompatible(
        String defaultHashAlgorithm,
        ECGenParameterSpec spec,
        KeyPair key,
        KeyPairGenerator kg,
        KeyFactory kf)
        throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException,
            SignatureException {
      Signature sig = null;
      try {
        // check default Signature compatible with kf/kg
        sig = Signature.getInstance(defaultHashAlgorithm);
        selftestSign(key, sig);
        return new SigResult(sig, key, kg, kf);
      } catch (Exception e) { // fallback to BouncyCastle
        LOG.warn(
            "default Signature provider ({}) is broken or incompatible with KeyPairGenerator,"
                + " falling back to BouncyCastle",
            sig != null ? sig.getProvider() : null,
            e);
        kg = KeyPairGenerator.getInstance("EC", JceLoader.BouncyCastle);
        kf = KeyFactory.getInstance("EC", JceLoader.BouncyCastle);
        kg.initialize(spec);
        key = kg.generateKeyPair();
        sig = Signature.getInstance(defaultHashAlgorithm, JceLoader.BouncyCastle);
        selftestSign(key, sig);
        return new SigResult(sig, key, kg, kf);
      }
    }

    /**
     * Generates a new EC key pair using this curve's configured {@link KeyPairGenerator}.
     *
     * <p>Synchronization ensures the underlying generator is not accessed concurrently.
     */
    @SuppressWarnings("unused")
    public synchronized KeyPair generateKeyPair() {
      return keygen.generateKeyPair();
    }

    /**
     * Builds a {@link SimpleFieldSet} representation containing the base64-encoded public key under
     * this curve's name.
     *
     * @param pub public key to serialize; must be an instance produced for this curve
     * @return field set mapping {@code name() -> { pub = ... }}
     */
    public SimpleFieldSet getSFS(ECPublicKey pub) {
      SimpleFieldSet ecdsaSFS = new SimpleFieldSet(true);
      SimpleFieldSet curveSFS = new SimpleFieldSet(true);
      curveSFS.putSingle("pub", Base64.encode(pub.getEncoded()));
      ecdsaSFS.put(name(), curveSFS);
      return ecdsaSFS;
    }

    /** Returns the JCA curve name (e.g., {@code secp256r1}). */
    @Override
    public String toString() {
      return spec.getName();
    }
  }

  /**
   * Constructs an instance with a freshly generated key pair for the specified curve.
   *
   * @param curve curve used for key generation; must not be {@code null}
   */
  public ECDSA(Curves curve) {
    this.curve = curve;
    this.key = curve.keygen.generateKeyPair();
  }

  /**
   * Constructs an instance from a serialized key in a {@link SimpleFieldSet} produced by {@link
   * #asFieldSet(boolean)}.
   *
   * @param sfs field set containing base64-encoded {@code pub} and (optionally) {@code pri} entries
   *     under {@code curve.name()}
   * @param curve curve corresponding to the serialized key material
   * @throws FSParseException if the key material cannot be decoded or does not match {@code curve}
   */
  public ECDSA(SimpleFieldSet sfs, Curves curve) throws FSParseException {
    byte[] pub;
    byte[] pri;
    try {
      pub = Base64.decode(sfs.get("pub"));
      if (pub.length > curve.modulusSize) throw new InvalidKeyException();
      ECPublicKey pubK = getPublicKey(pub, curve);

      pri = Base64.decode(sfs.get("pri"));
      PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(pri);
      KeyFactory kf = KeyFactory.getInstance("EC", curve.kfProvider);
      ECPrivateKey privK = (ECPrivateKey) kf.generatePrivate(ks);

      this.key = new KeyPair(pubK, privK);
    } catch (Exception e) {
      throw new FSParseException(e);
    }
    this.curve = curve;
  }

  /**
   * Signs the provided content and returns a DER-encoded ECDSA signature.
   *
   * <p>The input is the logical concatenation of all {@code data} chunks. The method retries when a
   * produced signature exceeds {@link Curves#maxSigSize}; otherwise the first successful result is
   * returned. Provider selection prefers deterministic ECDSA where supported.
   *
   * @param data one or more byte-array chunks to sign; must not be {@code null}
   * @return DER-encoded signature, or {@code null} if signing fails
   */
  public byte[] sign(byte[]... data) {
    byte[] result = null;
    try {
      while (true) {
        // Note: BouncyCastle is used here because legacy non-deterministic
        // (SHA256withECDSA) signatures are not compatible with the
        // deterministic SHA256withECDDSA verifier in some providers.
        Signature sig =
            Signature.getInstance(
                curve.defaultHashAlgorithm.replace("ECDSA", "ECDDSA"), JceLoader.BouncyCastle);
        sig.initSign(key.getPrivate());
        for (byte[] d : data) sig.update(d);
        result = sig.sign();
        // Most DER-encoded signatures fit within the configured bound. Retry if they do not.
        if (result.length <= curve.maxSigSize) break;
        else
          LOG.error(
              "DER encoded signature used {} bytes, more than expected {} - re-signing...",
              result.length,
              curve.maxSigSize);
      }
    } catch (NoSuchAlgorithmException e) {
      LOG.error(MSG_NO_SUCH_ALGO + "{}", e.getMessage(), e);
    } catch (InvalidKeyException e) {
      LOG.error("InvalidKeyException : {}", e.getMessage(), e);
    } catch (SignatureException e) {
      LOG.error("SignatureException : {}", e.getMessage(), e);
    }

    return result;
  }

  /**
   * Signs the content and returns a fixed-size signature suitable for the network format.
   *
   * <p>Input data is hashed by the {@link Signature} implementation for the selected curve. The
   * returned array is {@link Curves#maxSigSize} bytes long: the DER signature followed by zero
   * padding when shorter. If a produced signature is longer than the limit, an {@link
   * IllegalStateException} is thrown.
   *
   * @param data one or more byte-array chunks to sign; must not be {@code null}
   * @return zero-padded DER signature of length {@code maxSigSize}
   * @throws IllegalStateException if a signature longer than {@code maxSigSize} is produced
   */
  public byte[] signToNetworkFormat(byte[]... data) {
    byte[] plainsig = sign(data);
    int targetLength = curve.maxSigSize;

    if (plainsig.length != targetLength) {
      byte[] newData = new byte[targetLength];
      if (plainsig.length < targetLength) {
        System.arraycopy(plainsig, 0, newData, 0, plainsig.length);
      } else {
        throw new IllegalStateException("Too long!");
      }
      plainsig = newData;
    }
    return plainsig;
  }

  /**
   * Verifies a signature produced for this instance's public key.
   *
   * @param signature DER-encoded signature; may include trailing zero padding
   * @param data one or more byte-array chunks that were signed
   * @return {@code true} if the signature verifies; {@code false} otherwise
   */
  public boolean verify(byte[] signature, byte[]... data) {
    return verify(curve, getPublicKey(), signature, data);
  }

  /**
   * Verifies a signature with offset and length, tolerating padded network format.
   *
   * @param signature buffer containing the signature
   * @param sigoffset start offset of the signature in {@code signature}
   * @param siglen maximum available bytes (may include padding); the actual DER length is decoded
   * @param data one or more byte-array chunks that were signed
   * @return {@code true} if the signature verifies; {@code false} otherwise
   */
  public boolean verify(byte[] signature, int sigoffset, int siglen, byte[]... data) {
    return verify(curve, getPublicKey(), signature, sigoffset, siglen, data);
  }

  /**
   * Verifies a signature for the given public key.
   *
   * @param curve curve associated with {@code key}
   * @param key public key to verify against
   * @param signature DER-encoded signature (padding tolerated)
   * @param data one or more byte-array chunks that were signed
   * @return {@code true} if the signature verifies; {@code false} otherwise
   */
  public static boolean verify(Curves curve, ECPublicKey key, byte[] signature, byte[]... data) {
    return verify(curve, key, signature, 0, signature.length, data);
  }

  /*
   * Decodes the DER SEQUENCE header at {@code sigOff} and returns the total encoded length of the
   * signature (header + payload). Throws {@link SignatureException} when the header is malformed or
   * claims a length outside the provided bounds. Accepts only definite-length encodings.
   */
  private static int actualSignatureLength(byte[] signature, int sigOff, int sigLen)
      throws SignatureException {
    // SEQUENCE, universal, constructed
    if (sigLen < 2 || signature[sigOff] != 0x30) {
      throw new SignatureException("Not a sequence");
    }
    int length = signature[1 + sigOff] & 0xFF;
    if (length == 0x80) {
      throw new SignatureException("Indefinite length");
    }
    if (length <= 127) {
      return length + 2;
    }
    final int size = length & 0x7F;
    if (size > 4) {
      throw new SignatureException("Header too big");
    }
    if (sigLen < size + 2) {
      throw new SignatureException("Header out of bounds");
    }
    length = 0;
    for (int i = 0; i < size; i++) {
      length <<= 8;
      length += signature[i + sigOff + 2] & 0xFF;
    }
    if (length < 0) {
      throw new SignatureException("Negative sequence length");
    }
    if (length > sigLen - 2 - size) {
      throw new SignatureException("Sequence out of bounds");
    }
    return length + 2 + size;
  }

  /**
   * Verifies a signature with offset and length for the given public key.
   *
   * <p>The method decodes the DER length and ignores any trailing zero padding commonly used by the
   * network format.
   *
   * @param curve curve associated with {@code key}
   * @param key public key to verify against
   * @param signature buffer containing the signature
   * @param sigoffset start offset of the signature in {@code signature}
   * @param siglen maximum available bytes (may include padding)
   * @param data one or more byte-array chunks that were signed
   * @return {@code true} if the signature verifies; {@code false} otherwise
   */
  public static boolean verify(
      Curves curve, ECPublicKey key, byte[] signature, int sigoffset, int siglen, byte[]... data) {
    if (key == null || curve == null || signature == null || data == null) return false;
    boolean result = false;
    try {
      Signature sig = Signature.getInstance(curve.defaultHashAlgorithm, curve.sigProvider);
      sig.initVerify(key);
      for (byte[] d : data) sig.update(d);
      // Strip padding: BC 1.54 cannot deal with it.
      siglen = actualSignatureLength(signature, sigoffset, siglen);
      result = sig.verify(signature, sigoffset, siglen);
    } catch (NoSuchAlgorithmException e) {
      LOG.error(MSG_NO_SUCH_ALGO + "{}", e.getMessage(), e);
    } catch (InvalidKeyException e) {
      LOG.error("InvalidKeyException : {}", e.getMessage(), e);
    } catch (SignatureException e) {
      LOG.error("SignatureException : {}", e.getMessage(), e);
    }
    return result;
  }

  /** Returns this instance's public key. */
  public ECPublicKey getPublicKey() {
    return (ECPublicKey) key.getPublic();
  }

  /**
   * Reconstructs an {@link ECPublicKey} from a SubjectPublicKeyInfo (X.509) encoding.
   *
   * @param data DER-encoded key as returned by {@link ECPublicKey#getEncoded()}
   * @param curve curve associated with the key material
   * @return the decoded public key, or {@code null} on error
   */
  public static ECPublicKey getPublicKey(byte[] data, Curves curve) {
    ECPublicKey remotePublicKey = null;
    try {
      X509EncodedKeySpec ks = new X509EncodedKeySpec(data);
      KeyFactory kf = KeyFactory.getInstance("EC", curve.kfProvider);
      remotePublicKey = (ECPublicKey) kf.generatePublic(ks);

    } catch (NoSuchAlgorithmException e) {
      LOG.error(MSG_NO_SUCH_ALGO + "{}", e.getMessage(), e);
    } catch (InvalidKeySpecException e) {
      LOG.error("InvalidKeySpecException : {}", e.getMessage(), e);
    }

    return remotePublicKey;
  }

  /**
   * Serializes the key material to a {@link SimpleFieldSet}.
   *
   * <p>The returned structure contains a single entry keyed by {@code curve.name()} whose value is
   * a nested field set with {@code pub} (base64 X.509 encoding) and, when requested, {@code pri}
   * (base64 PKCS#8 encoding). Intended for persistence and controlled interchange.
   *
   * @param includePrivate whether to include the private key
   * @return a field set representing the key material
   */
  public SimpleFieldSet asFieldSet(boolean includePrivate) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    SimpleFieldSet fsCurve = new SimpleFieldSet(true);
    fsCurve.putSingle("pub", Base64.encode(key.getPublic().getEncoded()));
    if (includePrivate) fsCurve.putSingle("pri", Base64.encode(key.getPrivate().getEncoded()));
    fs.put(curve.name(), fsCurve);
    return fs;
  }
}
