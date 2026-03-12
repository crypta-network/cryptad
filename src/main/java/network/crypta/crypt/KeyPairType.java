package network.crypta.crypt;

import java.security.spec.ECGenParameterSpec;

/**
 * Supported elliptic-curve key-pair types.
 *
 * <p>This enum binds a Java security algorithm name and a named curve to a ready-to-use {@link
 * ECGenParameterSpec}. It is intended for configuring {@code KeyPairGenerator} instances and for
 * conveying the expected encoded size of public keys for storage or validation.
 *
 * <p>Legacy DSA verification exists in dedicated classes for historical content and is not exposed
 * here.
 *
 * <p>Typical usage:
 *
 * <pre>{@code
 * KeyPairType type = KeyPairType.ECP256;
 * KeyPairGenerator kpg = KeyPairGenerator.getInstance(type.alg);
 * kpg.initialize(type.spec);
 * KeyPair kp = kpg.generateKeyPair();
 * }</pre>
 *
 * <p>Constants:
 *
 * <ul>
 *   <li>{@link #ECP256} — NIST P-256 ({@code secp256r1})
 *   <li>{@link #ECP384} — NIST P-384 ({@code secp384r1})
 *   <li>{@link #ECP521} — NIST P-521 ({@code secp521r1})
 * </ul>
 *
 * <p>Thread safety: enum instances are immutable and safe for concurrent use.
 */
@SuppressWarnings("ImmutableEnumChecker")
public enum KeyPairType {
  ECP256("EC", "secp256r1", 91),
  ECP384("EC", "secp384r1", 120),
  ECP521("EC", "secp521r1", 158);

  /**
   * JCA algorithm name passed to {@code KeyPairGenerator.getInstance}. For these constants it is
   * {@code "EC"}. Never {@code null}.
   */
  public final String alg;

  /**
   * Named curve identifier accepted by {@link ECGenParameterSpec} (for example, {@code
   * "secp256r1"}). Never {@code null}.
   */
  public final String specName;

  /**
   * Expected length, in bytes, of the DER-encoded X.509 SubjectPublicKeyInfo form returned by
   * {@code PublicKey.getEncoded()} for keys of this type. Values are typical for common providers
   * and are used for sizing/validation.
   */
  public final int modulusSize;

  /** Immutable curve parameters derived from {@link #specName}. Never {@code null}. */
  public final ECGenParameterSpec spec;

  /**
   * Initializes the enum constant with the provided algorithm and curve, and derives the {@link
   * ECGenParameterSpec}.
   *
   * @param alg JCA algorithm name used by {@code KeyPairGenerator}; typically {@code "EC"}.
   * @param specName Named curve identifier for {@link ECGenParameterSpec} (for example, {@code
   *     "secp256r1"}).
   * @param modulusSize Expected length of the DER-encoded X.509 public key, in bytes.
   */
  KeyPairType(String alg, String specName, int modulusSize) {
    this.alg = alg;
    this.specName = specName;
    this.modulusSize = modulusSize;
    this.spec = new ECGenParameterSpec(specName);
  }
}
