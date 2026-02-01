package network.crypta.node;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.crypt.BlockCipher;
import org.jetbrains.annotations.NotNull;

/**
 * Groups the ciphers and key bytes used by a {@link SessionKey}.
 *
 * <p>This value object represents the negotiated packet-encryption material for a peer session. It
 * is typically assembled during handshake processing and then passed as a single unit when a {@code
 * SessionKey} is created. The instance is a simple carrier: it performs no validation and does not
 * derive new keys, so callers are responsible for ensuring the material is consistent and ready for
 * use. Array components are stored by reference rather than copied. This keeps construction
 * lightweight, but it means callers must treat the arrays as mutable, shared state. Mutating the
 * arrays after construction affects any consumer that reads them.
 *
 * <p>Instances are immutable with respect to their component references and are safe to share
 * across threads when the underlying arrays are not modified. To avoid leaking secrets, do not log
 * the contained key material.
 *
 * <ul>
 *   <li>Captures the outgoing, incoming, and IV ciphers needed by packet processing.
 *   <li>Holds raw key bytes and nonces without defensive copying.
 *   <li>Bundles the material for reuse across constructors and tests.
 * </ul>
 *
 * @see SessionKey
 */
public final class SessionKeyCryptoMaterial {
  private final BlockCipher outgoingCipher;
  private final byte[] outgoingKey;
  private final BlockCipher incommingCipher;
  private final byte[] incommingKey;
  private final BlockCipher ivCipher;
  private final byte[] ivNonce;
  private final byte[] hmacKey;

  /**
   * Creates a session key material bundle.
   *
   * @param outgoingCipher cipher used to encrypt outgoing packets; may be {@code null} in tests.
   * @param outgoingKey raw key bytes for {@code outgoingCipher}; stored by reference and mutable.
   * @param incommingCipher cipher used to decrypt incoming packets; may be {@code null} in tests.
   * @param incommingKey raw key bytes for {@code incommingCipher}; stored by reference and mutable.
   * @param ivCipher cipher used to derive per-packet IV material; may be {@code null} in tests.
   * @param ivNonce base nonce bytes paired with {@code ivCipher}; stored by reference and mutable.
   * @param hmacKey key bytes for message authentication; stored by reference and mutable.
   */
  public SessionKeyCryptoMaterial(
      BlockCipher outgoingCipher,
      byte[] outgoingKey,
      BlockCipher incommingCipher,
      byte[] incommingKey,
      BlockCipher ivCipher,
      byte[] ivNonce,
      byte[] hmacKey) {
    this.outgoingCipher = outgoingCipher;
    this.outgoingKey = outgoingKey;
    this.incommingCipher = incommingCipher;
    this.incommingKey = incommingKey;
    this.ivCipher = ivCipher;
    this.ivNonce = ivNonce;
    this.hmacKey = hmacKey;
  }

  public BlockCipher outgoingCipher() {
    return outgoingCipher;
  }

  public byte[] outgoingKey() {
    return outgoingKey;
  }

  public BlockCipher incommingCipher() {
    return incommingCipher;
  }

  public byte[] incommingKey() {
    return incommingKey;
  }

  public BlockCipher ivCipher() {
    return ivCipher;
  }

  public byte[] ivNonce() {
    return ivNonce;
  }

  public byte[] hmacKey() {
    return hmacKey;
  }

  /**
   * Determines whether another object represents the same cryptographic material.
   *
   * <p>This comparison checks cipher references using {@link Objects#equals(Object, Object)} and
   * compares each byte array by content. It is intended for diagnostics and test assertions rather
   * than for constant-time security checks. The result is consistent with {@link #hashCode()} as
   * long as the array contents remain unchanged after construction. If any array is mutated, the
   * equality result may change accordingly.
   *
   * @param o object to compare; may be {@code null} or a different type.
   * @return {@code true} when all cipher references and array contents match.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof SessionKeyCryptoMaterial other)) return false;
    return Objects.equals(outgoingCipher, other.outgoingCipher)
        && Arrays.equals(outgoingKey, other.outgoingKey)
        && Objects.equals(incommingCipher, other.incommingCipher)
        && Arrays.equals(incommingKey, other.incommingKey)
        && Objects.equals(ivCipher, other.ivCipher)
        && Arrays.equals(ivNonce, other.ivNonce)
        && Arrays.equals(hmacKey, other.hmacKey);
  }

  /**
   * Computes a hash based on cipher references and the contents of the byte arrays.
   *
   * <p>The hash incorporates the three cipher components and each array's contents. It is stable as
   * long as the underlying arrays are not mutated. If callers change the array contents after
   * construction, the hash code can change, so instances should not be used as keys in hashed
   * collections when mutation is possible.
   *
   * @return hash code derived from cipher references and key material contents.
   */
  @Override
  public int hashCode() {
    int result = Objects.hash(outgoingCipher, incommingCipher, ivCipher);
    result = 31 * result + Arrays.hashCode(outgoingKey);
    result = 31 * result + Arrays.hashCode(incommingKey);
    result = 31 * result + Arrays.hashCode(ivNonce);
    result = 31 * result + Arrays.hashCode(hmacKey);
    return result;
  }

  /**
   * Formats a diagnostic string including cipher references and key material bytes.
   *
   * <p>The output includes {@link Arrays#toString(byte[])} for each array component. This is useful
   * for tests and debugging but may expose sensitive material if logged. Callers should avoid
   * emitting the returned value to persistent logs or telemetry in production environments.
   *
   * @return human-readable representation of the cipher references and key bytes.
   */
  @Override
  public @NotNull String toString() {
    return "SessionKeyCryptoMaterial[outgoingCipher="
        + outgoingCipher
        + ", outgoingKey="
        + Arrays.toString(outgoingKey)
        + ", incommingCipher="
        + incommingCipher
        + ", incommingKey="
        + Arrays.toString(incommingKey)
        + ", ivCipher="
        + ivCipher
        + ", ivNonce="
        + Arrays.toString(ivNonce)
        + ", hmacKey="
        + Arrays.toString(hmacKey)
        + "]";
  }
}
