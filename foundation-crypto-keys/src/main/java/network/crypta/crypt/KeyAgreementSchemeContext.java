package network.crypta.crypt;

/**
 * Context for key-agreement schemes used during peer handshakes.
 *
 * <p>This abstraction holds per-context metadata such as the creation timestamp and the last-use
 * time and, for negotiation types {@code >= 9}, a cached ECDSA signature over the public-key
 * material. Concrete implementations encapsulate the algorithm-specific details and expose the
 * public key in the protocol's wire format via {@link #getPublicKeyNetworkFormat()}.
 *
 * <p>Threading: instances are not inherently thread-safe. Only {@link #lastUsedTime()} is
 * synchronized to provide a consistent read across threads. Subclasses and callers must ensure any
 * updates to {@code lastUsedTime} and other state happen with appropriate synchronization.
 *
 * @see ECDHLightContext
 */
public abstract class KeyAgreementSchemeContext {

  /**
   * Time at which this context was last used, in milliseconds since the Unix epoch (UTC).
   *
   * <p>Subclasses should update this when operations that consume the context occur. Use {@link
   * #lastUsedTime()} for a synchronized read.
   */
  protected long lastUsedTime;

  /**
   * Cached ECDSA signature for negotiation types {@code >= 9}. May be {@code null}.
   *
   * <p>The byte content and verification rules are defined by the active negotiation type; this
   * class stores the raw bytes without interpretation.
   */
  private byte[] ecdsaSig;

  /**
   * Creation timestamp, in milliseconds since the Unix epoch (UTC).
   *
   * <p>The value is captured during construction and never changes. Despite the name, it records
   * the creation time rather than a duration.
   */
  public final long lifetime = System.currentTimeMillis();

  /**
   * Returns the time, in milliseconds since the Unix epoch (UTC), at which this context was last
   * used.
   *
   * <p>Threading: this method is synchronized to provide a consistent read across threads.
   *
   * @return last-use time in milliseconds since the epoch
   */
  public synchronized long lastUsedTime() {
    return lastUsedTime;
  }

  /**
   * Sets the ECDSA signature associated with this context.
   *
   * <p>The provided array is defensively copied. Passing {@code null} clears the stored value.
   *
   * <p>Validation: this method does not verify the signature; callers are responsible for
   * constructing and validating the appropriate format for the active negotiation type.
   *
   * @param sig signature bytes, or {@code null} to clear
   */
  public void setECDSASignature(byte[] sig) {
    // Defensive copy to preserve encapsulation.
    this.ecdsaSig = (sig == null) ? null : sig.clone();
  }

  /**
   * Returns a copy of the ECDSA signature associated with this context.
   *
   * <p>The returned array is a defensive copy; modifying it does not affect internal state.
   *
   * @return a copy of the signature, or {@code null} if unset
   */
  public byte[] getECDSASignature() {
    return (ecdsaSig == null) ? null : ecdsaSig.clone();
  }

  /**
   * Returns the public key encoded in the network wire format expected by the handshake protocol.
   *
   * <p>The exact encoding (curve, length, byte order) is defined by concrete implementations and
   * the active negotiation type. Callers should treat the returned bytes as immutable and copy them
   * if they need to retain the value.
   *
   * @return public-key bytes suitable for transmission
   */
  public abstract byte[] getPublicKeyNetworkFormat();
}
