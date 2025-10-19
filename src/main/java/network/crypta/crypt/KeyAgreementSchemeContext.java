package network.crypta.crypt;

/**
 * Context for key-agreement schemes used during peer handshakes.
 *
 * <p>This abstraction holds per-context metadata such as creation time and the last-use timestamp
 * and, for negotiation types {@code >= 9}, the ECDSA signature over the public key material.
 * Implementations provide the public key in the network wire format via {@link
 * #getPublicKeyNetworkFormat()}.
 *
 * <p>Threading: instances are not inherently thread-safe. The {@link #lastUsedTime()} accessor is
 * synchronized for safe concurrent reads. Implementations are responsible for updating {@code
 * lastUsedTime} consistently whenever the context is used.
 */
public abstract class KeyAgreementSchemeContext {

  /**
   * Time at which this context was last used, in milliseconds since the epoch.
   *
   * <p>Subclasses should update this when operations that consume the context occur. Use {@link
   * #lastUsedTime()} for a synchronized read.
   */
  protected long lastUsedTime;

  /** Cached ECDSA signature for negotiation types {@code >= 9}. May be {@code null}. */
  private byte[] ecdsaSig;

  /**
   * Creation time in milliseconds since the epoch.
   *
   * <p>The value is set during construction and never changes.
   */
  public final long lifetime = System.currentTimeMillis();

  /**
   * Returns the time, in milliseconds since the epoch, at which this context was last used.
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
   * @param sig signature bytes, or {@code null} to clear
   */
  public void setECDSASignature(byte[] sig) {
    // Defensive copy to preserve encapsulation
    this.ecdsaSig = (sig == null) ? null : sig.clone();
  }

  /**
   * Returns a copy of the ECDSA signature associated with this context.
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
   * the active negotiation type.
   *
   * @return public key bytes suitable for transmission
   */
  public abstract byte[] getPublicKeyNetworkFormat();
}
