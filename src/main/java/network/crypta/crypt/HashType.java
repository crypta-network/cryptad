package network.crypta.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import org.bitpedia.util.TigerTree;

/**
 * Supported content-hash algorithms used across Crypta.
 *
 * <p>Each constant defines:
 *
 * <ul>
 *   <li>a bitmask for aggregating multiple algorithms,
 *   <li>an optional JCA algorithm name ({@link #javaName}) used with {@link MessageDigest}, and
 *   <li>the digest length in bytes ({@link #hashLength}).
 * </ul>
 *
 * <p>Algorithms without a JCA name (ED2K and TTH) use custom implementations ({@link
 * Ed2MessageDigest} and {@link TigerTree}). For JCA-backed algorithms, a preferred {@link Provider}
 * is selected at startup via {@link Util#mdProviders}.
 */
public enum HashType {
  // Keep constants synchronized with Util.mdProviders keys.
  SHA1(1, "SHA1", 20),
  MD5(2, "MD5", 16),
  SHA256(4, "SHA-256", 32),
  SHA384(8, "SHA-384", 48),
  SHA512(16, "SHA-512", 64),
  ED2K(32, null, 16),
  TTH(64, null, 24);

  /** Bitmask for aggregation. */
  public final int bitmask;

  /**
   * JCA algorithm name for {@link MessageDigest}; may contain dashes (for example, {@code
   * "SHA-256"}). {@code null} when a custom implementation is used (ED2K and TTH).
   */
  public final String javaName;

  /** Digest length in bytes for this algorithm. */
  public final int hashLength;

  // Preferred provider for JCA-backed algorithms; null for ED2K/TTH.
  private final Provider provider;

  /**
   * Constructs a hash type definition.
   *
   * @param bitmask aggregation mask used by callers to request multiple hashes
   * @param name JCA name for {@link MessageDigest#getInstance(String)}, or {@code null}
   * @param hashLength digest length, in bytes
   */
  HashType(int bitmask, String name, int hashLength) {
    this.bitmask = bitmask;
    this.javaName = name;
    this.hashLength = hashLength;
    this.provider = javaName != null ? Util.mdProviders.get(javaName) : null;
  }

  /**
   * Returns a {@link MessageDigest}-compatible instance for this algorithm.
   *
   * <p>For ED2K and TTH, this method returns custom implementations ({@link Ed2MessageDigest} and
   * {@link TigerTree}). For other algorithms, a new JCA {@link MessageDigest} is created using the
   * preferred {@link Provider}.
   *
   * <p>The returned instance is stateful and not thread-safe; use one per thread/task.
   *
   * @return a new digest instance for this hash type
   * @throws IllegalStateException if the configured algorithm/provider is unavailable
   */
  public final MessageDigest get() {
    if (this == ED2K) {
      return new Ed2MessageDigest();
    }
    if (this == TTH) {
      return new TigerTreeMessageDigest(new TigerTree());
    }
    try {
      return MessageDigest.getInstance(javaName, provider);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Unsupported digest algorithm " + javaName, e);
    }
  }

  /** MessageDigest adapter that delegates to the streaming TigerTree implementation. */
  private static final class TigerTreeMessageDigest extends MessageDigest {
    private final TigerTree delegate;

    TigerTreeMessageDigest(TigerTree delegate) {
      super("tigertree");
      this.delegate = delegate;
    }

    @Override
    protected int engineGetDigestLength() {
      return delegate.getDigestLength();
    }

    @Override
    protected void engineUpdate(byte input) {
      delegate.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
      delegate.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
      return delegate.digest();
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len)
        throws java.security.DigestException {
      return delegate.digest(buf, offset, len);
    }

    @Override
    protected void engineReset() {
      delegate.reset();
    }
  }
}
