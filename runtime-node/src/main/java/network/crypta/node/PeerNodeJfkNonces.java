package network.crypta.node;

import java.security.MessageDigest;
import java.util.ArrayDeque;
import network.crypta.crypt.SHA256;

/**
 * Tracks a bounded, in-memory set of initiator nonces for JFK handshake validation.
 *
 * <p>This helper stores the raw nonce values that the initiator generated and later needs to
 * verify. During the handshake, the initiator transmits {@code SHA256(nonce)} and expects the
 * responder to echo it; when the echo arrives, the original nonce must be found by its hash so the
 * handshake can continue. The class therefore keeps recently used nonces and exposes lookup by
 * hash.
 *
 * <p>Typical usage is to remember each locally generated nonce before it is sent on the wire, then
 * call {@link #findOriginalNonceByHash(byte[])} when the responder echoes the hash. The list is
 * bounded by a caller-supplied maximum; older nonces are evicted in insertion order to cap memory
 * usage. All operations synchronize on the internal list, so lookups and mutations are safe when
 * accessed by multiple threads, but the returned nonce array remains mutable and owned by the
 * caller.
 *
 * <p><b>Notable behaviors</b>
 *
 * <ul>
 *   <li>Evicts the oldest nonce when the maximum count is exceeded.
 *   <li>Returns {@code null} when no matching hash exists.
 *   <li>Stores and returns the original byte array reference without copying.
 * </ul>
 */
final class PeerNodeJfkNonces {
  /** Holds remembered nonce values in insertion order for bounded replay checks. */
  private final ArrayDeque<byte[]> nonces = new ArrayDeque<>();

  /**
   * Creates an empty nonce tracker with no retained values.
   *
   * <p>The instance starts with an empty list and becomes populated only through calls to {@link
   * #rememberNonce(byte[], int)}.
   */
  PeerNodeJfkNonces() {}

  /**
   * Remembers nonce for later lookup by its hash, enforcing a maximum retained count.
   *
   * <p>This method appends the provided nonce to the end of the internal list and trims the oldest
   * entry if the list grows beyond {@code maxNonces}. The operation is synchronized, so callers may
   * invoke it concurrently with lookup and clear operations. Reference stores the nonce, so callers
   * should not modify the array after storing it if they expect hash lookups to remain valid.
   *
   * <pre>{@code
   * byte[] nonce = new byte[] {1, 2, 3};
   * nonces.rememberNonce(nonce, 64);
   * }</pre>
   *
   * @param nonce the raw nonce bytes to retain; expected to be non-null and stable after storing
   * @param maxNonces the maximum number of nonces to keep; values {@code <= 0} evict immediately
   */
  void rememberNonce(byte[] nonce, int maxNonces) {
    synchronized (nonces) {
      nonces.add(nonce);
      if (nonces.size() > maxNonces) nonces.removeFirst();
    }
  }

  /**
   * Finds the original nonce whose SHA-256 hash matches the provided hash value.
   *
   * <p>The method iterates the retained nonces in insertion order, computes {@code SHA256(nonce)}
   * for each entry, and returns the first byte array whose hash equals {@code nonceHash}. If no
   * entry matches, the method returns {@code null}. The returned array is the original stored
   * reference and therefore mutable; callers should treat it as read-only and must not assume any
   * defensive copying.
   *
   * <pre>{@code
   * byte[] nonceHash = SHA256.digest(nonce);
   * byte[] original = nonces.findOriginalNonceByHash(nonceHash);
   * }</pre>
   *
   * @param nonceHash the SHA-256 digest to match against stored nonces; non-null input required
   * @return the original nonce array that matches the hash, or {@code null} if none matches
   */
  @SuppressWarnings("java:S1168")
  byte[] findOriginalNonceByHash(byte[] nonceHash) {
    synchronized (nonces) {
      for (byte[] nonce : nonces) {
        if (MessageDigest.isEqual(nonceHash, SHA256.digest(nonce))) return nonce;
      }
    }
    return null;
  }

  /**
   * Removes all remembered nonces so later lookups return {@code null}.
   *
   * <p>This method is synchronized and can be called at any time to reset the retained nonce
   * window, such as after a handshake failure or when shutting down. Clearing is idempotent and
   * does not affect the byte arrays themselves beyond removing their references from the list.
   */
  void clear() {
    synchronized (nonces) {
      nonces.clear();
    }
  }
}
