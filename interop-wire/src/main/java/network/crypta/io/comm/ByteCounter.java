package network.crypta.io.comm;

/**
 * Reports byte counts for network I/O.
 *
 * <p>This minimal callback interface is used by messaging and transfer layers to report the
 * quantity of data that has been sent or received. Counts are expressed in bytes. Implementations
 * typically update statistics, throttling, or diagnostic views; the specific side effects are
 * implementation-defined.
 *
 * <p>Threading: Callers may invoke these methods from arbitrary threads (for example, I/O or worker
 * threads). Implementations should document their own thread-safety guarantees if they are shared
 * across threads.
 */
public interface ByteCounter {

  /**
   * Records raw bytes transmitted on the wire.
   *
   * <p>The count includes all protocol overhead (headers, framing, etc.) and may also include bytes
   * that a higher-level throttle has already accounted for.
   *
   * @param x number of bytes sent (bytes)
   */
  void sentBytes(int x);

  /**
   * Records raw bytes received from the wire.
   *
   * <p>The count includes all protocol overhead (headers, framing, etc.).
   *
   * @param x number of bytes received (bytes)
   */
  void receivedBytes(int x);

  /**
   * Records application payload bytes transmitted.
   *
   * <p>Only report the size of user-visible data and exclude protocol overhead. For the same
   * transfer the caller is expected to also report the raw size via {@link #sentBytes(int)}; do not
   * sum the totals from {@code sentBytes(...)} and {@code sentPayload(...)} externally, as they
   * represent overlapping measurements and will double-count.
   *
   * @param x number of payload bytes sent (bytes)
   */
  void sentPayload(int x);
}
