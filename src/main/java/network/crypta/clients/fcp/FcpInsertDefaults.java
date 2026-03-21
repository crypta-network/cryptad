package network.crypta.clients.fcp;

/**
 * Holds FCP-local default values for insert-related message parsing.
 *
 * <p>This helper keeps ordinary {@code clients.fcp} message classes from depending directly on
 * daemon-owned types when they only need stable protocol defaults. The values defined here are
 * intentionally duplicated from the daemon layer and verified by parity tests, so cleanup work can
 * reduce compile-time coupling without altering runtime behavior. Callers treat this class as a
 * read-only constants holder during request parsing, serialization, and validation.
 *
 * <p>The type is package-private because the constants are an internal detail of the FCP message
 * package rather than a general daemon API. It has no mutable state, performs no I/O, and is safe
 * for concurrent access from parser and handler threads.
 */
final class FcpInsertDefaults {
  /**
   * Default value used when an FCP insert request omits the {@code ForkOnCacheable} field.
   *
   * <p>A value of {@code true} preserves the daemon's current behavior for cacheable inserts while
   * allowing message classes such as {@code ClientPutMessage} and {@code ClientPutDirMessage} to
   * avoid a direct dependency on daemon-owned constants.
   */
  static final boolean FORK_ON_CACHEABLE_DEFAULT = true;

  /** Prevents instantiation of this constants-only helper type. */
  private FcpInsertDefaults() {}
}
