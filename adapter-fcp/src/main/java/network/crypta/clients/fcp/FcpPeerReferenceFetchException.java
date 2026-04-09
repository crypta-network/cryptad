package network.crypta.clients.fcp;

/**
 * Signals that AddPeer failed to fetch a noderef from a valid Crypta/Freenet URI.
 *
 * <p>This checked exception is owned by {@code :adapter-fcp} so the AddPeer message path can keep
 * its fallback policy in the protocol layer without importing runtime-owned fetch types such as
 * {@code FetchException}. A caller uses this type only to distinguish "the URI parsed correctly,
 * but the fetch failed" from other cases such as malformed URI parsing or ordinary URL I/O
 * failures. That distinction preserves the existing behavior where AddPeer retries the same input
 * as a regular URL after valid-URI fetch failures, while still surfacing post-fetch read failures
 * as plain {@link java.io.IOException}.
 *
 * <p>The exception carries the original cause unchanged, so bridge implementations and tests can
 * still inspect the lower-level failure when needed. It does not add transport-specific state or
 * protocol codes because those remain the responsibility of the message layer.
 */
public final class FcpPeerReferenceFetchException extends Exception {

  /**
   * Creates a new adapter-owned wrapper for a fetch failure on a valid Crypta/Freenet URI.
   *
   * <p>Callers typically provide a short bridge-level message and the original runtime exception as
   * the cause. The constructed exception is then propagated back to the AddPeer message handler,
   * which decides whether to fall back to ordinary URL loading or translate the failure into a
   * protocol error.
   *
   * @param message human-readable summary of the fetch failure context
   * @param cause original runtime exception that caused the fetch to fail
   */
  public FcpPeerReferenceFetchException(String message, Throwable cause) {
    super(message, cause);
  }
}
