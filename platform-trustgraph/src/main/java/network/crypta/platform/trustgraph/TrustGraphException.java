package network.crypta.platform.trustgraph;

/**
 * Stable exception for trust graph parsing, validation, and store failures.
 *
 * <p>Messages are suitable for API error responses because they describe the violated bound or
 * field name only. They never include raw trust documents, signatures, request bodies, tokens,
 * local paths, or private identity material.
 *
 * <p>The Platform API layer maps this exception to a client error. Model code should therefore use
 * stable, specific error codes and bounded messages whenever input validation fails.
 */
public final class TrustGraphException extends RuntimeException {
  /** Machine-readable error code used by Platform API validation responses. */
  private final String errorCode;

  /**
   * Creates a trust graph exception with a stable error code.
   *
   * @param errorCode machine-readable error code suitable for API responses
   * @param message bounded human-readable message that does not echo sensitive input
   */
  public TrustGraphException(String errorCode, String message) {
    super(message);
    this.errorCode = java.util.Objects.requireNonNull(errorCode, "errorCode");
  }

  /**
   * Returns the machine-readable error code.
   *
   * @return stable error code supplied by the model or parser
   */
  public String errorCode() {
    return errorCode;
  }
}
