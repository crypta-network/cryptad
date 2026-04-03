package network.crypta.platform.api;

import java.util.Objects;

/**
 * Internal exception used to map validation and lookup failures onto API error responses.
 *
 * <p>The router catches this exception and serializes it through the standard Platform API error
 * shape, keeping request-parsing helpers and endpoint handlers concise without exposing the
 * exception type as part of the public API surface.
 */
public final class PlatformApiException extends RuntimeException {
  /** HTTP-style status code that the router should expose for this failure. */
  private final int statusCode;

  /** Stable machine-readable error identifier included in the serialized error payload. */
  private final String errorCode;

  /**
   * Creates a structured platform API exception.
   *
   * @param statusCode transport-level status code to emit
   * @param errorCode machine-readable error code
   * @param message human-readable error message
   */
  public PlatformApiException(int statusCode, String errorCode, String message) {
    super(Objects.requireNonNull(message, "message"));
    this.statusCode = statusCode;
    this.errorCode = Objects.requireNonNull(errorCode, "errorCode");
  }

  /**
   * Returns the transport-level status code associated with the failure.
   *
   * @return HTTP-style status code that the router should copy into the response
   */
  public int statusCode() {
    return statusCode;
  }

  /**
   * Returns the machine-readable error code associated with the failure.
   *
   * @return stable error identifier included in the serialized JSON error body
   */
  public String errorCode() {
    return errorCode;
  }

  /**
   * Returns the standard reason phrase corresponding to {@link #statusCode()}.
   *
   * @return short reason phrase used when the router serializes this failure into a response
   */
  @SuppressWarnings("unused")
  public String reasonPhrase() {
    return PlatformApiResponse.reasonPhrase(statusCode);
  }
}
