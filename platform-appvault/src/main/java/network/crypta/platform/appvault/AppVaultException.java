package network.crypta.platform.appvault;

import java.util.Objects;

/**
 * Stable failure raised by the app-vault service.
 *
 * <p>The vault core is transport-neutral, but callers still need a small stable error vocabulary so
 * HTTP adapters and tests can distinguish malformed requests, denied grants, missing records, and
 * local storage failures without leaking secret values or filesystem paths.
 *
 * <p>The status code is HTTP-shaped because the primary caller is the Platform API router. The
 * exception itself does not depend on HTTP and can also be used by app lifecycle hooks, release
 * certification fixtures, and unit tests. Messages must remain redacted: attach low-level causes
 * for debugging, but do not place raw secret material, private keys, tokens, or absolute vault
 * paths in the public message.
 */
public final class AppVaultException extends RuntimeException {
  /** HTTP-style status code selected by the vault layer for API mapping. */
  private final int statusCode;

  /** Stable redacted machine-readable code selected by the vault layer. */
  private final String errorCode;

  /**
   * Creates a vault failure with an HTTP-style status and stable machine code.
   *
   * <p>Use this constructor when there is no underlying implementation exception, for example for
   * validation errors, authorization denials, unsupported identity kinds, and missing records.
   *
   * @param statusCode HTTP-style status selected by the caller
   * @param errorCode stable machine-readable error code for API responses and tests
   * @param message redacted human-readable message safe for JSON responses
   */
  public AppVaultException(int statusCode, String errorCode, String message) {
    super(Objects.requireNonNull(message, "message"));
    this.statusCode = statusCode;
    this.errorCode = requireErrorCode(errorCode);
  }

  /**
   * Creates a vault failure with an underlying cause.
   *
   * <p>Use this constructor when preserving the implementation cause helps local diagnostics. The
   * public message and code should still describe the stable vault failure rather than exposing
   * filenames, key bytes, ciphertext, or request secrets.
   *
   * @param statusCode HTTP-style status selected by the caller
   * @param errorCode stable machine-readable error code for API responses and tests
   * @param message redacted human-readable message safe for JSON responses
   * @param cause underlying implementation failure retained for local debugging
   */
  public AppVaultException(int statusCode, String errorCode, String message, Throwable cause) {
    super(Objects.requireNonNull(message, "message"), cause);
    this.statusCode = statusCode;
    this.errorCode = requireErrorCode(errorCode);
  }

  /**
   * Returns the HTTP-style status that API adapters should use for this failure.
   *
   * <p>The value is selected by the vault layer at the point where the failure is classified. It
   * allows callers to map vault failures without parsing error-code strings.
   *
   * @return status code selected by the vault service
   */
  public int statusCode() {
    return statusCode;
  }

  /**
   * Returns the stable machine-readable error code.
   *
   * <p>Error codes are intended for tests, API clients, and lifecycle hooks. They are stable enough
   * to branch on, but they deliberately avoid embedding secret names, raw values, token text, or
   * filesystem paths.
   *
   * @return redacted machine-readable error code
   */
  public String errorCode() {
    return errorCode;
  }

  private static String requireErrorCode(String value) {
    String text = Objects.requireNonNull(value, "errorCode").trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException("errorCode must not be blank");
    }
    return text;
  }
}
