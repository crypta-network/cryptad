package network.crypta.platform.appcatalog;

import java.util.Objects;

/**
 * Signals signed-catalog, artifact-download, or staged-bundle failures.
 *
 * <p>The exception carries a stable machine-readable error code in addition to the operator-facing
 * message. Platform API handlers use that code to preserve explicit catalog failure contracts
 * without forcing the lower catalog module to depend on the API response model.
 *
 * <p>The catalog package throws this unchecked exception for rejected input and policy failures,
 * including malformed sidecars, untrusted signatures, disallowed artifact URIs, digest mismatches,
 * and unsafe ZIP contents. Callers that expose user-facing APIs should map {@link #errorCode()} to
 * stable response codes and keep the message as a concise diagnostic. Unexpected filesystem
 * failures may still be reported as {@link java.io.IOException} by methods that declare it.
 */
public class AppCatalogException extends RuntimeException {
  /**
   * Stable machine-readable code used by API handlers and tests.
   *
   * <p>Codes are defined by {@link AppCatalogSidecars} and intentionally remain strings so the
   * transport-independent catalog module does not depend on the Platform API response classes.
   */
  private final String errorCode;

  /**
   * Creates a catalog exception with a stable error code.
   *
   * <p>Use this constructor when the rejection is fully described by the catalog state and no lower
   * exception needs to be retained. Both parameters are required so API adapters can always expose
   * a stable code and a short message.
   *
   * @param errorCode machine-readable failure code exposed by API adapters
   * @param message human-readable description of the rejected catalog or artifact state
   */
  public AppCatalogException(String errorCode, String message) {
    super(Objects.requireNonNull(message, "message"));
    this.errorCode = Objects.requireNonNull(errorCode, "errorCode");
  }

  /**
   * Creates a catalog exception with a stable error code and underlying cause.
   *
   * <p>Use this constructor when preserving the lower cause helps logs or tests distinguish a
   * parse, transport, filesystem, or cryptographic failure. API adapters should still use {@link
   * #errorCode()} rather than inspecting the cause type.
   *
   * @param errorCode machine-readable failure code exposed by API adapters
   * @param message human-readable description of the rejected catalog or artifact state
   * @param cause parse, filesystem, network, or cryptographic failure that triggered rejection
   */
  public AppCatalogException(String errorCode, String message, Throwable cause) {
    super(Objects.requireNonNull(message, "message"), cause);
    this.errorCode = Objects.requireNonNull(errorCode, "errorCode");
  }

  /**
   * Returns the stable error code for API and test assertions.
   *
   * <p>The returned value is intended for exact comparison by tests and API error mappers. It is
   * not localized and should remain stable across wording changes in exception messages.
   *
   * @return machine-readable catalog failure code
   */
  public String errorCode() {
    return errorCode;
  }
}
