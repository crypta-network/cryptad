package network.crypta.platform.appdist;

import java.io.IOException;

/**
 * Signals digest, signature, or trust-policy failures for local app bundles.
 *
 * <p>{@code AppDistributionException} keeps bundle-distribution failures in the same checked I/O
 * flow as filesystem work while still letting callers distinguish invalid sidecars, unsupported
 * algorithms, untrusted keys, and tampered bundle contents from other generic {@link IOException}
 * cases. Code that maps errors to API responses can treat this exception as caller-fixable bundle
 * input when it arises from sidecar or trust validation, while still preserving unrelated raw
 * {@code IOException} failures as host-side problems.
 *
 * <p>Messages are written for local operators and tests. They should identify the rejected
 * distribution state without relying on absolute paths, secrets, or private key material.
 */
public class AppDistributionException extends IOException {
  /**
   * Creates an exception with a human-readable failure message.
   *
   * @param message detail describing the rejected bundle state or distribution metadata
   */
  public AppDistributionException(String message) {
    super(message);
  }

  /**
   * Creates an exception with a human-readable failure message and underlying cause.
   *
   * @param message detail describing the rejected bundle state or distribution metadata
   * @param cause underlying parse, filesystem, or crypto error that triggered the failure
   */
  public AppDistributionException(String message, Throwable cause) {
    super(message, cause);
  }
}
