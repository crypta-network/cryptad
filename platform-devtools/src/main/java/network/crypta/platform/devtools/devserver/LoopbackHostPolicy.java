package network.crypta.platform.devtools.devserver;

import java.net.InetAddress;
import java.net.UnknownHostException;
import network.crypta.platform.appdist.AppDistributionException;

/**
 * Host binding policy for the local development server.
 *
 * <p>The dev server is safe by default only when it listens on loopback. This helper keeps the
 * policy small and testable: common loopback literals are accepted without DNS work, other host
 * values are resolved through {@link InetAddress}, and non-loopback listeners require an explicit
 * caller opt-in. The returned warning is intended for CLI startup output so developers can see when
 * they have exposed the mock API beyond the local machine.
 */
public final class LoopbackHostPolicy {
  /** Prevents construction of this stateless host-policy helper. */
  private LoopbackHostPolicy() {}

  /**
   * Ensures the requested host is loopback unless the caller explicitly opted into exposure.
   *
   * @param host listener host text
   * @param allowNonLoopback whether non-loopback binding was explicitly allowed
   * @return warning text for explicit non-loopback binding, or an empty string
   * @throws AppDistributionException if the host is non-loopback and override is not enabled
   */
  public static String requireAllowedHost(String host, boolean allowNonLoopback)
      throws AppDistributionException {
    if (isLoopback(host)) {
      return "";
    }
    if (!allowNonLoopback) {
      throw new AppDistributionException(
          "refusing non-loopback dev server host: "
              + host
              + " (use --allow-non-loopback to override)");
    }
    return "Warning: dev server is bound to a non-loopback host; use only on trusted networks.";
  }

  /**
   * Returns whether the host resolves to a loopback address.
   *
   * @param host listener host text, with surrounding whitespace ignored
   * @return {@code true} for loopback literals or resolvable loopback host names
   */
  public static boolean isLoopback(String host) {
    String value = host == null ? "" : host.trim();
    if (value.isEmpty()) {
      return false;
    }
    if ("localhost".equalsIgnoreCase(value)
        || "127.0.0.1".equals(value)
        || "::1".equals(value)
        || "0:0:0:0:0:0:0:1".equals(value)) {
      return true;
    }
    try {
      return InetAddress.getByName(value).isLoopbackAddress();
    } catch (UnknownHostException _) {
      return false;
    }
  }
}
