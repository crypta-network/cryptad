package network.crypta.platform.appui;

import java.util.Optional;

/**
 * Verifies opaque browser app session tokens presented to the Platform API bridge.
 *
 * <p>The legacy HTTP Platform API adapter calls this interface when a request carries {@code
 * X-Crypta-App-Session}. A successful verification converts the bearer token into an {@link
 * AppBrowserSession}, which contains only app identity, permissions, and timestamps. The raw token
 * must not cross into transport-neutral Platform API request objects, audit records, router errors,
 * or app summaries.
 *
 * <p>Implementations should fail closed. Blank, unknown, expired, stale, non-static, and
 * uninstalled-app sessions return {@link Optional#empty()}. Callers can then map that result to a
 * structured authentication failure such as {@code invalid_app_browser_session}. Permission denial
 * is not the verifier's job; the central Platform API capability matrix handles missing manifest
 * permissions after a token has been authenticated.
 */
public interface AppBrowserSessionVerifier {
  /**
   * Verifies one browser session token.
   *
   * <p>The supplied token may come directly from an HTTP header and therefore may be blank,
   * malformed, expired, or already evicted. Implementations should normalize defensively and avoid
   * echoing token text in exceptions, logs, or returned objects.
   *
   * @param token opaque bearer token from the {@code X-Crypta-App-Session} request header
   * @return token-free app browser session when the bearer token is currently valid
   */
  Optional<AppBrowserSession> verify(String token);
}
