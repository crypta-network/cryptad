package network.crypta.platform.devtools.devserver;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

/**
 * Issues and validates mock browser sessions for one local dev server.
 *
 * <p>The mock Platform API requires the same {@code X-Crypta-App-Session} header shape as the
 * browser SDK uses with a real daemon-side app session. This class owns the single active token for
 * a dev server, its expiration instant, and token refresh on subsequent bootstrap requests. It is
 * synchronized because the JDK HTTP server can dispatch bootstrap and API requests concurrently on
 * several worker threads.
 *
 * <p>Tokens are generated with URL-safe Base64 and are never logged by this class. Expired tokens
 * fail API validation immediately; the next bootstrap request receives a fresh token and expiry.
 */
final class DevServerBrowserSession {
  /** Lifetime assigned to each issued mock browser session. */
  private final Duration ttl;

  /** Clock used for expiration checks and for deterministic tests. */
  private final Clock clock;

  /** Randomness source used to generate opaque session tokens. */
  private final SecureRandom random;

  /** Current active session, replaced when bootstrap observes expiration. */
  private Session current;

  /**
   * Creates a session issuer using system UTC time and secure randomness.
   *
   * @param ttl positive lifetime for each issued browser session
   */
  @SuppressWarnings("unused")
  DevServerBrowserSession(Duration ttl) {
    this(ttl, Clock.systemUTC(), new SecureRandom());
  }

  /**
   * Creates a session issuer with injectable time and randomness.
   *
   * @param ttl positive lifetime for each issued browser session
   * @param clock clock used to compute and validate expiration times
   * @param random randomness source used to create token bytes
   */
  DevServerBrowserSession(Duration ttl, Clock clock, SecureRandom random) {
    this.ttl = Objects.requireNonNull(ttl, "ttl");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.random = Objects.requireNonNull(random, "random");
    this.current = newSession(clock.instant());
  }

  /**
   * Returns the session that should be embedded in the next bootstrap response.
   *
   * @return current non-expired session, or a freshly generated replacement when expired
   */
  synchronized Session currentForBootstrap() {
    Instant now = clock.instant();
    if (!current.expiresAt().isAfter(now)) {
      current = newSession(now);
    }
    return current;
  }

  /**
   * Checks whether an API request presented the current, non-expired token.
   *
   * @param token token value from the {@code X-Crypta-App-Session} request header
   * @return {@code true} only when the token matches the current session and has not expired
   */
  synchronized boolean isValid(String token) {
    return current.token().equals(token) && current.expiresAt().isAfter(clock.instant());
  }

  /**
   * Generates a new opaque token and expiration instant.
   *
   * @param now current time used as the base for the session lifetime
   * @return newly issued mock browser session
   */
  private Session newSession(Instant now) {
    byte[] bytes = new byte[32];
    random.nextBytes(bytes);
    return new Session(
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes), now.plus(ttl));
  }

  /**
   * Opaque browser-session value returned in bootstrap JSON.
   *
   * @param token URL-safe opaque token required by mock API requests
   * @param expiresAt instant after which the token must no longer be accepted
   */
  record Session(String token, Instant expiresAt) {}
}
