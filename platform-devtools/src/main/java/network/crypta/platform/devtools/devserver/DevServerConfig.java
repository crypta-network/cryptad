package network.crypta.platform.devtools.devserver;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;

/**
 * Configuration for one local {@code crypta-app dev} server instance.
 *
 * <p>The record is the normalized boundary between CLI options and server startup. It turns a
 * missing host into the loopback default, converts local paths to absolute normalized form, accepts
 * port {@code 0} for OS assignment, and supplies the default mock browser-session lifetime when the
 * caller does not specify one. Host exposure policy is checked by {@link LoopbackHostPolicy} during
 * server startup rather than in this record, because tests and CLI parsing both need to construct
 * the same values before deciding whether to allow non-loopback binding.
 *
 * <p>Instances are immutable after construction and safe to share with the server wrapper. They do
 * not validate that the bundle or fixture directory exists; startup performs those checks so errors
 * can use the same app-distribution exception path as the rest of devtools.
 *
 * @param bundleDir staged app bundle root
 * @param host listener host, loopback unless explicitly allowed by the caller
 * @param port listener port, where {@code 0} asks the OS to allocate one
 * @param fixtureDir optional directory containing deterministic JSON fixture files
 * @param allowNonLoopback whether the caller explicitly accepted a non-loopback listener
 * @param sessionTtl browser-session lifetime used in bootstrap JSON
 */
public record DevServerConfig(
    Path bundleDir,
    String host,
    int port,
    Path fixtureDir,
    boolean allowNonLoopback,
    Duration sessionTtl) {
  /** Default loopback host used by {@code crypta-app dev}. */
  public static final String DEFAULT_HOST = "127.0.0.1";

  /** Default browser-session lifetime for local developer bootstrap responses. */
  public static final Duration DEFAULT_SESSION_TTL = Duration.ofHours(1);

  /**
   * Creates a normalized configuration snapshot.
   *
   * <p>The constructor rejects invalid port numbers and non-positive session lifetimes immediately.
   * It does not resolve symlinks or open files; that work belongs to the static asset and fixture
   * safety checks that run after the bundle manifest is parsed.
   */
  public DevServerConfig {
    bundleDir = Objects.requireNonNull(bundleDir, "bundleDir").toAbsolutePath().normalize();
    host = host == null || host.isBlank() ? DEFAULT_HOST : host.trim();
    if (port < 0 || port > 65535) {
      throw new IllegalArgumentException("port must be between 0 and 65535");
    }
    if (fixtureDir != null) {
      fixtureDir = fixtureDir.toAbsolutePath().normalize();
    }
    sessionTtl = Objects.requireNonNullElse(sessionTtl, DEFAULT_SESSION_TTL);
    if (sessionTtl.isZero() || sessionTtl.isNegative()) {
      throw new IllegalArgumentException("session TTL must be positive");
    }
  }
}
