package network.crypta.fs;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Immutable final directory set produced after applying all resolution rules.
 *
 * <p>This record represents the effective paths used by Cryptad at runtime for configuration,
 * persistent data, cache content, runtime artifacts, and log output. Values are expected to be
 * absolute or otherwise fully normalized by resolver logic before construction. The instance acts
 * as a transport object between directory strategy code and downstream consumers that need stable
 * filesystem locations.
 *
 * @param configDir resolved configuration directory path
 * @param dataDir resolved data/state directory path
 * @param cacheDir resolved cache directory path
 * @param runDir resolved runtime directory path for transient files
 * @param logsDir resolved logs directory path
 */
public record Resolved(Path configDir, Path dataDir, Path cacheDir, Path runDir, Path logsDir) {
  /**
   * Creates a validated resolved-directory record.
   *
   * <p>All directory components are required to be non-null, so callers can safely consume the
   * returned record without null checks.
   */
  public Resolved {
    Objects.requireNonNull(configDir);
    Objects.requireNonNull(dataDir);
    Objects.requireNonNull(cacheDir);
    Objects.requireNonNull(runDir);
    Objects.requireNonNull(logsDir);
  }
}
