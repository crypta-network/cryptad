package network.crypta.fs;

import java.nio.file.Path;
import java.util.Objects;

/** Final absolute directories for config, data/state, cache, run, and logs. */
public record Resolved(Path configDir, Path dataDir, Path cacheDir, Path runDir, Path logsDir) {
  public Resolved {
    Objects.requireNonNull(configDir);
    Objects.requireNonNull(dataDir);
    Objects.requireNonNull(cacheDir);
    Objects.requireNonNull(runDir);
    Objects.requireNonNull(logsDir);
  }
}
