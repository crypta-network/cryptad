package network.crypta.fs;

import java.nio.file.Path;

/** Optional override paths for config/data/cache/run/logs resolution. */
public record Overrides(Path config, Path data, Path cache, Path run, Path logs) {

  public Overrides() {
    this(null, null, null, null, null);
  }
}
