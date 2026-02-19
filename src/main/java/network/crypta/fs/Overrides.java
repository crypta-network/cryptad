package network.crypta.fs;

import java.nio.file.Path;
import java.util.Objects;

/** Optional override paths for config/data/cache/run/logs resolution. */
public final class Overrides {
  private final Path config;
  private final Path data;
  private final Path cache;
  private final Path run;
  private final Path logs;

  public Overrides() {
    this(null, null, null, null, null);
  }

  public Overrides(Path config, Path data, Path cache, Path run, Path logs) {
    this.config = config;
    this.data = data;
    this.cache = cache;
    this.run = run;
    this.logs = logs;
  }

  public Path getConfig() {
    return config;
  }

  public Path getData() {
    return data;
  }

  public Path getCache() {
    return cache;
  }

  public Path getRun() {
    return run;
  }

  public Path getLogs() {
    return logs;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Overrides overrides)) {
      return false;
    }
    return Objects.equals(config, overrides.config)
        && Objects.equals(data, overrides.data)
        && Objects.equals(cache, overrides.cache)
        && Objects.equals(run, overrides.run)
        && Objects.equals(logs, overrides.logs);
  }

  @Override
  public int hashCode() {
    return Objects.hash(config, data, cache, run, logs);
  }

  @Override
  public String toString() {
    return "Overrides{"
        + "config="
        + config
        + ", data="
        + data
        + ", cache="
        + cache
        + ", run="
        + run
        + ", logs="
        + logs
        + '}';
  }
}
