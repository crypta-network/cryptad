package network.crypta.fs;

import java.nio.file.Path;
import java.util.Objects;

/** Final absolute directories for config, data/state, cache, run, and logs. */
public final class Resolved {
  private final Path configDir;
  private final Path dataDir;
  private final Path cacheDir;
  private final Path runDir;
  private final Path logsDir;

  public Resolved(Path configDir, Path dataDir, Path cacheDir, Path runDir, Path logsDir) {
    this.configDir = Objects.requireNonNull(configDir);
    this.dataDir = Objects.requireNonNull(dataDir);
    this.cacheDir = Objects.requireNonNull(cacheDir);
    this.runDir = Objects.requireNonNull(runDir);
    this.logsDir = Objects.requireNonNull(logsDir);
  }

  public Path getConfigDir() {
    return configDir;
  }

  public Path getDataDir() {
    return dataDir;
  }

  public Path getCacheDir() {
    return cacheDir;
  }

  public Path getRunDir() {
    return runDir;
  }

  public Path getLogsDir() {
    return logsDir;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Resolved resolved)) {
      return false;
    }
    return Objects.equals(configDir, resolved.configDir)
        && Objects.equals(dataDir, resolved.dataDir)
        && Objects.equals(cacheDir, resolved.cacheDir)
        && Objects.equals(runDir, resolved.runDir)
        && Objects.equals(logsDir, resolved.logsDir);
  }

  @Override
  public int hashCode() {
    return Objects.hash(configDir, dataDir, cacheDir, runDir, logsDir);
  }

  @Override
  public String toString() {
    return "Resolved{"
        + "configDir="
        + configDir
        + ", dataDir="
        + dataDir
        + ", cacheDir="
        + cacheDir
        + ", runDir="
        + runDir
        + ", logsDir="
        + logsDir
        + '}';
  }
}
