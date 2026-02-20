package network.crypta.fs;

import java.nio.file.Path;

/**
 * Optional path overrides applied during directory resolution.
 *
 * <p>This record carries override candidates for each directory category used by Cryptad runtime
 * path selection. Each component is nullable; a {@code null} component indicates that resolution
 * should fall back to lower-precedence sources such as environment-derived values or platform base
 * defaults. Instances are immutable and intended to be composed by different layers (for example,
 * CLI parsing and environment mapping) before precedence merging in resolver code.
 *
 * @param config override path for configuration directory resolution, or {@code null} to defer
 * @param data override path for data directory resolution, or {@code null} to defer
 * @param cache override path for cache directory resolution, or {@code null} to defer
 * @param run override path for runtime directory resolution, or {@code null} to defer
 * @param logs override path for logs directory resolution, or {@code null} to defer
 */
public record Overrides(Path config, Path data, Path cache, Path run, Path logs) {

  /**
   * Creates an override set with no explicit values.
   *
   * <p>All components are set to {@code null}, meaning callers should use default precedence
   * resolution from other sources.
   */
  public Overrides() {
    this(null, null, null, null, null);
  }
}
