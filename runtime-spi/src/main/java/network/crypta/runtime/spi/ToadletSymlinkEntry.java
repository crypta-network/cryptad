package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Immutable alias-to-target entry used by the legacy symlinker toadlet SPI.
 *
 * <p>This record is intentionally small and JDK-only, so runtime SPI callers can exchange symlink
 * state without depending on daemon config or HTTP classes. Each instance represents one persisted
 * mapping from a short admin-shell alias path to the target toadlet path prefix that should replace
 * it during redirect construction.
 *
 * <p>The record does not normalize, canonicalize, or otherwise reinterpret slash conventions.
 * Callers are expected to preserve the stored values that the symlinker already understands.
 *
 * @param alias request-path prefix that the symlinker should match for incoming requests
 * @param target destination-path prefix that replaces the alias when constructing redirects
 */
public record ToadletSymlinkEntry(String alias, String target) {
  /**
   * Creates one detached symlink entry.
   *
   * <p>The constructor enforces only non-nullity. It does not validate prefix formatting, trailing
   * slashes, or redirect safety because those behaviors remain the responsibility of the existing
   * symlinker logic and its callers.
   *
   * @param alias request-path prefix to match; never {@code null}
   * @param target destination-path prefix to substitute during redirect rewriting; never {@code
   *     null}
   */
  public ToadletSymlinkEntry {
    Objects.requireNonNull(alias, "alias");
    Objects.requireNonNull(target, "target");
  }
}
