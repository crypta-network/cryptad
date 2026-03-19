package network.crypta.runtime.spi;

import java.util.List;

/**
 * Exposes the narrow persisted-symlink storage still needed by the legacy symlinker toadlet.
 *
 * <p>This SPI keeps the existing configuration-backed load and save behavior behind the runtime
 * boundary while leaving the in-memory alias map, redirect logic, and HTTP 404 behavior in the
 * toadlet itself. The interface works entirely with detached {@link ToadletSymlinkEntry} lists so
 * callers do not depend on daemon config classes, callback types, or the concrete map structure
 * inside {@code SymlinkerToadlet}.
 *
 * <p>Typical usage is straightforward: load one snapshot during toadlet construction, then persist
 * the full alias set after each admin add or remove operation. Implementations may back the data
 * with legacy node configuration, tests, or another persistence layer, but callers should always
 * treat returned lists as snapshots and pass the complete desired state on writes.
 *
 * @see RuntimePorts#toadletSymlinks()
 */
public interface ToadletSymlinkPort {
  /**
   * Loads the currently configured alias mappings.
   *
   * <p>The returned list is detached request-independent data suitable for constructing the
   * symlinker's in-memory alias map. Callers should not assume the list is live or mutable, and
   * they should rebuild any internal lookup structures they need from the returned entries.
   *
   * @return detached list of configured alias mappings representing the persisted symlink state at
   *     load time
   */
  List<ToadletSymlinkEntry> loadConfiguredSymlinks();

  /**
   * Persists the full current alias mapping set.
   *
   * <p>Callers provide the complete mapping list after an add or remove operation, so the runtime
   * implementation can preserve the legacy configuration-store behavior without depending on the
   * toadlet's internal map structure. Implementations may write immediate or stage data for an
   * underlying config callback, but callers should assume the supplied list fully replaces the
   * previously persisted alias set.
   *
   * @param entries detached list representing the full current alias mapping set that should remain
   *     available after restart
   */
  void persistConfiguredSymlinks(List<ToadletSymlinkEntry> entries);
}
