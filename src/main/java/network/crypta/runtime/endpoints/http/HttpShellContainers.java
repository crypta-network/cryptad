package network.crypta.runtime.endpoints.http;

import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.io.ArrayBucketFactory;

/**
 * Static factory helpers for runtime-owned HTTP shell container wiring.
 *
 * <p>This class centralizes creation of the runtime-facing HTTP shell seam, so bootstrap and
 * service code do not instantiate the legacy HTTP shell implementation directly. The class has no
 * policy of its own: it preserves the existing concrete construction path, including the current
 * bucket-factory choice and executor handoff, and simply returns the narrow {@link
 * HttpShellContainer} view that runtime packages are meant to depend on.
 *
 * <p>Keeping construction here makes the dependency boundary explicit. Runtime code sees only the
 * seam, while the bridge package retains the knowledge that the current backing implementation is
 * {@link SimpleToadletServer}. Future changes to the concrete shell host can therefore stay
 * localized to this package rather than spreading new direct references back into bootstrap or
 * endpoint wiring code.
 */
public final class HttpShellContainers {
  private HttpShellContainers() {}

  /**
   * Creates the runtime-owned HTTP shell container backed by {@link SimpleToadletServer}.
   *
   * <p>The returned wrapper preserves the existing FProxy shell construction path. It builds a new
   * {@link SimpleToadletServer} with the same runtime-selected {@link ArrayBucketFactory} and
   * executor that legacy startup code already relied on, then exposes that server through the
   * narrower runtime seam. Callers should treat the returned container as the sole handle for later
   * startup, configuration, and FProxy lifecycle operations.
   *
   * @param fproxyConfig FProxy configuration subsection used to initialize listener, theme, and
   *     related shell settings
   * @param executor priority-aware executor that the HTTP shell should use for its background and
   *     request-adjacent work
   * @return runtime-owned wrapper around a newly created concrete HTTP shell host
   * @throws InvalidConfigValueException if the supplied FProxy configuration cannot produce a valid
   *     concrete shell server
   */
  public static HttpShellContainer create(SubConfig fproxyConfig, PriorityAwareExecutor executor)
      throws InvalidConfigValueException {
    return new SimpleToadletServerHttpShellContainer(
        new SimpleToadletServer(fproxyConfig, new ArrayBucketFactory(), executor));
  }
}
