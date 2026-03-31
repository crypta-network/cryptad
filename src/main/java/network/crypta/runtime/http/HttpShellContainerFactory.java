package network.crypta.runtime.http;

import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.support.PriorityAwareExecutor;

/**
 * Creates runtime-owned {@link HttpShellContainer} instances for node-facing HTTP services.
 *
 * <p>This interface is the narrow seam between runtime bootstrap code and whichever HTTP shell
 * bridge binding a composition root selects. Callers such as the node services subsystem depend on
 * this factory instead of naming a specific shell host directly. That keeps concrete bridge
 * construction out of higher-level runtime code and makes startup wiring easier to test.
 *
 * <p>The contract is intentionally small. A factory implementation receives the already-selected
 * FProxy sub-configuration and executor, constructs a matching shell container, and returns the
 * runtime-facing wrapper. The interface does not define caching, singleton behavior, or lifecycle
 * ownership beyond creation; callers remain responsible for deciding when to start and manage the
 * returned container.
 *
 * @see HttpShellContainer
 */
@FunctionalInterface
public interface HttpShellContainerFactory {

  /**
   * Creates a new HTTP shell container for the supplied FProxy configuration and executor.
   *
   * <p>Implementations should translate the provided runtime configuration into a concrete shell
   * host without widening the dependency surface that runtime code must see. The method is expected
   * to return a fresh container suitable for one startup path. It does not start the container,
   * finalize configuration, or apply any separate lifecycle policy on behalf of the caller.
   *
   * @param fproxyConfig FProxy sub-configuration that supplies listener and shell initialization
   *     values
   * @param executor priority-aware executor that the created shell uses for request-adjacent work
   * @return a newly constructed runtime-facing container that wraps the concrete HTTP shell
   *     implementation
   * @throws InvalidConfigValueException if the supplied FProxy configuration cannot produce a valid
   *     shell container
   */
  HttpShellContainer create(SubConfig fproxyConfig, PriorityAwareExecutor executor)
      throws InvalidConfigValueException;
}
