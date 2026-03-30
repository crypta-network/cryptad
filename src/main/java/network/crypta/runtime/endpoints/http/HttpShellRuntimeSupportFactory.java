package network.crypta.runtime.endpoints.http;

import network.crypta.clients.http.HttpShellRuntimeSupport;
import network.crypta.node.NodeClientCore;

/**
 * Creates runtime-owned {@link HttpShellRuntimeSupport} instances for HTTP shell wiring.
 *
 * <p>This interface is the narrow construction seam that higher-level runtime code uses when it
 * needs HTTP shell support backed by a {@link NodeClientCore}. It lets packages outside {@code
 * network.crypta.runtime.endpoints.http} request runtime support without naming a concrete bridge
 * class directly. That keeps the endpoint package responsible for binding top-level wiring to the
 * current implementation while preserving the existing startup behavior.
 *
 * <p>Typical callers choose a factory during daemon startup, then invoke {@link
 * #create(NodeClientCore)} while assembling HTTP shell components. The interface does not define
 * caching, singleton semantics, or ownership transfer. It only describes how to get a support
 * object for a given core, and concrete implementations remain free to decide whether each call
 * returns a new bridge instance.
 */
@FunctionalInterface
public interface HttpShellRuntimeSupportFactory {

  /**
   * Creates a runtime support bridge for the supplied daemon core.
   *
   * <p>The supplied {@code core} becomes the backing runtime object for the returned support
   * instance. Callers usually invoke this during HTTP shell startup after the node has created its
   * client core and before endpoint code begins serving requests. This method does not impose
   * caching requirements, so repeated calls may produce distinct support instances over the same
   * core when an implementation chooses to do so.
   *
   * @param core daemon core that the returned runtime support delegates to for node-backed
   *     operations
   * @return a runtime support bridge compatible with the current HTTP shell implementation for the
   *     supplied daemon core
   */
  HttpShellRuntimeSupport create(NodeClientCore core);

  /**
   * Returns the core-backed runtime support factory used by the current HTTP bridge.
   *
   * <p>This helper centralizes the production binding to {@link CoreHttpShellRuntimeSupport} inside
   * the runtime HTTP endpoint package. Callers outside this package can therefore use the default
   * runtime path without importing the concrete bridge class directly. The returned factory is
   * suitable for repeated reuse anywhere the current node runtime should preserve the legacy
   * core-backed behavior.
   *
   * @return factory that constructs {@link CoreHttpShellRuntimeSupport} instances from a supplied
   *     daemon core
   */
  static HttpShellRuntimeSupportFactory coreBacked() {
    return CoreHttpShellRuntimeSupport::new;
  }
}
