package network.crypta.runtime.http;

import network.crypta.node.NodeClientCore;

/**
 * Creates runtime-owned {@link HttpShellRuntimeSupport} instances for HTTP shell wiring.
 *
 * <p>This interface is the narrow construction seam that higher-level runtime code uses when it
 * needs HTTP shell support backed by a {@link NodeClientCore}. It lets higher-level runtime
 * packages request runtime support without naming a concrete bridge class directly. That keeps the
 * composition root responsible for selecting the production binding while preserving the existing
 * startup behavior.
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
   * @return a runtime-owned support bridge for the supplied daemon core
   */
  HttpShellRuntimeSupport create(NodeClientCore core);
}
