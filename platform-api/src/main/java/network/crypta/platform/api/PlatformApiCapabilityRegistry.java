package network.crypta.platform.api;

import java.util.Set;

/**
 * Public read-only registry of manifest capabilities recognized by Platform API v1.
 *
 * <p>The capability vocabulary is derived from {@link PlatformApiContract#current()} so developer
 * tooling, contract snapshots, and runtime app-principal authorization use one shared source of
 * truth. Callers can ask whether a manifest-declared name is known, but they should use the full
 * contract when they need route permissions, app-principal policy, or stability metadata.
 *
 * <p>The registry is immutable, process-local, and safe to share across threads. Capability names
 * are returned in lexicographic order so command-line diagnostics, generated documentation, and
 * unit tests do not depend on descriptor declaration order.
 *
 * @see PlatformApiContract
 */
public final class PlatformApiCapabilityRegistry {
  private static final Set<String> KNOWN_CAPABILITIES =
      PlatformApiContract.current().capabilityNames();

  private PlatformApiCapabilityRegistry() {}

  /**
   * Returns the sorted immutable set of known app manifest capabilities.
   *
   * <p>The returned set is the canonical capability vocabulary for manifest linting and developer
   * tooling. It is not a mutable configuration view, and attempts to add or remove names fail
   * through the collection API. Callers that need presentation-specific ordering can copy the set,
   * but they should not duplicate the capability literals in another module.
   *
   * @return immutable sorted capability names currently recognized by Platform API v1
   */
  public static Set<String> knownCapabilities() {
    return KNOWN_CAPABILITIES;
  }
}
