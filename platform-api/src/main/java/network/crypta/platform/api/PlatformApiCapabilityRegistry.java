package network.crypta.platform.api;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/**
 * Public read-only registry of manifest capabilities recognized by Platform API v1.
 *
 * <p>The authorization matrix remains owned by {@link PlatformApiCapabilities}; this class exposes
 * only the capability names so developer tooling can lint app manifests without copying the list
 * into another module. It is deliberately smaller than the authorization implementation: callers
 * can ask whether a manifest-declared name is known, but they cannot infer route permissions,
 * app-principal policy, or future compatibility guarantees from this registry alone.
 *
 * <p>The registry is immutable, process-local, and safe to share across threads. Capability names
 * are returned in lexicographic order so command-line diagnostics, generated documentation, and
 * unit tests do not depend on declaration order inside {@link PlatformApiCapabilities}. When
 * Platform API v1 gains or retires a capability, update the authorization matrix and this registry
 * together so app developer tools continue to report the same vocabulary that runtime authorization
 * enforces.
 *
 * @see PlatformApiCapabilities
 */
public final class PlatformApiCapabilityRegistry {
  private static final Set<String> KNOWN_CAPABILITIES =
      Collections.unmodifiableSet(
          new TreeSet<>(
              Set.of(
                  PlatformApiCapabilities.ALERTS_READ,
                  PlatformApiCapabilities.ALERTS_WRITE,
                  PlatformApiCapabilities.APPS_MANAGE,
                  PlatformApiCapabilities.APPS_READ,
                  PlatformApiCapabilities.CATALOGS_MANAGE,
                  PlatformApiCapabilities.CATALOGS_READ,
                  PlatformApiCapabilities.CONFIG_READ,
                  PlatformApiCapabilities.CONFIG_WRITE,
                  PlatformApiCapabilities.CONNECTIVITY_READ,
                  PlatformApiCapabilities.CONTENT_INSERT,
                  PlatformApiCapabilities.DIAGNOSTICS_READ,
                  PlatformApiCapabilities.NODE_READ,
                  PlatformApiCapabilities.PEERS_READ,
                  PlatformApiCapabilities.PEERS_WRITE,
                  PlatformApiCapabilities.QUEUE_READ,
                  PlatformApiCapabilities.QUEUE_WRITE,
                  PlatformApiCapabilities.SECURITY_READ,
                  PlatformApiCapabilities.SECURITY_WRITE,
                  PlatformApiCapabilities.UPDATES_READ,
                  PlatformApiCapabilities.UPDATES_WRITE,
                  PlatformApiCapabilities.WIZARD_READ,
                  PlatformApiCapabilities.WIZARD_WRITE)));

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
