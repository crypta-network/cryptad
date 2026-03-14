package network.crypta.runtime.spi;

import java.util.Map;
import java.util.Set;

/**
 * Exposes runtime configuration export and update capabilities without leaking daemon-only types.
 *
 * <p>This management-facing port gives infrastructure code a narrow closed loop around the
 * configuration state: export one or more logical sections, apply textual overrides keyed by a
 * dotted option name, and then persist the resulting state through the runtime's existing
 * persistence path. The SPI deliberately does not expose daemon config registries, option objects,
 * storage internals, or transport-specific field-set implementations.
 *
 * <p>Typical callers are request handlers that need to:
 *
 * <ul>
 *   <li>perform access control in a higher layer;
 *   <li>request a point-in-time configuration snapshot;
 *   <li>apply validated textual overrides; and
 *   <li>persist the resulting runtime state when appropriate.
 * </ul>
 *
 * <p>Implementations may preserve legacy semantics such as ignoring unknown keys or logging invalid
 * values. Those policies remain implementation details so the SPI can stay JDK-only and stable
 * across runtime adapters.
 *
 * @see RuntimePorts
 * @see ConfigSnapshot
 */
public interface ConfigPort {
  /**
   * Exports the requested configuration sections as an immutable snapshot.
   *
   * <p>The returned snapshot represents a point-in-time view that is suitable for immediate
   * response serialization. Implementations may omit sections that were not requested or that
   * resolve to empty exports. Callers should therefore treat the result as sparse rather than
   * assuming that every requested section will be present.
   *
   * @param sections configuration sections to export for the current request
   * @return immutable snapshot containing the requested sections that exported non-empty content
   */
  ConfigSnapshot export(Set<ConfigSection> sections);

  /**
   * Applies textual overrides keyed by the dotted configuration name.
   *
   * <p>The SPI accepts already-parsed textual values and leaves validation, lookup, and error
   * handling to the runtime implementation. Unknown keys may be ignored according to existing
   * behavior, and a successful application does not imply persistence. Callers that need durable
   * changes should invoke {@link #persist()} explicitly after the update pass completes.
   *
   * @param overrides requested overrides keyed by dotted option name such as {@code node.maxPeers}
   */
  void applyOverrides(Map<String, String> overrides);

  /**
   * Persists the current configuration state using the runtime's existing persistence path.
   *
   * <p>This method does not define transactional or change-detection behavior. Implementations may
   * persist even when no values changed, when some overrides were ignored, or when validation
   * failures were logged during a prior {@link #applyOverrides(Map)} call.
   */
  void persist();
}
