package network.crypta.platform.api.networkbudget;

import java.util.Locale;
import java.util.Objects;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Stable identities used by app-network budget counters.
 *
 * <p>Most counters are scoped to a real normalized app id. A few counters are internal aggregate
 * scopes, such as the node-wide global budget and host/operator budget. Internal scopes are
 * path-safe but deliberately start with {@code _}, which is not accepted by the AppHost app-id
 * grammar, so a real installed app cannot collide with them.
 *
 * <p>This helper is the only place that accepts both app ids and internal budget scopes. Stores and
 * services use it before building durable keys, so a caller cannot smuggle a content URI, local
 * path, source label, or arbitrary underscore-prefixed name into the budget namespace. The returned
 * values are stable path segments, not display names.
 */
public final class AppNetworkBudgetScope {
  /**
   * Internal node-wide aggregate budget scope.
   *
   * <p>The service persists global counters under this scope for budget families that must be
   * shared across apps, such as the content-fetch family and global subscription poll counters.
   */
  public static final String GLOBAL = "_cryptad_global";

  /**
   * Internal host/operator budget scope used for non-app Trust Graph imports.
   *
   * <p>Host/operator calls do not have an app manifest id. Storing them here keeps their Trust
   * Graph and import-by-URI fetch usage separate from a valid app whose id happens to be {@code
   * operator}.
   */
  public static final String HOST_OPERATOR = "_cryptad_operator";

  private AppNetworkBudgetScope() {}

  /**
   * Normalizes either a real app id or one of the reserved internal budget scopes.
   *
   * <p>Real app ids are normalized through the AppHost manifest grammar. Internal scopes must match
   * one of the constants in this class exactly after trimming and lower-casing; other underscore
   * names are rejected so future reserved scopes cannot collide with app-supplied text.
   *
   * @param scopeId app id or reserved internal scope to normalize for durable budget keys
   * @return normalized path-safe budget scope suitable for store keys and snapshots
   * @throws IllegalArgumentException if the value is neither a valid app id nor a valid internal
   *     scope
   */
  public static String normalize(String scopeId) {
    String normalized = Objects.requireNonNull(scopeId, "scopeId").trim().toLowerCase(Locale.ROOT);
    if (normalized.isEmpty()) {
      throw new IllegalArgumentException("budget scope must not be blank");
    }
    if (normalized.charAt(0) == '_') {
      if (!GLOBAL.equals(normalized) && !HOST_OPERATOR.equals(normalized)) {
        throw new IllegalArgumentException("invalid internal budget scope");
      }
      return normalized;
    }
    return AppManifest.normalizeAppId(normalized);
  }

  /**
   * Returns whether the supplied normalized scope is the internal global aggregate scope.
   *
   * <p>The method normalizes the input before comparing it with {@link #GLOBAL}, so callers can use
   * it with either raw store values or app-facing input that has not yet been normalized. Invalid
   * app ids and unknown internal scopes fail with the same validation behavior as {@link
   * #normalize(String)}.
   *
   * @param scopeId budget scope to inspect for global aggregate behavior
   * @return {@code true} when the scope is the global aggregate scope
   */
  @SuppressWarnings("unused")
  public static boolean isGlobal(String scopeId) {
    return GLOBAL.equals(normalize(scopeId));
  }
}
