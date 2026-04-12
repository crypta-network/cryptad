package network.crypta.clients.http;

/**
 * Describes how FProxy should treat cached filtered content when serving a request.
 *
 * <p>The enum is HTTP-local on purpose. Shared shell types such as {@link ToadletContext}, {@link
 * ToadletContainer}, and {@link SimpleToadletServer} need to expose and persist the policy without
 * depending on the concrete fetch-tracker implementation that applies it. Keeping the type here
 * makes that boundary explicit: shell code can talk about refiltering as a user-visible HTTP
 * choice, while fetch execution code can consume the same value without owning the public contract.
 *
 * <p>The constant names are part of the persisted configuration round-trip used by the legacy HTTP
 * shell. Callers store and restore them through {@link Enum#name()} and {@link Enum#valueOf(Class,
 * String)}, so the identifiers must remain stable. The three values are ordered by increasing
 * freshness requirements: reuse an already filtered cached result, re-run filtering against cached
 * data, or bypass the cached representation and fetch fresh bytes from the network.
 */
public enum RefilterPolicy {
  /**
   * Reuse previously filtered bytes without re-running the filter.
   *
   * <p>This is the least disruptive option. It favors responsiveness and avoids extra temporary
   * bucket churn when cached filtered output is already available, but it may preserve older
   * filtering decisions instead of applying the latest filter rules.
   */
  ACCEPT_OLD,

  /**
   * Re-run filtering against the cached content.
   *
   * <p>This middle ground keeps the response aligned with current filtering rules while still
   * avoiding a full network refetching when the cached source data is otherwise usable. It
   * typically trades some local processing and temporary storage for better policy freshness.
   */
  RE_FILTER,

  /**
   * Discard the cached representation and refetch the content from the network.
   *
   * <p>This is the strongest refresh behavior. It avoids reusing any cached filtered output and can
   * bypass stale cached source artifacts as well, at the cost of extra latency, bandwidth, and
   * network dependency compared with the other policies.
   */
  RE_FETCH
}
