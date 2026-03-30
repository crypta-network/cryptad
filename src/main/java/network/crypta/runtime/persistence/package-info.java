/**
 * Runtime-owned helpers for persisting daemon-local throttle and statistics snapshots.
 *
 * <p>This package groups the small persistence helper cluster used by runtime wiring and
 * daemon-local statistics code to read and write {@code SimpleFieldSet}-backed snapshots. The
 * re-home is ownership clarification only: scheduling cadence, shutdown-hook ordering, file naming,
 * and configuration semantics remain unchanged while the helpers move out of {@code
 * network.crypta.node}.
 *
 * <p>The package currently owns {@link network.crypta.runtime.persistence.Persistable}, {@link
 * network.crypta.runtime.persistence.Persister}, and the configurable path adapter pair used by
 * runtime endpoint and node statistics initialization.
 */
package network.crypta.runtime.persistence;
