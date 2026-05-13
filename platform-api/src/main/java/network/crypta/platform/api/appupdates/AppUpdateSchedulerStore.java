package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.util.Optional;

/**
 * Durable state store for app-update scheduler metadata.
 *
 * <p>The scheduler writes only path-free state: stable target ids, timestamps, status strings,
 * failure counters, error codes, and short safe messages. Implementations may choose memory or
 * filesystem storage, but neither form should expose its backing path through returned state. The
 * app-state methods are used for Platform API summaries; the catalog-state methods let background
 * catalog refresh due times and failures survive node restarts without adding a separate public
 * endpoint.
 *
 * <p>Implementations are part of scheduler correctness, not just serialization. Reads must reject
 * malformed or misplaced state instead of returning metadata for a different target id. Write
 * failures must be reported with {@link IOException} so the scheduler can enter visible backoff
 * rather than repeating catalog refreshes or app checks on every poll.
 */
public interface AppUpdateSchedulerStore {
  /**
   * Reads scheduler state for one app.
   *
   * <p>The returned state must belong to the requested app id. If persisted data is absent,
   * malformed, or names a different target, implementations should return {@link Optional#empty()}
   * unless the backing store itself cannot be read.
   *
   * @param appId normalized app id whose scheduler metadata should be loaded
   * @return stored state for the requested app, or empty when no valid state exists
   * @throws IOException if the backing store cannot be read
   */
  Optional<AppUpdateSchedulerState> readAppState(String appId) throws IOException;

  /**
   * Persists scheduler state for one app.
   *
   * <p>App state must be kept separate from internal scheduler targets such as catalog refresh
   * state. The scheduler relies on failed writes being visible so it can record a sanitized
   * scheduler-store failure and apply backoff.
   *
   * @param state path-free scheduler state for one app target
   * @throws IOException if the backing store cannot be written
   */
  void writeAppState(AppUpdateSchedulerState state) throws IOException;

  /**
   * Removes scheduler state for one app.
   *
   * <p>Uninstall and missing-app cleanup call this method so a later reinstall with the same app id
   * starts from fresh scheduler metadata instead of inheriting stale backoff, error, or due-time
   * state from the removed installation.
   *
   * @param appId normalized app id whose app scheduler state should be removed
   * @throws IOException if the backing store cannot remove the state
   */
  void clearAppState(String appId) throws IOException;

  /**
   * Reads scheduler state for the catalog refresh target.
   *
   * <p>Catalog state is global scheduler metadata and must not share the same durable slot as any
   * app id, including an app whose valid id happens to match an internal target label.
   *
   * @return stored catalog-refresh state, or empty when no valid catalog state exists
   * @throws IOException if the backing store cannot be read
   */
  Optional<AppUpdateSchedulerState> readCatalogState() throws IOException;

  /**
   * Persists scheduler state for the catalog refresh target.
   *
   * <p>The stored value represents configured catalog refresh work, not a user-installed app.
   * Implementations should keep this namespace isolated from app state and propagate write failures
   * to the scheduler.
   *
   * @param state path-free scheduler state for catalog refresh work
   * @throws IOException if the backing store cannot be written
   */
  void writeCatalogState(AppUpdateSchedulerState state) throws IOException;
}
