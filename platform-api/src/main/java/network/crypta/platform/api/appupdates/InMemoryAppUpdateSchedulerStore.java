package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * In-memory scheduler state store for tests and embedded routers.
 *
 * <p>The production HTTP runtime uses {@link FileAppUpdateSchedulerStore} so scheduler metadata
 * survives restarts. This implementation keeps the same store contract without touching the
 * filesystem, which makes unit tests deterministic and lets alternate embeddings opt in to
 * scheduler summaries without durable state. All methods are synchronized so callers see a coherent
 * snapshot even when a background scheduler thread and an API request access the store at the same
 * time.
 *
 * <p>The in-memory store mirrors the file-backed namespace split: app state lives in a map keyed by
 * app id, while catalog refresh state lives in a separate slot. This keeps tests for an app named
 * {@code catalog-refresh} representative of production behavior.
 */
public final class InMemoryAppUpdateSchedulerStore implements AppUpdateSchedulerStore {
  private static final String CATALOG_STATE_KEY = "catalog-refresh";

  private final Map<String, AppUpdateSchedulerState> appStates = new LinkedHashMap<>();
  private AppUpdateSchedulerState catalogState;

  /**
   * Creates an empty in-memory scheduler store.
   *
   * <p>The store starts with no app state and no catalog-refresh state. It is intended for tests
   * and embeddings that do not need state to survive process restart.
   */
  public InMemoryAppUpdateSchedulerStore() {
    // Intentionally empty: field initializers create the clean in-memory store state.
  }

  /**
   * Reads scheduler state for one app from memory.
   *
   * <p>No normalization is performed here; callers should pass the same normalized app id used by
   * the scheduler. The file-backed implementation performs the stricter persisted-state validation
   * needed for disk files.
   *
   * @param appId normalized app id whose in-memory state should be loaded
   * @return stored app state, or empty when no state has been written
   */
  @Override
  public synchronized Optional<AppUpdateSchedulerState> readAppState(String appId) {
    return Optional.ofNullable(appStates.get(appId));
  }

  /**
   * Writes scheduler state for one app in memory.
   *
   * <p>Writing replaces any previous state for the same app id. App state remains separate from the
   * internal catalog-refresh slot even when the app id is {@code catalog-refresh}.
   *
   * @param state path-free scheduler state for one app target
   */
  @Override
  public synchronized void writeAppState(AppUpdateSchedulerState state) {
    appStates.put(state.appId(), state);
  }

  /**
   * Removes scheduler state for one app from memory.
   *
   * <p>The method is idempotent and intentionally does not touch catalog refresh state. Tests use
   * this to model uninstall and missing-app cleanup.
   *
   * @param appId normalized app id whose in-memory state should be removed
   */
  @Override
  public synchronized void clearAppState(String appId) throws IOException {
    appStates.remove(appId);
  }

  /**
   * Reads scheduler state for the in-memory catalog-refresh target.
   *
   * @return stored catalog-refresh state, or empty when no catalog state has been written
   */
  @Override
  public synchronized Optional<AppUpdateSchedulerState> readCatalogState() {
    return Optional.ofNullable(catalogState);
  }

  /**
   * Writes scheduler state for the in-memory catalog-refresh target.
   *
   * <p>The target id must be {@code catalog-refresh}. Rejecting other ids keeps test behavior
   * aligned with the file-backed store's namespace rules.
   *
   * @param state path-free scheduler state for catalog refresh work
   */
  @Override
  public synchronized void writeCatalogState(AppUpdateSchedulerState state) {
    if (!CATALOG_STATE_KEY.equals(state.appId())) {
      throw new IllegalArgumentException("catalog state must use target id " + CATALOG_STATE_KEY);
    }
    catalogState = state;
  }
}
