package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogSourceSnapshot;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Conservative background scheduler for signed app catalog refreshes and app update checks.
 *
 * <p>The scheduler performs discovery work for the app-update lifecycle. A scheduler pass refreshes
 * configured signed catalogs, records a path-free result for that global target, and then calls
 * {@link AppUpdateService#check(String, boolean)} for installed apps whose per-app due time has
 * arrived. That service remains the single owner of candidate validation, review gates,
 * policy-driven staging, apply-when-stopped behavior, process health handling, rollback state, and
 * history. The scheduler never calls AppHost bundle replacement, catalog install-plan preparation,
 * or rollback primitives directly.
 *
 * <p>The default runtime configuration enables background discovery, not silent third-party update
 * apply. Manual remains the default per-app policy; automatic staging or apply happens only when an
 * operator explicitly selected {@code stage} or {@code apply_when_stopped}, and the update
 * service's existing gates allow it.
 *
 * <p>State is deliberately small and safe to expose through the Platform API. The scheduler records
 * timestamps, bounded failure counts, sanitized error codes, sanitized messages, and next due
 * times. Backing paths, catalog scratch locations, process tokens, and staged bundle paths stay
 * outside this type's public summaries.
 *
 * <p>Thread lifecycle is explicit. Tests can call {@link #tick(Instant)} without starting a
 * background thread, while the HTTP runtime calls {@link #start()} and registers {@link #close()}
 * with shutdown. Concurrent ticks are skipped rather than overlapped. App lifecycle mutation
 * remains serialized by the shared {@link AppUpdateService}, and scheduler persistence failures are
 * converted into visible backoff state instead of causing rapid repeated checks.
 */
public final class AppUpdateScheduler implements AutoCloseable {
  private static final System.Logger LOG = System.getLogger(AppUpdateScheduler.class.getName());
  private static final String CATALOG_STATE_ID = "catalog-refresh";
  private static final String ERROR_CATALOG_LIST_FAILED = "catalog_list_failed";
  private static final String ERROR_CATALOG_REFRESH_FAILED = "catalog_refresh_failed";
  private static final String ERROR_APP_LIST_FAILED = "app_list_failed";
  private static final String ERROR_SCHEDULER_STORE_FAILED = "scheduler_store_failed";
  private static final String ERROR_SCHEDULER_FAILED = "scheduler_failed";
  private static final String MESSAGE_APP_CHECK_COMPLETED = "Scheduler update check completed.";
  private static final String MESSAGE_APP_CHECK_FAILED = "Scheduler update check failed.";
  private static final String MESSAGE_CATALOG_REFRESH_COMPLETED =
      "Scheduler catalog refresh completed.";
  private static final String MESSAGE_CATALOG_REFRESH_FAILED =
      "Scheduler catalog refresh failed; cached verified catalogs remain in use.";

  private final AppHost appHost;
  private final AppCatalogManager catalogManager;
  private final AppUpdateService updateService;
  private final AppUpdateSchedulerConfig config;
  private final AppUpdateSchedulerStore store;
  private final Clock clock;
  private final Random random;
  private final Instant startedAt;
  private final AtomicBoolean running = new AtomicBoolean();
  private final ConcurrentMap<String, AppUpdateSchedulerState> transientAppStates =
      new ConcurrentHashMap<>();
  private final AtomicReference<AppUpdateSchedulerState> transientCatalogState =
      new AtomicReference<>();
  private ScheduledExecutorService executor;
  private ScheduledFuture<?> scheduledTask;

  /**
   * Creates a scheduler using the system clock and nondeterministic jitter.
   *
   * <p>This constructor is the production-oriented entry point. It prepares the scheduler object
   * but does not start a background thread; runtime composition must call {@link #start()} after
   * the shared {@link AppUpdateService} has been wired into the router and after shutdown cleanup
   * has been registered. The generated jitter is intentionally nondeterministic so nodes do not
   * refresh configured catalogs at the same instant after startup.
   *
   * @param appHost AppHost used only to enumerate installed apps before checks
   * @param catalogManager signed catalog manager used for configured catalog refreshes
   * @param updateService update service that owns app lifecycle checks and policy behavior
   * @param config scheduler intervals, jitter, enablement, and failure backoff settings
   * @param store durable scheduler state store used for summaries and restart continuity
   * @throws NullPointerException if any required scheduler dependency is {@code null}
   */
  public AppUpdateScheduler(
      AppHost appHost,
      AppCatalogManager catalogManager,
      AppUpdateService updateService,
      AppUpdateSchedulerConfig config,
      AppUpdateSchedulerStore store) {
    this(
        appHost,
        catalogManager,
        updateService,
        config,
        store,
        Clock.systemUTC(),
        new SecureRandom());
  }

  /**
   * Creates a scheduler with deterministic time and jitter inputs.
   *
   * <p>This constructor is intended for focused tests. Calling it does not start a thread; tests
   * should invoke {@link #tick(Instant)} directly and assert on the returned result and stored
   * state. Supplying a fixed {@link Clock} and seeded {@link Random} makes next-check timestamps,
   * failure backoff, and jitter bounds reproducible without sleeping or waiting for a scheduled
   * executor.
   *
   * @param appHost AppHost used only to enumerate installed apps before checks
   * @param catalogManager signed catalog manager used for configured catalog refreshes
   * @param updateService update service that owns app lifecycle checks and policy behavior
   * @param config scheduler intervals, jitter, enablement, and failure backoff settings
   * @param store durable scheduler state store used for summaries and restart continuity
   * @param clock clock used by {@link #runDueTasksOnce()} and summary fallback timestamps
   * @param random random source used for bounded jitter between scheduled passes
   * @throws NullPointerException if any required scheduler dependency is {@code null}
   */
  public AppUpdateScheduler(
      AppHost appHost,
      AppCatalogManager catalogManager,
      AppUpdateService updateService,
      AppUpdateSchedulerConfig config,
      AppUpdateSchedulerStore store,
      Clock clock,
      Random random) {
    this.appHost = Objects.requireNonNull(appHost, "appHost");
    this.catalogManager = Objects.requireNonNull(catalogManager, "catalogManager");
    this.updateService = Objects.requireNonNull(updateService, "updateService");
    this.config = Objects.requireNonNull(config, "config");
    this.store = Objects.requireNonNull(store, "store");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.random = Objects.requireNonNull(random, "random");
    startedAt = clock.instant();
  }

  /**
   * Starts the optional background executor.
   *
   * <p>Calling this method on a disabled scheduler is a no-op. Calling it more than once keeps the
   * existing executor. The executor wakes on a fixed delay and then consults durable per-target due
   * times before doing work, so the poll cadence can be shorter than the catalog-refresh or app
   * check intervals without hammering catalogs or installed apps. Startup delay and jitter are
   * applied before the first wakeup.
   */
  public synchronized void start() {
    if (!config.enabled() || executor != null) {
      return;
    }
    executor =
        Executors.newSingleThreadScheduledExecutor(
            runnable -> {
              Thread thread = new Thread(runnable, "Cryptad-AppUpdateScheduler");
              thread.setDaemon(true);
              return thread;
            });
    long initialDelaySeconds = config.initialDelay().plus(jitter()).toSeconds();
    long pollSeconds = config.pollInterval().toSeconds();
    scheduledTask =
        executor.scheduleWithFixedDelay(
            this::runDueTasksOnceSafely,
            initialDelaySeconds,
            Math.max(1L, pollSeconds),
            TimeUnit.SECONDS);
  }

  /**
   * Runs scheduler work using the configured clock.
   *
   * <p>This method is useful for manual probes and tests that want production clock semantics but
   * do not want to start the background executor. The method performs at most one pass and returns
   * a path-free aggregate result that can be logged, asserted, or included in release-certification
   * evidence.
   *
   * @return aggregate result from the due-work pass at the current scheduler clock time
   */
  public AppUpdateSchedulerTickResult runDueTasksOnce() {
    return tick(clock.instant());
  }

  /**
   * Runs one deterministic scheduler pass at the supplied time.
   *
   * <p>The pass refreshes due catalogs first, then checks due installed apps with {@code
   * refreshCatalogs=false} so the app-update service does not refresh each catalog once per app.
   * Catalog refresh failures are recorded and the pass continues with the manager's last verified
   * snapshots, matching the existing catalog-manager behavior.
   *
   * <p>The method is non-overlapping. If another scheduler pass is active, this call returns an
   * {@code already_running} result without waiting for the active pass. Disabled schedulers return
   * a disabled result and perform no store, catalog, or app-host work.
   *
   * @param now scheduler time to use for due checks, state timestamps, and backoff calculations
   * @return path-free aggregate tick result for the attempted deterministic pass
   * @throws NullPointerException if {@code now} is {@code null}
   */
  public AppUpdateSchedulerTickResult tick(Instant now) {
    Instant checkedNow = Objects.requireNonNull(now, "now");
    if (!config.enabled()) {
      return AppUpdateSchedulerTickResult.disabled(checkedNow);
    }
    if (!running.compareAndSet(false, true)) {
      return AppUpdateSchedulerTickResult.alreadyRunning(checkedNow);
    }
    try {
      return runTick(checkedNow);
    } finally {
      running.set(false);
    }
  }

  /**
   * Returns path-free scheduler state for one app summary.
   *
   * <p>If no scheduler pass has touched the app yet, the method returns an initial scheduled or
   * disabled state derived from configuration. Store failures are reported as sanitized scheduler
   * failures rather than exposing the store path.
   *
   * <p>The returned map is suitable for direct inclusion in the existing {@code scheduler} field of
   * the app-update summary envelope. It contains only the normalized app id, status, timestamps,
   * result, failure count, error code, safe message, and concurrency label.
   *
   * @param appId installed app id to normalize before reading scheduler metadata
   * @return scheduler summary safe for Platform API responses and Web Shell display
   */
  public java.util.Map<String, Object> summary(String appId) {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    if (!config.enabled()) {
      return AppUpdateSchedulerState.disabled(normalizedAppId).toJsonValue();
    }
    return readAppState(normalizedAppId, clock.instant()).toJsonValue();
  }

  /**
   * Clears scheduler metadata for one app.
   *
   * <p>App uninstall and missing-app cleanup use this method through {@link AppUpdateService} so a
   * later reinstall does not inherit stale scheduler backoff, failure, or due-time state from a
   * removed installation. A store delete failure is contained to scheduler metadata: the in-process
   * summary falls back to a fresh scheduled state, and the failure is logged without exposing the
   * backing path through API responses.
   *
   * @param appId installed app id whose durable scheduler metadata should be removed
   */
  public void clearAppState(String appId) {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    try {
      store.clearAppState(normalizedAppId);
      transientAppStates.remove(normalizedAppId);
    } catch (IOException _) {
      transientAppStates.put(normalizedAppId, freshScheduledState(normalizedAppId));
      LOG.log(System.Logger.Level.WARNING, "Failed to clear app update scheduler state");
    }
  }

  /**
   * Stops the background executor if one was started.
   *
   * <p>The method is idempotent and does not wait for a long-running app-update check to finish. It
   * cancels future scheduler wakeups and interrupts the scheduler thread. AppHost shutdown remains
   * responsible for stopping managed app processes, and interrupted app-update work must still rely
   * on the update service and host for lifecycle safety.
   */
  @Override
  public synchronized void close() {
    if (executor == null) {
      return;
    }
    if (scheduledTask != null) {
      scheduledTask.cancel(true);
      scheduledTask = null;
    }
    executor.shutdownNow();
    executor = null;
  }

  private void runDueTasksOnceSafely() {
    try {
      runDueTasksOnce();
    } catch (RuntimeException exception) {
      LOG.log(System.Logger.Level.WARNING, "App update scheduler pass failed", exception);
    }
  }

  private AppUpdateSchedulerTickResult runTick(Instant now) {
    AppUpdateSchedulerState catalogState = readCatalogState(now);
    CatalogRefreshResult catalogResult = refreshCatalogsIfDue(now, catalogState);
    List<InstalledAppSnapshot> installedApps;
    try {
      installedApps =
          appHost.listInstalled().stream()
              .sorted(Comparator.comparing(InstalledAppSnapshot::appId))
              .toList();
    } catch (IOException _) {
      AppUpdateSchedulerState failedCatalogState =
          catalogState.withFailure(
              now,
              nextAfterFailure(now, catalogState),
              ERROR_APP_LIST_FAILED,
              "Installed apps could not be listed for scheduler checks.");
      AppUpdateSchedulerState recordedCatalogState = writeCatalogState(failedCatalogState);
      return new AppUpdateSchedulerTickResult(
          now,
          AppUpdateSchedulerStatus.BACKOFF,
          AppUpdateSchedulerState.RESULT_FAILED,
          catalogResult.attempted(),
          catalogResult.failures(),
          0,
          1,
          0,
          recordedCatalogState.nextCheckAt(),
          "Installed apps could not be listed for scheduler checks.");
    }

    AppCheckResult appResult = checkDueApps(now, installedApps);
    int failures = catalogResult.failures() + appResult.failures();
    int work = catalogResult.attempted() + appResult.checked();
    AppUpdateSchedulerStatus status = aggregateStatus(work, failures);
    String result = aggregateResult(work, failures);
    return new AppUpdateSchedulerTickResult(
        now,
        status,
        result,
        catalogResult.attempted(),
        catalogResult.failures(),
        appResult.checked(),
        appResult.failures(),
        appResult.skipped(),
        earliest(catalogResult.nextDueAt(), appResult.nextDueAt()),
        aggregateMessage(work, failures));
  }

  private CatalogRefreshResult refreshCatalogsIfDue(
      Instant now, AppUpdateSchedulerState catalogState) {
    if (isCurrentSchedulerStoreFailure(catalogState, now)) {
      return new CatalogRefreshResult(0, 1, catalogState.nextCheckAt());
    }
    if (catalogState.isScheduledAfter(now)) {
      return CatalogRefreshResult.notDue(catalogState.nextCheckAt());
    }
    return refreshDueCatalogs(now, catalogState);
  }

  private CatalogRefreshResult refreshDueCatalogs(Instant now, AppUpdateSchedulerState state) {
    AppUpdateSchedulerState runningState = writeCatalogState(state.withRunning(now));
    if (isSchedulerStoreFailure(runningState)) {
      return new CatalogRefreshResult(0, 1, runningState.nextCheckAt());
    }
    List<AppCatalogSourceSnapshot> catalogs;
    try {
      catalogs = catalogManager.listCatalogs();
    } catch (AppCatalogException exception) {
      AppUpdateSchedulerState failed =
          state.withFailure(
              now,
              nextAfterFailure(now, state),
              exception.errorCode(),
              "Configured catalogs could not be listed for scheduler refresh.");
      AppUpdateSchedulerState recorded = writeCatalogState(failed);
      return new CatalogRefreshResult(0, 1, recorded.nextCheckAt());
    } catch (IOException _) {
      AppUpdateSchedulerState failed =
          state.withFailure(
              now,
              nextAfterFailure(now, state),
              ERROR_CATALOG_LIST_FAILED,
              "Configured catalogs could not be listed for scheduler refresh.");
      AppUpdateSchedulerState recorded = writeCatalogState(failed);
      return new CatalogRefreshResult(0, 1, recorded.nextCheckAt());
    }
    int failures = 0;
    for (AppCatalogSourceSnapshot catalog : catalogs) {
      try {
        catalogManager.refresh(catalog.catalogId());
      } catch (AppCatalogException | IOException _) {
        failures++;
      }
    }
    if (failures == 0) {
      AppUpdateSchedulerState success =
          state.withSuccess(
              now,
              nextAfterSuccess(now, config.catalogRefreshInterval()),
              MESSAGE_CATALOG_REFRESH_COMPLETED);
      AppUpdateSchedulerState recorded = writeCatalogState(success);
      return new CatalogRefreshResult(
          catalogs.size(), isSchedulerStoreFailure(recorded) ? 1 : 0, recorded.nextCheckAt());
    }
    AppUpdateSchedulerState failed =
        state.withFailure(
            now,
            nextAfterFailure(now, state),
            ERROR_CATALOG_REFRESH_FAILED,
            MESSAGE_CATALOG_REFRESH_FAILED);
    AppUpdateSchedulerState recorded = writeCatalogState(failed);
    return new CatalogRefreshResult(catalogs.size(), failures, recorded.nextCheckAt());
  }

  private AppCheckResult checkDueApps(Instant now, List<InstalledAppSnapshot> installedApps) {
    int checked = 0;
    int failures = 0;
    int skipped = 0;
    Instant nextDueAt = null;
    for (InstalledAppSnapshot installed : installedApps) {
      AppUpdateSchedulerState state = readAppState(installed.appId(), now);
      if (isCurrentSchedulerStoreFailure(state, now)) {
        failures++;
        nextDueAt = earliest(nextDueAt, state.nextCheckAt());
      } else if (state.isScheduledAfter(now)) {
        skipped++;
        nextDueAt = earliest(nextDueAt, state.nextCheckAt());
      } else {
        checked++;
        AppUpdateSchedulerState nextState = checkOneApp(now, state);
        if (AppUpdateSchedulerState.RESULT_FAILED.equals(nextState.lastResult())) {
          failures++;
        }
        nextDueAt = earliest(nextDueAt, nextState.nextCheckAt());
      }
    }
    return new AppCheckResult(checked, failures, skipped, nextDueAt);
  }

  private AppUpdateSchedulerState checkOneApp(Instant now, AppUpdateSchedulerState state) {
    AppUpdateSchedulerState runningState = writeAppState(state.withRunning(now));
    if (isSchedulerStoreFailure(runningState)) {
      return runningState;
    }
    try {
      updateService.check(state.appId(), false);
      AppUpdateSchedulerState success =
          state.withSuccess(
              now, nextAfterSuccess(now, config.appCheckInterval()), MESSAGE_APP_CHECK_COMPLETED);
      return writeAppState(success);
    } catch (PlatformApiException exception) {
      if (exception.statusCode() == 404) {
        clearAppState(state.appId());
        return state.withNotInstalled(now);
      }
      AppUpdateSchedulerState failed =
          state.withFailure(
              now, nextAfterFailure(now, state), exception.errorCode(), MESSAGE_APP_CHECK_FAILED);
      return writeAppState(failed);
    } catch (RuntimeException _) {
      AppUpdateSchedulerState failed =
          state.withFailure(
              now, nextAfterFailure(now, state), ERROR_SCHEDULER_FAILED, MESSAGE_APP_CHECK_FAILED);
      return writeAppState(failed);
    }
  }

  private AppUpdateSchedulerState readAppState(String appId, Instant now) {
    AppUpdateSchedulerState transientState = transientAppStates.get(appId);
    if (transientState != null) {
      return transientState;
    }
    try {
      Optional<AppUpdateSchedulerState> stored = store.readAppState(appId);
      return stored.orElseGet(() -> initialScheduledState(appId));
    } catch (IOException _) {
      AppUpdateSchedulerState failed =
          schedulerStoreFailureState(appId, now, 1, "Scheduler state could not be read.");
      transientAppStates.put(appId, failed);
      return failed;
    }
  }

  private AppUpdateSchedulerState readCatalogState(Instant now) {
    AppUpdateSchedulerState transientState = transientCatalogState.get();
    if (transientState != null) {
      return transientState;
    }
    try {
      Optional<AppUpdateSchedulerState> stored = store.readCatalogState();
      return stored.orElseGet(() -> initialScheduledState(CATALOG_STATE_ID));
    } catch (IOException _) {
      AppUpdateSchedulerState failed =
          schedulerStoreFailureState(
              CATALOG_STATE_ID, now, 1, "Scheduler state could not be read.");
      transientCatalogState.set(failed);
      return failed;
    }
  }

  private AppUpdateSchedulerState writeAppState(AppUpdateSchedulerState state) {
    try {
      store.writeAppState(state);
      transientAppStates.remove(state.appId());
      return state;
    } catch (IOException _) {
      AppUpdateSchedulerState failed =
          schedulerStoreFailureState(
              state.appId(),
              state.lastCheckAt() == null ? clock.instant() : state.lastCheckAt(),
              state.failureCount() + 1,
              "Scheduler state could not be persisted.");
      transientAppStates.put(state.appId(), failed);
      LOG.log(System.Logger.Level.WARNING, "Failed to persist app update scheduler state");
      return failed;
    }
  }

  private AppUpdateSchedulerState writeCatalogState(AppUpdateSchedulerState state) {
    try {
      store.writeCatalogState(state);
      transientCatalogState.set(null);
      return state;
    } catch (IOException _) {
      AppUpdateSchedulerState failed =
          schedulerStoreFailureState(
              state.appId(),
              state.lastCheckAt() == null ? clock.instant() : state.lastCheckAt(),
              state.failureCount() + 1,
              "Scheduler state could not be persisted.");
      transientCatalogState.set(failed);
      LOG.log(System.Logger.Level.WARNING, "Failed to persist app catalog scheduler state");
      return failed;
    }
  }

  private AppUpdateSchedulerState initialScheduledState(String appId) {
    Instant initialDueAt = startedAt.plus(config.initialDelay());
    return AppUpdateSchedulerState.scheduled(appId, initialDueAt);
  }

  private AppUpdateSchedulerState freshScheduledState(String appId) {
    return AppUpdateSchedulerState.scheduled(appId, clock.instant().plus(config.initialDelay()));
  }

  private AppUpdateSchedulerState schedulerStoreFailureState(
      String appId, Instant now, int failureCount, String message) {
    return new AppUpdateSchedulerState(
        appId,
        true,
        AppUpdateSchedulerStatus.BACKOFF,
        now,
        now.plus(failureBackoff(failureCount)).plus(jitter()),
        AppUpdateSchedulerState.RESULT_FAILED,
        now,
        failureCount,
        ERROR_SCHEDULER_STORE_FAILED,
        message);
  }

  private Instant nextAfterSuccess(Instant now, Duration interval) {
    return now.plus(interval).plus(jitter());
  }

  private Instant nextAfterFailure(Instant now, AppUpdateSchedulerState state) {
    return now.plus(failureBackoff(state.failureCount() + 1)).plus(jitter());
  }

  private Duration failureBackoff(int failureCount) {
    long baseSeconds = Math.max(1L, config.failureBackoff().toSeconds());
    long maxSeconds = Math.max(baseSeconds, config.maxFailureBackoff().toSeconds());
    long delay = baseSeconds;
    for (int index = 1; index < failureCount && delay < maxSeconds; index++) {
      if (delay > maxSeconds / 2L) {
        delay = maxSeconds;
      } else {
        delay *= 2L;
      }
    }
    return Duration.ofSeconds(Math.min(delay, maxSeconds));
  }

  private Duration jitter() {
    long jitterSeconds = config.jitter().toSeconds();
    if (jitterSeconds <= 0L) {
      return Duration.ZERO;
    }
    long exclusiveBound = jitterSeconds == Long.MAX_VALUE ? Long.MAX_VALUE : jitterSeconds + 1L;
    return Duration.ofSeconds(random.nextLong(exclusiveBound));
  }

  private static boolean isSchedulerStoreFailure(AppUpdateSchedulerState state) {
    return ERROR_SCHEDULER_STORE_FAILED.equals(state.lastErrorCode());
  }

  private static boolean isCurrentSchedulerStoreFailure(
      AppUpdateSchedulerState state, Instant now) {
    return isSchedulerStoreFailure(state) && now.equals(state.lastCheckAt());
  }

  private static AppUpdateSchedulerStatus aggregateStatus(int work, int failures) {
    if (failures > 0) {
      return AppUpdateSchedulerStatus.BACKOFF;
    }
    if (work == 0) {
      return AppUpdateSchedulerStatus.SKIPPED;
    }
    return AppUpdateSchedulerStatus.SUCCESS;
  }

  private static String aggregateResult(int work, int failures) {
    if (failures > 0) {
      return AppUpdateSchedulerState.RESULT_FAILED;
    }
    if (work == 0) {
      return AppUpdateSchedulerState.RESULT_SKIPPED;
    }
    return AppUpdateSchedulerState.RESULT_SUCCESS;
  }

  private static String aggregateMessage(int work, int failures) {
    if (failures > 0) {
      return "Scheduler pass completed with failures.";
    }
    if (work == 0) {
      return "No scheduler work was due.";
    }
    return "Scheduler pass completed.";
  }

  private static Instant earliest(Instant left, Instant right) {
    if (left == null) {
      return right;
    }
    if (right == null) {
      return left;
    }
    return left.isBefore(right) ? left : right;
  }

  private record CatalogRefreshResult(int attempted, int failures, Instant nextDueAt) {
    private static CatalogRefreshResult notDue(Instant nextDueAt) {
      return new CatalogRefreshResult(0, 0, nextDueAt);
    }
  }

  private record AppCheckResult(int checked, int failures, int skipped, Instant nextDueAt) {}
}
