package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.Optional;
import java.util.Properties;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * File-backed scheduler state store rooted below the AppHost data tree.
 *
 * <p>The store persists one properties file per installed app plus one catalog-refresh file in an
 * internal scheduler namespace. File names are derived from normalized app ids rather than request
 * input, and file contents contain only the path-free fields from {@link AppUpdateSchedulerState}.
 * The store never returns its root path in state or exception text consumed by Platform API
 * summaries.
 *
 * <p>Writes use a temporary file followed by an atomic move when the filesystem supports it. A
 * partially written state file should therefore not be observed after a process crash; at worst the
 * scheduler falls back to its initial due-time state and runs another conservative catalog refresh
 * or app check.
 *
 * <p>Corrupt files and files that contain a different valid target id are ignored as absent state.
 * Actual I/O failures still propagate as {@link IOException}. That distinction lets the scheduler
 * recover from stale or manually edited metadata while still entering visible backoff when the data
 * directory cannot be read or written.
 */
public final class FileAppUpdateSchedulerStore implements AppUpdateSchedulerStore {
  private static final String CATALOG_STATE_ID = "catalog-refresh";
  private static final String FILE_SUFFIX = ".properties";
  private static final String KEY_VERSION = "version";
  private static final String KEY_APP_ID = "appId";
  private static final String KEY_ENABLED = "enabled";
  private static final String KEY_STATUS = "status";
  private static final String KEY_LAST_CHECK_AT = "lastCheckAt";
  private static final String KEY_NEXT_CHECK_AT = "nextCheckAt";
  private static final String KEY_LAST_RESULT = "lastResult";
  private static final String KEY_LAST_FAILURE_AT = "lastFailureAt";
  private static final String KEY_FAILURE_COUNT = "failureCount";
  private static final String KEY_LAST_ERROR_CODE = "lastErrorCode";
  private static final String KEY_MESSAGE = "message";

  private final Path rootDirectory;

  /**
   * Creates a file-backed scheduler store.
   *
   * <p>The directory is normalized to an absolute path once, but the normalized value is kept
   * private to the implementation. API summaries receive only the path-free values stored inside
   * each properties file.
   *
   * @param rootDirectory directory that will hold scheduler state files
   * @throws NullPointerException if {@code rootDirectory} is {@code null}
   */
  public FileAppUpdateSchedulerStore(Path rootDirectory) {
    this.rootDirectory =
        java.util.Objects.requireNonNull(rootDirectory, "rootDirectory")
            .toAbsolutePath()
            .normalize();
  }

  /**
   * Reads scheduler state for one app from the app-state namespace.
   *
   * <p>The file name is derived from the normalized app id. The loaded state is returned only when
   * its stored {@code appId} matches that normalized id, which prevents misplaced files from
   * driving checks or policy actions for a different app.
   *
   * @param appId normalized or normalizable app id whose scheduler metadata should be loaded
   * @return stored app state, or empty when no valid matching state exists
   * @throws IOException if the app-state file cannot be read
   */
  @Override
  public synchronized Optional<AppUpdateSchedulerState> readAppState(String appId)
      throws IOException {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    return readState(appStateFile(normalizedAppId), normalizedAppId);
  }

  /**
   * Writes scheduler state for one app into the app-state namespace.
   *
   * <p>The method validates the state target as an app id before writing. An app whose id is equal
   * to the internal catalog target label still writes to the app namespace, not the catalog
   * namespace.
   *
   * @param state path-free scheduler state for one app target
   * @throws IOException if the state file or its temporary replacement cannot be written
   */
  @Override
  public synchronized void writeAppState(AppUpdateSchedulerState state) throws IOException {
    AppManifest.normalizeAppId(state.appId());
    writeState(appStateFile(state.appId()), state);
  }

  /**
   * Removes scheduler state for one app from the app-state namespace.
   *
   * <p>Only the app-state file is removed. Catalog refresh metadata is preserved even if the app id
   * is {@code catalog-refresh}, which keeps internal scheduler state isolated from app lifecycle
   * cleanup.
   *
   * @param appId normalized or normalizable app id whose scheduler metadata should be removed
   * @throws IOException if the app-state file cannot be removed
   */
  @Override
  public synchronized void clearAppState(String appId) throws IOException {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    Files.deleteIfExists(appStateFile(normalizedAppId));
  }

  /**
   * Reads scheduler state for the internal catalog-refresh target.
   *
   * <p>The catalog state lives under an internal subdirectory rather than beside app files. The
   * stored target id must still match {@code catalog-refresh}; otherwise the method treats the file
   * as stale or corrupt and returns empty state.
   *
   * @return stored catalog-refresh state, or empty when no valid matching state exists
   * @throws IOException if the catalog-state file cannot be read
   */
  @Override
  public synchronized Optional<AppUpdateSchedulerState> readCatalogState() throws IOException {
    return readState(catalogStateFile(), CATALOG_STATE_ID);
  }

  /**
   * Writes scheduler state for the internal catalog-refresh target.
   *
   * <p>The method rejects states for any other target before touching the filesystem. This keeps
   * app scheduler metadata and catalog scheduler metadata from overwriting each other.
   *
   * @param state path-free scheduler state whose target id is {@code catalog-refresh}
   * @throws IOException if the state file or its temporary replacement cannot be written
   * @throws IllegalArgumentException if {@code state} does not describe the catalog target
   */
  @Override
  public synchronized void writeCatalogState(AppUpdateSchedulerState state) throws IOException {
    if (!CATALOG_STATE_ID.equals(state.appId())) {
      throw new IllegalArgumentException("catalog state must use target id " + CATALOG_STATE_ID);
    }
    writeState(catalogStateFile(), state);
  }

  private Optional<AppUpdateSchedulerState> readState(Path file, String expectedTargetId)
      throws IOException {
    if (!Files.isRegularFile(file)) {
      return Optional.empty();
    }
    Properties properties = new Properties();
    try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
      properties.load(reader);
    }
    if (!"1".equals(properties.getProperty(KEY_VERSION))) {
      return Optional.empty();
    }
    try {
      AppUpdateSchedulerState state =
          new AppUpdateSchedulerState(
              properties.getProperty(KEY_APP_ID),
              Boolean.parseBoolean(properties.getProperty(KEY_ENABLED)),
              status(properties.getProperty(KEY_STATUS)),
              instant(properties.getProperty(KEY_LAST_CHECK_AT)),
              instant(properties.getProperty(KEY_NEXT_CHECK_AT)),
              properties.getProperty(KEY_LAST_RESULT),
              instant(properties.getProperty(KEY_LAST_FAILURE_AT)),
              integer(properties.getProperty(KEY_FAILURE_COUNT)),
              properties.getProperty(KEY_LAST_ERROR_CODE),
              properties.getProperty(KEY_MESSAGE));
      return expectedTargetId.equals(state.appId()) ? Optional.of(state) : Optional.empty();
    } catch (RuntimeException _) {
      return Optional.empty();
    }
  }

  private void writeState(Path file, AppUpdateSchedulerState state) throws IOException {
    Path parentDirectory = file.getParent();
    Files.createDirectories(parentDirectory);
    Properties properties = new Properties();
    properties.setProperty(KEY_VERSION, "1");
    properties.setProperty(KEY_APP_ID, state.appId());
    properties.setProperty(KEY_ENABLED, Boolean.toString(state.enabled()));
    properties.setProperty(KEY_STATUS, state.status().jsonValue());
    setInstant(properties, KEY_LAST_CHECK_AT, state.lastCheckAt());
    setInstant(properties, KEY_NEXT_CHECK_AT, state.nextCheckAt());
    properties.setProperty(KEY_LAST_RESULT, state.lastResult());
    setInstant(properties, KEY_LAST_FAILURE_AT, state.lastFailureAt());
    properties.setProperty(KEY_FAILURE_COUNT, Integer.toString(state.failureCount()));
    setOptional(properties, KEY_LAST_ERROR_CODE, state.lastErrorCode());
    setOptional(properties, KEY_MESSAGE, state.message());
    Path tempFile = Files.createTempFile(parentDirectory, ".app-update-scheduler-", ".tmp");
    boolean moved = false;
    try {
      try (Writer writer = Files.newBufferedWriter(tempFile, StandardCharsets.UTF_8)) {
        properties.store(writer, "Cryptad app update scheduler state");
      }
      moveReplacing(tempFile, file);
      moved = true;
    } finally {
      if (!moved) {
        Files.deleteIfExists(tempFile);
      }
    }
  }

  private Path appStateFile(String targetId) {
    return rootDirectory.resolve(targetId + FILE_SUFFIX);
  }

  private Path catalogStateFile() {
    return rootDirectory.resolve("_internal").resolve(CATALOG_STATE_ID + FILE_SUFFIX);
  }

  private static void moveReplacing(Path source, Path target) throws IOException {
    try {
      Files.move(
          source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static AppUpdateSchedulerStatus status(String value) {
    if (value == null || value.isBlank()) {
      return AppUpdateSchedulerStatus.SCHEDULED;
    }
    for (AppUpdateSchedulerStatus status : AppUpdateSchedulerStatus.values()) {
      if (status.jsonValue().equals(value.trim())) {
        return status;
      }
    }
    return AppUpdateSchedulerStatus.SCHEDULED;
  }

  private static Instant instant(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return Instant.parse(value.trim());
    } catch (RuntimeException _) {
      return null;
    }
  }

  private static int integer(String value) {
    if (value == null || value.isBlank()) {
      return 0;
    }
    try {
      return Math.max(0, Integer.parseInt(value.trim()));
    } catch (NumberFormatException _) {
      return 0;
    }
  }

  private static void setInstant(Properties properties, String key, Instant value) {
    if (value != null) {
      properties.setProperty(key, value.toString());
    }
  }

  private static void setOptional(Properties properties, String key, String value) {
    if (value != null) {
      properties.setProperty(key, value);
    }
  }
}
