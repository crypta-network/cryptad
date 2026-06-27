package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.net.URI;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * File-backed store for configured app catalog sources and their verified sidecars.
 *
 * <p>The store keeps each catalog under a path-safe catalog id directory below a host-owned root.
 * It persists the source URI and refresh timestamps in a strict key/value sidecar, while catalog
 * properties and signature bytes are stored verbatim so later refreshes and reads can re-run
 * signature verification against the same trusted-key policy.
 *
 * <p>The store is deliberately small and synchronous. It does not cache parsed catalogs, perform
 * trust decisions, or manage installed apps. The manager owns synchronization around calls to this
 * class. Scratch files for downloads and extraction live under {@code .staging}, a hidden name that
 * is outside the catalog-id namespace and skipped by listing.
 */
@SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
public final class AppCatalogSourceStore {
  private static final String SOURCE_FILE_NAME = "catalog-source.properties";
  private static final String ENDPOINTS_FILE_NAME = "catalog-source-endpoints.properties";
  private static final String HEALTH_FILE_NAME = "catalog-source-health.properties";
  private static final String HISTORY_DIRECTORY_NAME = "history";
  private static final String REVISION_FILE_NAME = "revision.properties";
  private static final String SOURCE_VERSION_KEY = "catalog.source.version";
  private static final String ENDPOINTS_VERSION_KEY = "catalog.source.endpoints.version";
  private static final String ENDPOINT_IDS_KEY = "endpoint.ids";
  private static final String HEALTH_VERSION_KEY = "catalog.source.health.version";
  private static final String HEALTH_IDS_KEY = "health.ids";
  private static final String REVISION_VERSION_KEY = "catalog.revision.version";
  private static final String CATALOG_ID_KEY = "catalog.id";
  private static final String CATALOG_NAME_KEY = "catalog.name";
  private static final String SOURCE_URI_KEY = "source.uri";
  private static final String ADDED_AT_KEY = "source.addedAt";
  private static final String REFRESHED_AT_KEY = "source.refreshedAt";
  private static final String LAST_ATTEMPT_AT_KEY = "source.lastAttemptAt";
  private static final String LAST_SUCCESSFUL_REFRESH_AT_KEY = "source.lastSuccessfulRefreshAt";
  private static final String LAST_FETCH_STATUS_KEY = "source.lastFetchStatus";
  private static final String LAST_FETCH_ERROR_CODE_KEY = "source.lastFetchErrorCode";
  private static final String LAST_FETCH_ERROR_MESSAGE_KEY = "source.lastFetchErrorMessage";
  private static final String LAST_RESOLVED_URI_KEY = "source.lastResolvedUri";
  private static final String REVISION_DIGEST_KEY = "revision.digest";
  private static final String REVISION_SIGNATURE_DIGEST_KEY = "revision.signatureDigest";
  private static final String REVISION_GENERATED_AT_KEY = "revision.generatedAt";
  private static final String REVISION_VERIFIED_AT_KEY = "revision.verifiedAt";
  private static final String REVISION_SOURCE_ID_KEY = "revision.source.id";
  private static final String REVISION_SOURCE_ROLE_KEY = "revision.source.role";
  private static final String REVISION_SOURCE_RESOLVED_URI_KEY = "revision.source.resolvedUri";
  private static final String REVISION_SIGNATURE_KEY_ID_KEY = "revision.signatureKeyId";
  private static final String REVISION_APP_COUNT_KEY = "revision.appCount";
  private static final String REVISION_ADVISORY_COUNT_KEY = "revision.advisoryCount";
  private static final String REVISION_DENYLIST_COUNT_KEY = "revision.denylistCount";
  private static final String REVISION_CHANNELS_KEY = "revision.channels";
  private static final String ENDPOINT_PRIORITY_KEY = "priority";
  private static final String HEALTH_LAST_GENERATED_AT_KEY = "lastGeneratedAt";
  private static final int REVISION_RETENTION_COUNT = 5;

  private final Path rootDirectory;
  private final SourceMetadataWriter sourceMetadataWriter;

  /**
   * Creates a source store rooted at a host-owned directory.
   *
   * <p>The root path is converted to an absolute normalized path immediately. Directories are
   * created lazily when a source is first written or when staging is needed for an
   * installation/update operation.
   *
   * @param rootDirectory directory where source records and catalog sidecars are stored
   */
  public AppCatalogSourceStore(Path rootDirectory) {
    this(rootDirectory, AppCatalogSourceStore::writeSourceMetadata);
  }

  AppCatalogSourceStore(Path rootDirectory, SourceMetadataWriter sourceMetadataWriter) {
    this.rootDirectory =
        Objects.requireNonNull(rootDirectory, "rootDirectory").toAbsolutePath().normalize();
    this.sourceMetadataWriter =
        Objects.requireNonNull(sourceMetadataWriter, "sourceMetadataWriter");
  }

  /**
   * Returns the root directory used for persistent catalog state.
   *
   * <p>Each configured catalog is stored below this directory using its normalized catalog id as
   * the child directory name. Callers should treat the returned path as host-private operational
   * state.
   *
   * @return absolute normalized store directory
   */
  @SuppressWarnings("unused")
  public Path rootDirectory() {
    return rootDirectory;
  }

  /**
   * Returns the scratch root used for downloads and extraction.
   *
   * <p>The scratch root is named {@code .staging} so valid catalog ids cannot collide with
   * temporary artifact state. The method returns the path only; callers create it when needed.
   *
   * @return scratch directory below the store root
   */
  public Path stagingDirectory() {
    return rootDirectory.resolve(".staging");
  }

  /**
   * Returns the host-owned review transparency log file below the catalog store root.
   *
   * <p>The returned path is operational state and must not be exposed through API, Web Shell, CLI
   * summaries, logs, or certification reports.
   *
   * @return local transparency log file path
   */
  public Path reviewTransparencyLogFile() {
    return rootDirectory
        .resolve(".review-transparency-log")
        .resolve(FileAppReviewTransparencyStore.LOG_FILE_NAME);
  }

  /**
   * Returns whether a catalog id is already stored.
   *
   * <p>The check looks for the source metadata sidecar rather than only the directory. This avoids
   * treating incomplete or scratch directories as configured catalogs.
   *
   * @param catalogId catalog id to test
   * @return {@code true} when source metadata exists for the id
   */
  public boolean exists(String catalogId) {
    return Files.isRegularFile(sourceFile(catalogId), LinkOption.NOFOLLOW_LINKS);
  }

  /**
   * Lists all stored catalog sources.
   *
   * <p>Only child directories containing valid source metadata are returned. The hidden staging
   * directory is skipped even if it contains files from a failed or in-progress catalog operation.
   * Records are sorted by directory name so API output is deterministic.
   *
   * @return stored source records sorted by catalog id
   * @throws IOException if source metadata or sidecars cannot be read safely
   */
  List<StoredCatalogSource> list() throws IOException {
    if (!Files.isDirectory(rootDirectory, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }
    List<StoredCatalogSource> sources = new ArrayList<>();
    try (var children = Files.list(rootDirectory)) {
      for (Path child :
          children.sorted(Comparator.comparing(path -> path.getFileName().toString())).toList()) {
        if (!Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS)
            || child.equals(stagingDirectory())
            || !Files.isRegularFile(child.resolve(SOURCE_FILE_NAME), LinkOption.NOFOLLOW_LINKS)) {
          continue;
        }
        sources.add(readByDirectory(child));
      }
    }
    return List.copyOf(sources);
  }

  /**
   * Reads one stored catalog source.
   *
   * <p>The metadata sidecar is parsed strictly and its catalog id must match the directory name.
   * The catalog properties and signature sidecars are returned as exact bytes for later
   * verification.
   *
   * @param catalogId catalog id to read
   * @return stored source record and catalog sidecar bytes
   * @throws IOException if the id is missing or its files cannot be read safely
   */
  StoredCatalogSource read(String catalogId) throws IOException {
    Path sourceDirectory = catalogDirectory(catalogId);
    if (!Files.isDirectory(sourceDirectory, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog not found: " + catalogId);
    }
    return readByDirectory(sourceDirectory);
  }

  /**
   * Writes or replaces one stored source and its latest fetched sidecars.
   *
   * <p>The method writes catalog bytes and signature bytes before the source metadata marker. The
   * metadata file is the store's commit marker, so a failed add that writes only fetched sidecars
   * is skipped by {@link #list()} and does not block retry as a configured catalog. It stores the
   * raw fetched sidecars rather than serializing {@code catalog}, preserving the exact bytes that
   * passed signature verification.
   *
   * @param catalog catalog content verified from {@code fetchedCatalog}
   * @param source source descriptor used to fetch the catalog
   * @param fetchedCatalog exact catalog and signature bytes to persist
   * @param addedAt original local source creation timestamp
   * @param refreshedAt latest successful refresh timestamp
   * @throws IOException if the store files cannot be written safely
   */
  public void write(
      AppCatalog catalog,
      AppCatalogSource source,
      FetchedCatalog fetchedCatalog,
      Instant addedAt,
      Instant refreshedAt)
      throws IOException {
    AppCatalogMirror primary = AppCatalogMirror.primary(source, addedAt);
    write(
        new VerifiedCatalogWrite(catalog, source, fetchedCatalog, addedAt, refreshedAt),
        new EndpointWriteState(primary, List.of(primary), Map.of()));
  }

  void write(VerifiedCatalogWrite catalogWrite, EndpointWriteState endpointState)
      throws IOException {
    AppCatalog catalog = catalogWrite.catalog();
    AppCatalogSource source = catalogWrite.source();
    FetchedCatalog fetchedCatalog = catalogWrite.fetchedCatalog();
    Instant addedAt = catalogWrite.addedAt();
    Instant refreshedAt = catalogWrite.refreshedAt();
    AppCatalogMirror selectedEndpoint = endpointState.selectedEndpoint();
    String resolvedUri = resolvedCatalogUri(fetchedCatalog, selectedEndpoint.source());
    Files.createDirectories(rootDirectory);
    Path directory = catalogDirectory(catalog.catalogId());
    Path sourceFile = directory.resolve(SOURCE_FILE_NAME);
    SourceStoreSnapshot previousSnapshot =
        Files.isRegularFile(sourceFile, LinkOption.NOFOLLOW_LINKS)
            ? SourceStoreSnapshot.capture(directory)
            : null;
    Files.createDirectories(directory);
    try {
      Files.write(
          directory.resolve(AppCatalogSignature.CATALOG_FILE_NAME), fetchedCatalog.catalogBytes());
      Files.write(
          directory.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME),
          fetchedCatalog.signatureBytes());
      writeEndpoints(directory, endpointState.mirrors());
      writeHealth(directory, endpointState.mirrorHealth());
      recordRevision(
          directory, catalog, fetchedCatalog, refreshedAt, selectedEndpoint, resolvedUri);
      sourceMetadataWriter.write(
          directory,
          sourceFile,
          serializeSource(
              catalog.catalogId(),
              source,
              addedAt,
              refreshedAt,
              AppCatalogSourceRefreshMetadata.success(refreshedAt, resolvedUri)));
    } catch (IOException exception) {
      if (previousSnapshot == null) {
        cleanupIncompleteAdd(directory, exception);
      } else {
        previousSnapshot.restore(directory, exception);
      }
      throw exception;
    } finally {
      if (previousSnapshot != null) {
        previousSnapshot.cleanup();
      }
    }
  }

  void recordRefreshFailure(
      StoredCatalogSource stored, Instant attemptedAt, AppCatalogException exception)
      throws IOException {
    recordRefreshFailure(stored, attemptedAt, exception, stored.source().resolvedCatalogFetchUri());
  }

  void recordRefreshFailure(
      StoredCatalogSource stored,
      Instant attemptedAt,
      AppCatalogException exception,
      String resolvedUri)
      throws IOException {
    String normalizedCatalogId = AppCatalog.normalizeCatalogId(stored.catalogId());
    AppCatalogSourceRefreshMetadata metadata =
        stored.refreshMetadata().failedAttempt(attemptedAt, exception, resolvedUri);
    Path directory = catalogDirectory(normalizedCatalogId);
    sourceMetadataWriter.write(
        directory,
        directory.resolve(SOURCE_FILE_NAME),
        serializeSource(
            normalizedCatalogId,
            stored.source(),
            stored.addedAt(),
            stored.refreshedAt(),
            metadata));
    Map<AppCatalogMirrorId, AppCatalogMirrorHealth> health =
        new LinkedHashMap<>(stored.mirrorHealth());
    AppCatalogMirror primary = AppCatalogMirror.primary(stored.source(), stored.addedAt());
    AppCatalogMirrorHealth previous =
        health.getOrDefault(primary.id(), AppCatalogMirrorHealth.skipped(primary));
    health.put(primary.id(), previous.failedAttempt(attemptedAt, exception, resolvedUri));
    writeHealth(directory, health);
  }

  void writeMirrorHealth(
      String catalogId, Map<AppCatalogMirrorId, AppCatalogMirrorHealth> mirrorHealth)
      throws IOException {
    Path directory = catalogDirectory(catalogId);
    if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog not found: " + catalogId);
    }
    writeHealth(directory, mirrorHealth);
  }

  void writeMirrors(String catalogId, List<AppCatalogMirror> mirrors) throws IOException {
    Path directory = catalogDirectory(catalogId);
    if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog not found: " + catalogId);
    }
    writeEndpoints(directory, mirrors);
  }

  List<AppCatalogVerifiedRevision> listRevisions(String catalogId, String currentDigest)
      throws IOException {
    Path historyDirectory = catalogDirectory(catalogId).resolve(HISTORY_DIRECTORY_NAME);
    if (!Files.isDirectory(historyDirectory, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }
    List<AppCatalogVerifiedRevision> revisions = new ArrayList<>();
    try (var children = Files.list(historyDirectory)) {
      for (Path child :
          children.sorted(Comparator.comparing(path -> path.getFileName().toString())).toList()) {
        if (isRevisionMetadataDirectory(child)) {
          revisions.add(readRevisionMetadata(child, currentDigest));
        }
      }
    }
    return revisions.stream()
        .sorted(
            Comparator.comparing(AppCatalogVerifiedRevision::verifiedAt)
                .reversed()
                .thenComparing(AppCatalogVerifiedRevision::revisionDigest))
        .toList();
  }

  FetchedCatalog readRevision(String catalogId, String revisionDigest) throws IOException {
    Path revisionDirectory =
        catalogDirectory(catalogId)
            .resolve(HISTORY_DIRECTORY_NAME)
            .resolve(AppCatalogRevisions.digestDirectoryName(revisionDigest));
    if (!Files.isDirectory(revisionDirectory, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog revision not found.");
    }
    return readFetchedCatalog(revisionDirectory);
  }

  private static boolean isRevisionMetadataDirectory(Path directory) {
    return Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
        && Files.isRegularFile(directory.resolve(REVISION_FILE_NAME), LinkOption.NOFOLLOW_LINKS);
  }

  /**
   * Removes a stored catalog source and its cached sidecars.
   *
   * <p>Removal deletes only the catalog directory named by the normalized id. The shared staging
   * directory and any installed apps are outside that directory and are not removed by this method.
   *
   * @param catalogId catalog id to remove
   * @throws IOException if deletion fails
   */
  public void remove(String catalogId) throws IOException {
    Path directory = catalogDirectory(catalogId);
    if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog not found: " + catalogId);
    }
    AppCatalogBundleExtractor.deleteRecursively(directory);
  }

  private StoredCatalogSource readByDirectory(Path directory) throws IOException {
    Map<String, String> properties = readSourceMetadata(directory);
    validateSourceVersion(properties.remove(SOURCE_VERSION_KEY));
    String catalogId = removeRequired(properties, CATALOG_ID_KEY);
    AppCatalog.normalizeCatalogId(catalogId);
    if (!directory.getFileName().toString().equals(catalogId)) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "catalog source metadata id does not match directory");
    }
    AppCatalogSource source = parseStoredSource(removeRequired(properties, SOURCE_URI_KEY));
    Instant addedAt = parseInstant(removeRequired(properties, ADDED_AT_KEY), ADDED_AT_KEY);
    Instant refreshedAt =
        parseInstant(removeRequired(properties, REFRESHED_AT_KEY), REFRESHED_AT_KEY);
    AppCatalogSourceRefreshMetadata refreshMetadata =
        parseRefreshMetadata(properties, refreshedAt, source);
    if (!properties.isEmpty()) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "unsupported catalog source property: " + properties.keySet().iterator().next());
    }
    FetchedCatalog fetchedCatalog = readFetchedCatalog(directory);
    return new StoredCatalogSource(
        catalogId,
        source,
        addedAt,
        refreshedAt,
        refreshMetadata,
        fetchedCatalog,
        readMirrors(directory, source, addedAt),
        readHealth(directory));
  }

  private static List<AppCatalogMirror> readMirrors(
      Path directory, AppCatalogSource primarySource, Instant addedAt) throws IOException {
    AppCatalogMirror primary = AppCatalogMirror.primary(primarySource, addedAt);
    Path endpointsFile = directory.resolve(ENDPOINTS_FILE_NAME);
    if (!Files.isRegularFile(endpointsFile, LinkOption.NOFOLLOW_LINKS)) {
      return List.of(primary);
    }
    Map<String, String> properties = readSidecar(endpointsFile, "catalog source endpoints");
    validateSidecarVersion(properties.remove(ENDPOINTS_VERSION_KEY), ENDPOINTS_VERSION_KEY);
    LinkedHashMap<AppCatalogMirrorId, AppCatalogMirror> mirrors = new LinkedHashMap<>();
    mirrors.put(primary.id(), primary);
    for (String idText : parseCommaList(removeRequired(properties, ENDPOINT_IDS_KEY))) {
      AppCatalogMirrorId id = AppCatalogMirrorId.parse(idText);
      String prefix = "endpoint." + id.value() + ".";
      AppCatalogSourceRole role =
          AppCatalogSourceRole.parse(removeRequired(properties, prefix + "role"));
      AppCatalogSource source =
          parseStoredSource(removeRequired(properties, prefix + SOURCE_URI_KEY));
      String priorityKey = prefix + ENDPOINT_PRIORITY_KEY;
      int priority = parseNonNegativeInt(removeRequired(properties, priorityKey), priorityKey);
      boolean enabled = Boolean.parseBoolean(removeRequired(properties, prefix + "enabled"));
      Instant endpointAddedAt =
          parseInstant(removeRequired(properties, prefix + ADDED_AT_KEY), prefix + ADDED_AT_KEY);
      if (role == AppCatalogSourceRole.PRIMARY) {
        mirrors.put(AppCatalogMirrorId.PRIMARY, primary);
      } else {
        mirrors.put(id, new AppCatalogMirror(id, role, source, priority, enabled, endpointAddedAt));
      }
    }
    if (!properties.isEmpty()) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "unsupported catalog source endpoint property: " + properties.keySet().iterator().next());
    }
    return mirrors.values().stream().sorted(AppCatalogSourceStore::compareMirrors).toList();
  }

  private static Map<AppCatalogMirrorId, AppCatalogMirrorHealth> readHealth(Path directory)
      throws IOException {
    Path healthFile = directory.resolve(HEALTH_FILE_NAME);
    if (!Files.isRegularFile(healthFile, LinkOption.NOFOLLOW_LINKS)) {
      return Map.of();
    }
    Map<String, String> properties = readSidecar(healthFile, "catalog source health");
    validateSidecarVersion(properties.remove(HEALTH_VERSION_KEY), HEALTH_VERSION_KEY);
    LinkedHashMap<AppCatalogMirrorId, AppCatalogMirrorHealth> health = new LinkedHashMap<>();
    for (String idText : parseCommaList(removeRequired(properties, HEALTH_IDS_KEY))) {
      AppCatalogMirrorId id = AppCatalogMirrorId.parse(idText);
      String prefix = "health." + id.value() + ".";
      AppCatalogSourceRole role =
          AppCatalogSourceRole.parse(removeRequired(properties, prefix + "role"));
      AppCatalogFetchStatus status =
          AppCatalogFetchStatus.parse(removeRequired(properties, prefix + LAST_FETCH_STATUS_KEY));
      health.put(
          id,
          new AppCatalogMirrorHealth(
              id,
              role,
              status,
              removeOptional(properties, prefix + LAST_ATTEMPT_AT_KEY)
                  .map(value -> parseInstant(value, prefix + LAST_ATTEMPT_AT_KEY)),
              removeOptional(properties, prefix + LAST_SUCCESSFUL_REFRESH_AT_KEY)
                  .map(value -> parseInstant(value, prefix + LAST_SUCCESSFUL_REFRESH_AT_KEY)),
              removeOptional(properties, prefix + LAST_FETCH_ERROR_CODE_KEY),
              removeOptional(properties, prefix + LAST_FETCH_ERROR_MESSAGE_KEY),
              removeOptional(properties, prefix + LAST_RESOLVED_URI_KEY),
              removeOptional(properties, prefix + "lastCatalogDigest"),
              removeOptional(properties, prefix + "lastSignatureKeyId"),
              removeOptional(properties, prefix + HEALTH_LAST_GENERATED_AT_KEY)
                  .map(value -> parseInstant(value, prefix + HEALTH_LAST_GENERATED_AT_KEY))));
    }
    if (!properties.isEmpty()) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "unsupported catalog source health property: " + properties.keySet().iterator().next());
    }
    return Map.copyOf(health);
  }

  private static AppCatalogSourceRefreshMetadata parseRefreshMetadata(
      Map<String, String> properties, Instant refreshedAt, AppCatalogSource source) {
    Optional<String> lastAttemptAtText = removeOptional(properties, LAST_ATTEMPT_AT_KEY);
    Instant lastAttemptAt =
        lastAttemptAtText
            .map(value -> parseInstant(value, LAST_ATTEMPT_AT_KEY))
            .orElse(refreshedAt);
    Optional<String> lastSuccessfulRefreshAtText =
        removeOptional(properties, LAST_SUCCESSFUL_REFRESH_AT_KEY);
    Instant lastSuccessfulRefreshAt =
        lastSuccessfulRefreshAtText
            .map(value -> parseInstant(value, LAST_SUCCESSFUL_REFRESH_AT_KEY))
            .orElse(refreshedAt);
    AppCatalogFetchStatus lastFetchStatus =
        removeOptional(properties, LAST_FETCH_STATUS_KEY)
            .map(AppCatalogFetchStatus::parse)
            .orElse(AppCatalogFetchStatus.SUCCESS);
    Optional<String> errorCode = removeOptional(properties, LAST_FETCH_ERROR_CODE_KEY);
    Optional<String> errorMessage = removeOptional(properties, LAST_FETCH_ERROR_MESSAGE_KEY);
    Optional<String> lastResolvedUri =
        removeOptional(properties, LAST_RESOLVED_URI_KEY)
            .or(() -> Optional.of(source.resolvedCatalogFetchUri()));
    return new AppCatalogSourceRefreshMetadata(
        lastAttemptAt,
        lastSuccessfulRefreshAt,
        lastFetchStatus,
        errorCode,
        errorMessage,
        lastResolvedUri);
  }

  private static FetchedCatalog readFetchedCatalog(Path directory) throws IOException {
    return new FetchedCatalog(
        AppCatalogSidecars.readRequiredBytes(
            directory.resolve(AppCatalogSignature.CATALOG_FILE_NAME),
            AppCatalogSidecars.MAX_CATALOG_BYTES,
            "catalog properties",
            AppCatalogSidecars.INVALID_CATALOG_SOURCE),
        AppCatalogSidecars.readRequiredBytes(
            directory.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME),
            AppCatalogSidecars.MAX_SIGNATURE_BYTES,
            "catalog signature",
            AppCatalogSidecars.INVALID_CATALOG_SOURCE));
  }

  private static AppCatalogSource parseStoredSource(String rawUri) {
    try {
      return new AppCatalogSource(URI.create(rawUri));
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "invalid stored catalog source URI",
          exception);
    }
  }

  private Path catalogDirectory(String catalogId) {
    return rootDirectory.resolve(AppCatalog.normalizeCatalogId(catalogId));
  }

  private Path sourceFile(String catalogId) {
    return catalogDirectory(catalogId).resolve(SOURCE_FILE_NAME);
  }

  private static Map<String, String> readSourceMetadata(Path directory) throws IOException {
    return readSidecar(directory.resolve(SOURCE_FILE_NAME), "catalog source metadata");
  }

  private static Map<String, String> readSidecar(Path file, String description) throws IOException {
    try {
      return AppCatalogSidecars.parseKeyValueSidecar(
          AppCatalogSidecars.utf8(
              AppCatalogSidecars.readRequiredBytes(
                  file,
                  AppCatalogSidecars.MAX_SIGNATURE_BYTES,
                  description,
                  AppCatalogSidecars.INVALID_CATALOG_SOURCE)),
          description);
    } catch (AppCatalogException exception) {
      if (AppCatalogSidecars.INVALID_CATALOG_ENTRY.equals(exception.errorCode())) {
        throw new AppCatalogException(
            AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.getMessage(), exception);
      }
      throw exception;
    }
  }

  private static void writeSourceMetadata(Path directory, Path sourceFile, String content)
      throws IOException {
    Path tempFile = Files.createTempFile(directory, ".catalog-source-", ".tmp");
    boolean moved = false;
    try {
      Files.writeString(tempFile, content);
      moveReplacing(tempFile, sourceFile);
      moved = true;
    } finally {
      if (!moved) {
        Files.deleteIfExists(tempFile);
      }
    }
  }

  private static void moveReplacing(Path source, Path target) throws IOException {
    try {
      Files.move(
          source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static void cleanupIncompleteAdd(Path directory, IOException originalException) {
    try {
      AppCatalogBundleExtractor.deleteRecursively(directory);
    } catch (IOException cleanupException) {
      originalException.addSuppressed(cleanupException);
    }
  }

  @FunctionalInterface
  interface SourceMetadataWriter {
    void write(Path directory, Path sourceFile, String content) throws IOException;
  }

  record VerifiedCatalogWrite(
      AppCatalog catalog,
      AppCatalogSource source,
      FetchedCatalog fetchedCatalog,
      Instant addedAt,
      Instant refreshedAt) {}

  record EndpointWriteState(
      AppCatalogMirror selectedEndpoint,
      List<AppCatalogMirror> mirrors,
      Map<AppCatalogMirrorId, AppCatalogMirrorHealth> mirrorHealth) {}

  private static final class SourceStoreSnapshot {
    private final FetchedCatalog fetchedCatalog;
    private final SnapshotFile sourceMetadata;
    private final SnapshotFile endpointsMetadata;
    private final SnapshotFile healthMetadata;
    private final Path backupDirectory;
    private final Path historyBackup;

    private SourceStoreSnapshot(
        FetchedCatalog fetchedCatalog,
        SnapshotFile sourceMetadata,
        SnapshotFile endpointsMetadata,
        SnapshotFile healthMetadata,
        Path backupDirectory,
        Path historyBackup) {
      this.fetchedCatalog = fetchedCatalog;
      this.sourceMetadata = sourceMetadata;
      this.endpointsMetadata = endpointsMetadata;
      this.healthMetadata = healthMetadata;
      this.backupDirectory = backupDirectory;
      this.historyBackup = historyBackup;
    }

    private static SourceStoreSnapshot capture(Path directory) throws IOException {
      Path backupDirectory = Files.createTempDirectory(directory, ".catalog-source-snapshot-");
      try {
        Path historyBackup = snapshotHistory(directory, backupDirectory);
        return new SourceStoreSnapshot(
            readFetchedCatalog(directory),
            SnapshotFile.read(directory.resolve(SOURCE_FILE_NAME)),
            SnapshotFile.read(directory.resolve(ENDPOINTS_FILE_NAME)),
            SnapshotFile.read(directory.resolve(HEALTH_FILE_NAME)),
            backupDirectory,
            historyBackup);
      } catch (IOException exception) {
        cleanupBackup(backupDirectory, exception);
        throw exception;
      }
    }

    private static Path snapshotHistory(Path directory, Path backupDirectory) throws IOException {
      Path historyDirectory = directory.resolve(HISTORY_DIRECTORY_NAME);
      if (!Files.isDirectory(historyDirectory, LinkOption.NOFOLLOW_LINKS)) {
        return null;
      }
      Path historyBackup = backupDirectory.resolve(HISTORY_DIRECTORY_NAME);
      copyRecursively(historyDirectory, historyBackup);
      return historyBackup;
    }

    private void restore(Path directory, IOException originalException) {
      restoreFetchedCatalog(directory, originalException);
      restoreSnapshotFile(directory.resolve(SOURCE_FILE_NAME), sourceMetadata, originalException);
      restoreSnapshotFile(
          directory.resolve(ENDPOINTS_FILE_NAME), endpointsMetadata, originalException);
      restoreSnapshotFile(directory.resolve(HEALTH_FILE_NAME), healthMetadata, originalException);
      restoreHistory(directory, originalException);
    }

    private void restoreHistory(Path directory, IOException originalException) {
      Path historyDirectory = directory.resolve(HISTORY_DIRECTORY_NAME);
      try {
        AppCatalogBundleExtractor.deleteRecursively(historyDirectory);
        if (historyBackup != null) {
          copyRecursively(historyBackup, historyDirectory);
        }
      } catch (IOException restoreException) {
        originalException.addSuppressed(restoreException);
      }
    }

    private void cleanup() {
      cleanupBackup(backupDirectory, null);
    }

    private static void cleanupBackup(Path backupDirectory, IOException originalException) {
      try {
        AppCatalogBundleExtractor.deleteRecursively(backupDirectory);
      } catch (IOException cleanupException) {
        if (originalException != null) {
          originalException.addSuppressed(cleanupException);
        }
      }
    }

    private void restoreFetchedCatalog(Path directory, IOException originalException) {
      try {
        Files.write(
            directory.resolve(AppCatalogSignature.CATALOG_FILE_NAME),
            fetchedCatalog.catalogBytes());
        Files.write(
            directory.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME),
            fetchedCatalog.signatureBytes());
      } catch (IOException restoreException) {
        originalException.addSuppressed(restoreException);
      }
    }

    private static void restoreSnapshotFile(
        Path file, SnapshotFile snapshot, IOException originalException) {
      try {
        if (snapshot.present()) {
          Files.write(file, snapshot.content());
          return;
        }
        Files.deleteIfExists(file);
      } catch (IOException restoreException) {
        originalException.addSuppressed(restoreException);
      }
    }

    private static void copyRecursively(Path source, Path target) throws IOException {
      try (var stream = Files.walk(source)) {
        for (Path sourcePath :
            stream
                .sorted(Comparator.comparingInt(path -> source.relativize(path).getNameCount()))
                .toList()) {
          Path relativePath = source.relativize(sourcePath);
          Path targetPath = target.resolve(relativePath);
          if (Files.isDirectory(sourcePath, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectories(targetPath);
          } else {
            Path parent = targetPath.getParent();
            if (parent != null) {
              Files.createDirectories(parent);
            }
            Files.copy(
                sourcePath,
                targetPath,
                LinkOption.NOFOLLOW_LINKS,
                StandardCopyOption.REPLACE_EXISTING);
          }
        }
      }
    }

    private static final class SnapshotFile {
      private final boolean present;
      private final byte[] content;

      private SnapshotFile(boolean present, byte[] content) {
        this.present = present;
        this.content = content;
      }

      private static SnapshotFile missing() {
        return new SnapshotFile(false, new byte[0]);
      }

      private static SnapshotFile read(Path file) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
          return missing();
        }
        return new SnapshotFile(true, Files.readAllBytes(file));
      }

      private boolean present() {
        return present;
      }

      private byte[] content() {
        return content;
      }
    }
  }

  private static void validateSourceVersion(String versionText) {
    validateSidecarVersion(versionText, SOURCE_VERSION_KEY);
  }

  private static void validateSidecarVersion(String versionText, String versionKey) {
    if (!"1".equals(versionText)) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          versionText == null
              ? "missing " + versionKey
              : "unsupported " + versionKey + ": " + versionText);
    }
  }

  private static int parseNonNegativeInt(String value, String key) {
    try {
      int parsed = Integer.parseInt(value);
      if (parsed >= 0) {
        return parsed;
      }
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE, "invalid " + key + ": " + value, exception);
    }
    throw new AppCatalogException(
        AppCatalogSidecars.INVALID_CATALOG_SOURCE, key + " must be non-negative");
  }

  private static Instant parseInstant(String value, String key) {
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE, "invalid " + key + ": " + value, exception);
    }
  }

  private static String removeRequired(Map<String, String> properties, String key) {
    String value = properties.remove(key);
    if (value == null) {
      throw new AppCatalogException(AppCatalogSidecars.INVALID_CATALOG_SOURCE, "missing " + key);
    }
    return value;
  }

  private static Optional<String> removeOptional(Map<String, String> properties, String key) {
    return Optional.ofNullable(properties.remove(key));
  }

  private static List<String> parseCommaList(String value) {
    if (value == null || value.isBlank()) {
      return List.of();
    }
    List<String> values = new ArrayList<>();
    for (String token : value.split(",", -1)) {
      String trimmed = token.trim();
      if (!trimmed.isEmpty()) {
        values.add(trimmed);
      }
    }
    return List.copyOf(values);
  }

  private static String serializeSource(
      String catalogId,
      AppCatalogSource source,
      Instant addedAt,
      Instant refreshedAt,
      AppCatalogSourceRefreshMetadata refreshMetadata) {
    StringBuilder builder =
        new StringBuilder()
            .append(SOURCE_VERSION_KEY)
            .append("=1\n")
            .append(CATALOG_ID_KEY)
            .append('=')
            .append(catalogId)
            .append('\n')
            .append(SOURCE_URI_KEY)
            .append('=')
            .append(source.displayUri())
            .append('\n')
            .append(ADDED_AT_KEY)
            .append('=')
            .append(addedAt)
            .append('\n')
            .append(REFRESHED_AT_KEY)
            .append('=')
            .append(refreshedAt)
            .append('\n')
            .append(LAST_ATTEMPT_AT_KEY)
            .append('=')
            .append(refreshMetadata.lastAttemptAt())
            .append('\n')
            .append(LAST_SUCCESSFUL_REFRESH_AT_KEY)
            .append('=')
            .append(refreshMetadata.lastSuccessfulRefreshAt())
            .append('\n')
            .append(LAST_FETCH_STATUS_KEY)
            .append('=')
            .append(refreshMetadata.lastFetchStatus().metadataValue())
            .append('\n');
    refreshMetadata
        .lastFetchErrorCode()
        .ifPresent(value -> appendProperty(builder, LAST_FETCH_ERROR_CODE_KEY, value));
    refreshMetadata
        .lastFetchErrorMessage()
        .ifPresent(value -> appendProperty(builder, LAST_FETCH_ERROR_MESSAGE_KEY, value));
    refreshMetadata
        .lastResolvedUri()
        .ifPresent(value -> appendProperty(builder, LAST_RESOLVED_URI_KEY, value));
    return builder.toString();
  }

  private static void appendProperty(StringBuilder builder, String key, String value) {
    builder.append(key).append('=').append(value).append('\n');
  }

  private static void writeEndpoints(Path directory, List<AppCatalogMirror> mirrors)
      throws IOException {
    List<AppCatalogMirror> ordered =
        mirrors.stream().sorted(AppCatalogSourceStore::compareMirrors).toList();
    StringBuilder builder =
        new StringBuilder()
            .append(ENDPOINTS_VERSION_KEY)
            .append("=1\n")
            .append(ENDPOINT_IDS_KEY)
            .append('=');
    builder.append(String.join(",", ordered.stream().map(mirror -> mirror.id().value()).toList()));
    builder.append('\n');
    for (AppCatalogMirror mirror : ordered) {
      String prefix = "endpoint." + mirror.id().value() + ".";
      appendProperty(builder, prefix + "role", mirror.role().metadataValue());
      appendProperty(builder, prefix + SOURCE_URI_KEY, mirror.source().displayUri());
      appendProperty(builder, prefix + ENDPOINT_PRIORITY_KEY, Integer.toString(mirror.priority()));
      appendProperty(builder, prefix + "enabled", Boolean.toString(mirror.enabled()));
      appendProperty(builder, prefix + ADDED_AT_KEY, mirror.addedAt().toString());
    }
    writeStringAtomic(directory, directory.resolve(ENDPOINTS_FILE_NAME), builder.toString());
  }

  private static void writeHealth(
      Path directory, Map<AppCatalogMirrorId, AppCatalogMirrorHealth> mirrorHealth)
      throws IOException {
    List<AppCatalogMirrorHealth> ordered =
        mirrorHealth.values().stream()
            .sorted(Comparator.comparing(health -> health.id().value()))
            .toList();
    StringBuilder builder =
        new StringBuilder()
            .append(HEALTH_VERSION_KEY)
            .append("=1\n")
            .append(HEALTH_IDS_KEY)
            .append('=');
    builder.append(String.join(",", ordered.stream().map(health -> health.id().value()).toList()));
    builder.append('\n');
    for (AppCatalogMirrorHealth health : ordered) {
      String prefix = "health." + health.id().value() + ".";
      appendProperty(builder, prefix + "role", health.role().metadataValue());
      appendProperty(
          builder, prefix + LAST_FETCH_STATUS_KEY, health.lastFetchStatus().metadataValue());
      health
          .lastAttemptAt()
          .ifPresent(
              value -> appendProperty(builder, prefix + LAST_ATTEMPT_AT_KEY, value.toString()));
      health
          .lastSuccessfulRefreshAt()
          .ifPresent(
              value ->
                  appendProperty(
                      builder, prefix + LAST_SUCCESSFUL_REFRESH_AT_KEY, value.toString()));
      health
          .lastFetchErrorCode()
          .ifPresent(value -> appendProperty(builder, prefix + LAST_FETCH_ERROR_CODE_KEY, value));
      health
          .lastFetchErrorMessage()
          .ifPresent(
              value -> appendProperty(builder, prefix + LAST_FETCH_ERROR_MESSAGE_KEY, value));
      health
          .lastResolvedUri()
          .ifPresent(value -> appendProperty(builder, prefix + LAST_RESOLVED_URI_KEY, value));
      health
          .lastCatalogDigest()
          .ifPresent(value -> appendProperty(builder, prefix + "lastCatalogDigest", value));
      health
          .lastSignatureKeyId()
          .ifPresent(value -> appendProperty(builder, prefix + "lastSignatureKeyId", value));
      health
          .lastGeneratedAt()
          .ifPresent(
              value ->
                  appendProperty(builder, prefix + HEALTH_LAST_GENERATED_AT_KEY, value.toString()));
    }
    writeStringAtomic(directory, directory.resolve(HEALTH_FILE_NAME), builder.toString());
  }

  private static void writeStringAtomic(Path directory, Path target, String content)
      throws IOException {
    Path tempFile = Files.createTempFile(directory, "." + target.getFileName(), ".tmp");
    boolean moved = false;
    try {
      Files.writeString(tempFile, content);
      moveReplacing(tempFile, target);
      moved = true;
    } finally {
      if (!moved) {
        Files.deleteIfExists(tempFile);
      }
    }
  }

  private static int compareMirrors(AppCatalogMirror left, AppCatalogMirror right) {
    if (left.role() != right.role()) {
      return left.role() == AppCatalogSourceRole.PRIMARY ? -1 : 1;
    }
    int priorityComparison = Integer.compare(left.priority(), right.priority());
    if (priorityComparison != 0) {
      return priorityComparison;
    }
    return left.id().value().compareTo(right.id().value());
  }

  private void recordRevision(
      Path directory,
      AppCatalog catalog,
      FetchedCatalog fetchedCatalog,
      Instant verifiedAt,
      AppCatalogMirror selectedEndpoint,
      String resolvedUri)
      throws IOException {
    String digest = AppCatalogRevisions.catalogDigest(fetchedCatalog);
    Path revisionDirectory =
        Files.createDirectories(
            directory
                .resolve(HISTORY_DIRECTORY_NAME)
                .resolve(AppCatalogRevisions.digestDirectoryName(digest)));
    Files.write(
        revisionDirectory.resolve(AppCatalogSignature.CATALOG_FILE_NAME),
        fetchedCatalog.catalogBytes());
    Files.write(
        revisionDirectory.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME),
        fetchedCatalog.signatureBytes());
    writeStringAtomic(
        revisionDirectory,
        revisionDirectory.resolve(REVISION_FILE_NAME),
        serializeRevision(catalog, fetchedCatalog, verifiedAt, selectedEndpoint, resolvedUri));
    pruneRevisions(directory, digest);
  }

  private void pruneRevisions(Path directory, String currentDigest) throws IOException {
    List<AppCatalogVerifiedRevision> revisions =
        listRevisions(directory.getFileName().toString(), currentDigest);
    for (int index = REVISION_RETENTION_COUNT; index < revisions.size(); index++) {
      AppCatalogVerifiedRevision revision = revisions.get(index);
      if (revision.current()) {
        continue;
      }
      AppCatalogBundleExtractor.deleteRecursively(
          directory
              .resolve(HISTORY_DIRECTORY_NAME)
              .resolve(AppCatalogRevisions.digestDirectoryName(revision.revisionDigest())));
    }
  }

  private static String serializeRevision(
      AppCatalog catalog,
      FetchedCatalog fetchedCatalog,
      Instant verifiedAt,
      AppCatalogMirror selectedEndpoint,
      String resolvedUri) {
    StringBuilder builder =
        new StringBuilder()
            .append(REVISION_VERSION_KEY)
            .append("=1\n")
            .append(REVISION_DIGEST_KEY)
            .append('=')
            .append(AppCatalogRevisions.catalogDigest(fetchedCatalog))
            .append('\n');
    appendProperty(builder, CATALOG_ID_KEY, catalog.catalogId());
    appendProperty(builder, CATALOG_NAME_KEY, catalog.name());
    appendProperty(builder, REVISION_GENERATED_AT_KEY, catalog.generatedAt().toString());
    appendProperty(builder, REVISION_VERIFIED_AT_KEY, verifiedAt.toString());
    appendProperty(builder, REVISION_SOURCE_ID_KEY, selectedEndpoint.id().value());
    appendProperty(builder, REVISION_SOURCE_ROLE_KEY, selectedEndpoint.role().metadataValue());
    appendProperty(builder, REVISION_SOURCE_RESOLVED_URI_KEY, resolvedUri);
    appendProperty(builder, REVISION_SIGNATURE_KEY_ID_KEY, revisionSignatureKeyId(fetchedCatalog));
    appendProperty(
        builder,
        REVISION_SIGNATURE_DIGEST_KEY,
        AppCatalogRevisions.signatureDigest(fetchedCatalog));
    appendProperty(builder, REVISION_APP_COUNT_KEY, Integer.toString(catalog.entries().size()));
    appendProperty(
        builder,
        REVISION_ADVISORY_COUNT_KEY,
        Integer.toString(catalog.securityPolicy().advisories().size()));
    appendProperty(
        builder,
        REVISION_DENYLIST_COUNT_KEY,
        Integer.toString(catalog.securityPolicy().denylist().size()));
    appendProperty(builder, REVISION_CHANNELS_KEY, String.join(",", catalogChannels(catalog)));
    return builder.toString();
  }

  private static String revisionSignatureKeyId(FetchedCatalog fetchedCatalog) {
    try {
      return AppCatalogVerifier.readSignature(fetchedCatalog.signatureBytes()).keyId();
    } catch (AppCatalogException _) {
      return "unknown";
    }
  }

  private static List<String> catalogChannels(AppCatalog catalog) {
    LinkedHashSet<String> channels = new LinkedHashSet<>();
    catalog.entries().stream()
        .map(entry -> entry.productionMetadata().channel().catalogValue())
        .sorted()
        .forEach(channels::add);
    return List.copyOf(channels);
  }

  private static AppCatalogVerifiedRevision readRevisionMetadata(
      Path revisionDirectory, String currentDigest) throws IOException {
    Map<String, String> properties =
        readSidecar(revisionDirectory.resolve(REVISION_FILE_NAME), "catalog revision metadata");
    validateSidecarVersion(properties.remove(REVISION_VERSION_KEY), REVISION_VERSION_KEY);
    String digest = removeRequired(properties, REVISION_DIGEST_KEY);
    AppCatalogVerifiedRevision revision =
        new AppCatalogVerifiedRevision(
            digest,
            removeRequired(properties, CATALOG_ID_KEY),
            removeRequired(properties, CATALOG_NAME_KEY),
            parseInstant(
                removeRequired(properties, REVISION_GENERATED_AT_KEY), REVISION_GENERATED_AT_KEY),
            parseInstant(
                removeRequired(properties, REVISION_VERIFIED_AT_KEY), REVISION_VERIFIED_AT_KEY),
            AppCatalogMirrorId.parse(removeRequired(properties, REVISION_SOURCE_ID_KEY)),
            AppCatalogSourceRole.parse(removeRequired(properties, REVISION_SOURCE_ROLE_KEY)),
            removeOptional(properties, REVISION_SOURCE_RESOLVED_URI_KEY),
            removeRequired(properties, REVISION_SIGNATURE_KEY_ID_KEY),
            Integer.parseInt(removeRequired(properties, REVISION_APP_COUNT_KEY)),
            Integer.parseInt(removeRequired(properties, REVISION_ADVISORY_COUNT_KEY)),
            Integer.parseInt(removeRequired(properties, REVISION_DENYLIST_COUNT_KEY)),
            parseCommaList(removeRequired(properties, REVISION_CHANNELS_KEY)),
            digest.equals(currentDigest),
            removeOptional(properties, REVISION_SIGNATURE_DIGEST_KEY));
    if (!properties.isEmpty()) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "unsupported catalog revision property: " + properties.keySet().iterator().next());
    }
    return revision;
  }

  private static String resolvedCatalogUri(FetchedCatalog fetchedCatalog, AppCatalogSource source) {
    return fetchedCatalog.resolvedCatalogUri().orElseGet(source::resolvedCatalogFetchUri);
  }
}
