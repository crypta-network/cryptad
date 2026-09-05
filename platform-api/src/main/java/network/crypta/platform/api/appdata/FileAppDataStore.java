package network.crypta.platform.api.appdata;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Stream;

/**
 * File-backed app-data store under a host-managed app-platform data tree.
 *
 * <p>The default layout is {@code
 * <store-root>/<appId>/.cryptad-app-data/namespaces/<namespace>/...}. Namespace names are
 * normalized path-safe labels. Record keys are never used as path segments; the record directory is
 * the SHA-256 hash of the logical key and the key itself is stored only inside metadata. A record
 * write creates a complete generation directory and then atomically replaces the small pointer
 * file, so a crash cannot make an incomplete generation the current successful record.
 *
 * <p>Production callers should place {@code store-root} in host-managed app-platform storage, not
 * inside the {@code CRYPTAD_APP_DATA_DIR} tree writable by the app process. That keeps the daemon's
 * write and cleanup operations out of app-mutated directory ancestors while the Platform API still
 * enforces app scoping, data quotas, and explicit preserve-data uninstall semantics.
 *
 * <p>The store treats filesystem failures differently from malformed app-owned metadata. Missing or
 * semantically invalid record metadata is ignored so one bad record does not make the whole app
 * unreadable. I/O failures, unreadable valid files, and quota-relevant scan failures propagate as
 * {@link IOException}, allowing {@link AppDataService} to return the stable {@code
 * app_data_store_unavailable} error instead of pretending data was deleted.
 *
 * <p>Reads are bounded before value bytes are loaded. Summary routes use metadata-only reads, and
 * direct value reads verify expected length and SHA-256 metadata before returning a record. On
 * platforms with {@link SecureDirectoryStream}, value reads use no-follow directory handles;
 * providers without that support fall back to repeated no-follow path validation and bounded
 * channel reads.
 */
public final class FileAppDataStore implements AppDataStore {
  private static final String STORE_DIRECTORY = ".cryptad-app-data";
  private static final String NAMESPACES_DIRECTORY = "namespaces";
  private static final String RECORDS_DIRECTORY = "records";
  private static final String GENERATIONS_DIRECTORY = "generations";
  private static final String METADATA_FILE = "metadata.properties";
  private static final String RECORD_FILE = "record.properties";
  private static final String VALUE_FILE = "value.bin";
  private static final String CURRENT_FILE = "current.properties";
  private static final String KEY_VERSION = "version";
  private static final String KEY_APP_ID = "appId";
  private static final String KEY_NAMESPACE = "namespace";
  private static final String KEY_SCHEMA_VERSION = "schemaVersion";
  private static final String KEY_CREATED_AT = "createdAt";
  private static final String KEY_UPDATED_AT = "updatedAt";
  private static final String KEY_MIGRATION_COUNT = "migration.count";
  private static final String KEY_MIGRATION_PREFIX = "migration.";
  private static final String KEY_FROM_SCHEMA_VERSION = ".fromSchemaVersion";
  private static final String KEY_TO_SCHEMA_VERSION = ".toSchemaVersion";
  private static final String KEY_SUMMARY = ".summary";
  private static final String KEY_MIGRATED_AT = ".migratedAt";
  private static final String KEY_KEY = "key";
  private static final String KEY_CONTENT_TYPE = "contentType";
  private static final String KEY_VALUE_BYTES = "valueBytes";
  private static final String KEY_SHA_256 = "sha256";
  private static final String KEY_GENERATION = "generation";
  private static final HexFormat HEX = HexFormat.of();
  private static final int MAX_PROPERTIES_FILE_BYTES = 65_536;

  private final Path appDataRoot;
  private final int maxRecordBytes;
  private final boolean forcePlainPathReadFallback;

  private record StoredRecordMetadata(String appId, AppDataRecordSummary summary, Path valueFile) {}

  /**
   * Creates a file store below the supplied host-managed root.
   *
   * <p>The default configuration applies the built-in app-data limits. Runtime composition should
   * pass a node-specific root owned by the daemon, such as the HTTP bridge's durable app-data
   * directory under the AppHost data tree.
   *
   * @param appDataRoot host-managed durable app-data store root
   */
  public FileAppDataStore(Path appDataRoot) {
    this(appDataRoot, AppDataStoreConfig.defaults());
  }

  /**
   * Creates a file store below the supplied host-managed root using the supplied host limits.
   *
   * <p>The store uses {@link AppDataStoreConfig#maxRecordBytes()} on read as well as write paths so
   * app-writable or corrupt files cannot bypass the bounded-record contract.
   *
   * @param appDataRoot host-managed durable app-data store root
   * @param config positive app-data store limits
   */
  public FileAppDataStore(Path appDataRoot, AppDataStoreConfig config) {
    this(appDataRoot, config, false);
  }

  /**
   * Creates a file store with an explicit read-path strategy for tests.
   *
   * <p>The production constructors leave secure-directory-stream support enabled when the
   * filesystem provider offers it. Focused tests can force the plain-path fallback to verify the
   * bounded read behavior used on providers without {@link SecureDirectoryStream} support.
   *
   * @param appDataRoot host-managed durable app-data store root
   * @param config positive app-data store limits
   * @param forcePlainPathReadFallback whether value reads should skip secure directory streams
   */
  FileAppDataStore(
      Path appDataRoot, AppDataStoreConfig config, boolean forcePlainPathReadFallback) {
    this.appDataRoot =
        Objects.requireNonNull(appDataRoot, "appDataRoot").toAbsolutePath().normalize();
    maxRecordBytes = Objects.requireNonNull(config, "config").maxRecordBytes();
    this.forcePlainPathReadFallback = forcePlainPathReadFallback;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The file implementation discovers app ids from first-level managed directories. It reports
   * only path-safe ids whose store subtree is present and not a symlink, so all-app backup can
   * include preserved app-data state without exposing host filesystem paths or following
   * caller-controlled links.
   */
  @Override
  public synchronized List<String> listAppIds() throws IOException {
    if (directoryMissingOrHasSymlinkAncestor(appDataRoot)) {
      return List.of();
    }
    ArrayList<String> appIds = new ArrayList<>();
    try (Stream<Path> stream = Files.list(existingManagedRootRealPath().orElseThrow())) {
      for (Path path : sortedDirectories(stream)) {
        String directoryName = path.getFileName().toString();
        try {
          String appId = AppDataRecord.normalizeAppId(directoryName);
          if (appId.equals(directoryName)
              && !directoryMissingOrHasSymlinkAncestor(appStoreDirectory(appId))) {
            appIds.add(appId);
          }
        } catch (RuntimeException _) {
          // Ignore malformed app-id directories; they are outside the app-data contract.
        }
      }
    }
    appIds.sort(Comparator.naturalOrder());
    return Collections.unmodifiableList(appIds);
  }

  /**
   * {@inheritDoc}
   *
   * <p>The file implementation derives record counts, byte totals, and effective update timestamps
   * from record summaries without reading record values.
   */
  @Override
  public synchronized List<AppDataNamespaceMetadata> listNamespaces(String appId)
      throws IOException {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    Path namespacesDirectory = namespacesDirectory(normalizedAppId);
    if (directoryMissingOrHasSymlinkAncestor(namespacesDirectory)) {
      return List.of();
    }
    ArrayList<AppDataNamespaceMetadata> namespaces = new ArrayList<>();
    try (Stream<Path> stream = Files.list(namespacesDirectory)) {
      for (Path path : sortedDirectories(stream)) {
        Optional<AppDataNamespaceMetadata> metadata =
            readNamespaceFile(path.resolve(METADATA_FILE), normalizedAppId);
        if (metadata.isPresent()) {
          namespaces.add(withDerivedTotals(metadata.get()));
        }
      }
    }
    return namespaces;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned metadata includes derived totals from current record summaries. Invalid
   * namespace metadata is treated as absent, while I/O failures propagate to the service layer.
   */
  @Override
  public synchronized Optional<AppDataNamespaceMetadata> readNamespace(
      String appId, String namespace) throws IOException {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace = AppDataRecord.normalizeNamespace(namespace);
    Optional<AppDataNamespaceMetadata> metadata =
        readNamespaceFile(
            namespaceDirectory(normalizedAppId, normalizedNamespace).resolve(METADATA_FILE),
            normalizedAppId);
    return metadata.isEmpty() ? Optional.empty() : Optional.of(withDerivedTotals(metadata.get()));
  }

  /**
   * {@inheritDoc}
   *
   * <p>Namespace metadata is written through a temporary properties file in the namespace directory
   * and then moved into place. The directory creation path validates each managed ancestor without
   * following symlinks below the configured store root.
   */
  @Override
  public synchronized void writeNamespace(AppDataNamespaceMetadata metadata) throws IOException {
    Path namespaceDirectory = namespaceDirectory(metadata.appId(), metadata.namespace());
    ensureDirectory(namespaceDirectory);
    Properties properties = new Properties();
    properties.setProperty(KEY_VERSION, "1");
    properties.setProperty(KEY_APP_ID, metadata.appId());
    properties.setProperty(KEY_NAMESPACE, metadata.namespace());
    properties.setProperty(KEY_SCHEMA_VERSION, Integer.toString(metadata.schemaVersion()));
    properties.setProperty(KEY_CREATED_AT, metadata.createdAt().toString());
    properties.setProperty(KEY_UPDATED_AT, metadata.updatedAt().toString());
    properties.setProperty(
        KEY_MIGRATION_COUNT, Integer.toString(metadata.migrationHistory().size()));
    for (int index = 0; index < metadata.migrationHistory().size(); index++) {
      AppDataMigrationRecord migration = metadata.migrationHistory().get(index);
      String prefix = KEY_MIGRATION_PREFIX + index;
      properties.setProperty(
          prefix + KEY_FROM_SCHEMA_VERSION, Integer.toString(migration.fromSchemaVersion()));
      properties.setProperty(
          prefix + KEY_TO_SCHEMA_VERSION, Integer.toString(migration.toSchemaVersion()));
      properties.setProperty(prefix + KEY_SUMMARY, migration.summary());
      properties.setProperty(prefix + KEY_MIGRATED_AT, migration.migratedAt().toString());
    }
    writePropertiesAtomically(
        namespaceDirectory.resolve(METADATA_FILE),
        properties,
        "Cryptad app-data namespace metadata");
  }

  /**
   * {@inheritDoc}
   *
   * <p>This method materializes values and should be reserved for read/export paths that need full
   * records. Summary endpoints use {@link #listRecordSummaries(String, String)} to avoid loading
   * every value.
   */
  @Override
  public synchronized List<AppDataRecord> listRecords(String appId, String namespace)
      throws IOException {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace =
        namespace == null ? null : AppDataRecord.normalizeNamespace(namespace);
    if (normalizedNamespace != null) {
      return listRecordsInNamespace(normalizedAppId, normalizedNamespace);
    }
    Path namespacesDirectory = namespacesDirectory(normalizedAppId);
    if (directoryMissingOrHasSymlinkAncestor(namespacesDirectory)) {
      return List.of();
    }
    ArrayList<AppDataRecord> records = new ArrayList<>();
    try (Stream<Path> stream = Files.list(namespacesDirectory)) {
      for (Path path : sortedDirectories(stream)) {
        records.addAll(
            listRecordsInNamespaceIfValid(normalizedAppId, path.getFileName().toString()));
      }
    }
    records.sort(Comparator.comparing(AppDataRecord::namespace).thenComparing(AppDataRecord::key));
    return Collections.unmodifiableList(records);
  }

  /**
   * {@inheritDoc}
   *
   * <p>Summaries are reconstructed from the current generation's metadata and value file size. The
   * value bytes are not read, but metadata still verifies the current pointer, generation
   * directory, expected file length, and app/namespace/key scope.
   */
  @Override
  public synchronized List<AppDataRecordSummary> listRecordSummaries(String appId, String namespace)
      throws IOException {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace =
        namespace == null ? null : AppDataRecord.normalizeNamespace(namespace);
    if (normalizedNamespace != null) {
      return listRecordSummariesInNamespace(normalizedAppId, normalizedNamespace);
    }
    Path namespacesDirectory = namespacesDirectory(normalizedAppId);
    if (directoryMissingOrHasSymlinkAncestor(namespacesDirectory)) {
      return List.of();
    }
    ArrayList<AppDataRecordSummary> summaries = new ArrayList<>();
    try (Stream<Path> stream = Files.list(namespacesDirectory)) {
      for (Path path : sortedDirectories(stream)) {
        summaries.addAll(
            listRecordSummariesInNamespaceIfValid(normalizedAppId, path.getFileName().toString()));
      }
    }
    summaries.sort(
        Comparator.comparing(AppDataRecordSummary::namespace)
            .thenComparing(AppDataRecordSummary::key));
    return Collections.unmodifiableList(summaries);
  }

  /**
   * {@inheritDoc}
   *
   * <p>The logical key is hashed to find the record directory. The stored key from metadata must
   * still match the normalized requested key before a value is returned.
   */
  @Override
  public synchronized Optional<AppDataRecord> readRecord(String appId, String namespace, String key)
      throws IOException {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace = AppDataRecord.normalizeNamespace(namespace);
    String normalizedKey = AppDataRecord.normalizeKey(key);
    return readRecordDirectory(
        recordDirectory(normalizedAppId, normalizedNamespace, normalizedKey),
        normalizedAppId,
        normalizedNamespace,
        normalizedKey);
  }

  /**
   * {@inheritDoc}
   *
   * <p>A writing creates or updates a content-addressed generation directory containing value bytes
   * and record metadata, then atomically replaces the current-pointer properties file. Older
   * generations become unreachable and are pruned best-effort after the pointer is published.
   */
  @Override
  public synchronized void writeRecord(AppDataRecord appDataRecord) throws IOException {
    Path recordDirectory =
        recordDirectory(appDataRecord.appId(), appDataRecord.namespace(), appDataRecord.key());
    Path generationsDirectory = recordDirectory.resolve(GENERATIONS_DIRECTORY);
    ensureDirectory(generationsDirectory);
    String generation = generationId(appDataRecord);
    Path generationDirectory = generationsDirectory.resolve(generation);
    ensureDirectory(generationDirectory);
    writeBytesAtomically(generationDirectory.resolve(VALUE_FILE), appDataRecord.value());
    Properties recordProperties = new Properties();
    recordProperties.setProperty(KEY_VERSION, "1");
    recordProperties.setProperty(KEY_APP_ID, appDataRecord.appId());
    recordProperties.setProperty(KEY_NAMESPACE, appDataRecord.namespace());
    recordProperties.setProperty(KEY_KEY, appDataRecord.key());
    recordProperties.setProperty(KEY_CONTENT_TYPE, appDataRecord.contentType());
    recordProperties.setProperty(
        KEY_SCHEMA_VERSION, Integer.toString(appDataRecord.schemaVersion()));
    recordProperties.setProperty(KEY_VALUE_BYTES, Integer.toString(appDataRecord.valueBytes()));
    recordProperties.setProperty(KEY_SHA_256, appDataRecord.sha256());
    recordProperties.setProperty(KEY_CREATED_AT, appDataRecord.createdAt().toString());
    recordProperties.setProperty(KEY_UPDATED_AT, appDataRecord.updatedAt().toString());
    writePropertiesAtomically(
        generationDirectory.resolve(RECORD_FILE),
        recordProperties,
        "Cryptad app-data record metadata");

    Properties current = new Properties();
    current.setProperty(KEY_VERSION, "1");
    current.setProperty(KEY_APP_ID, appDataRecord.appId());
    current.setProperty(KEY_NAMESPACE, appDataRecord.namespace());
    current.setProperty(KEY_KEY, appDataRecord.key());
    current.setProperty(KEY_GENERATION, generation);
    writePropertiesAtomically(
        recordDirectory.resolve(CURRENT_FILE), current, "Cryptad app-data current record pointer");
    pruneOldGenerations(generationsDirectory, generation);
  }

  /**
   * {@inheritDoc}
   *
   * <p>The target directory is derived from normalized app, namespace, and key values. Deletion is
   * scoped to the managed app-data tree and returns whether a record directory existed before
   * cleanup.
   */
  @Override
  public synchronized boolean deleteRecord(String appId, String namespace, String key)
      throws IOException {
    Path recordDirectory =
        recordDirectory(
            AppDataRecord.normalizeAppId(appId),
            AppDataRecord.normalizeNamespace(namespace),
            AppDataRecord.normalizeKey(key));
    boolean existed = Files.exists(recordDirectory, LinkOption.NOFOLLOW_LINKS);
    deleteTree(recordDirectory);
    return existed;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The namespace path is derived from normalized identifiers and contains only metadata and
   * hashed record directories owned by the app.
   */
  @Override
  public synchronized void deleteNamespace(String appId, String namespace) throws IOException {
    deleteTree(
        namespaceDirectory(
            AppDataRecord.normalizeAppId(appId), AppDataRecord.normalizeNamespace(namespace)));
  }

  /**
   * {@inheritDoc}
   *
   * <p>This removes the store subtree for one normalized app id. It is used by uninstall cleanup
   * when the operator does not preserve app data.
   */
  @Override
  public synchronized void deleteAllForApp(String appId) throws IOException {
    deleteTree(appStoreDirectory(AppDataRecord.normalizeAppId(appId)));
  }

  private List<AppDataRecord> listRecordsInNamespace(String appId, String namespace)
      throws IOException {
    Path recordsDirectory = recordsDirectory(appId, namespace);
    if (directoryMissingOrHasSymlinkAncestor(recordsDirectory)) {
      return List.of();
    }
    ArrayList<AppDataRecord> records = new ArrayList<>();
    try (Stream<Path> stream = Files.list(recordsDirectory)) {
      for (Path path : sortedDirectories(stream)) {
        Optional<AppDataRecord> maybeRecord = readRecordDirectory(path, appId, namespace, null);
        maybeRecord.ifPresent(records::add);
      }
    }
    records.sort(Comparator.comparing(AppDataRecord::key));
    return Collections.unmodifiableList(records);
  }

  private List<AppDataRecordSummary> listRecordSummariesInNamespace(String appId, String namespace)
      throws IOException {
    Path recordsDirectory = recordsDirectory(appId, namespace);
    if (directoryMissingOrHasSymlinkAncestor(recordsDirectory)) {
      return List.of();
    }
    ArrayList<AppDataRecordSummary> summaries = new ArrayList<>();
    try (Stream<Path> stream = Files.list(recordsDirectory)) {
      for (Path path : sortedDirectories(stream)) {
        Optional<AppDataRecordSummary> summary = readRecordSummaryDirectory(path, appId, namespace);
        summary.ifPresent(summaries::add);
      }
    }
    summaries.sort(Comparator.comparing(AppDataRecordSummary::key));
    return Collections.unmodifiableList(summaries);
  }

  private List<AppDataRecord> listRecordsInNamespaceIfValid(String appId, String namespace)
      throws IOException {
    try {
      return listRecordsInNamespace(appId, AppDataRecord.normalizeNamespace(namespace));
    } catch (RuntimeException _) {
      return List.of();
    }
  }

  private List<AppDataRecordSummary> listRecordSummariesInNamespaceIfValid(
      String appId, String namespace) throws IOException {
    try {
      return listRecordSummariesInNamespace(appId, AppDataRecord.normalizeNamespace(namespace));
    } catch (RuntimeException _) {
      return List.of();
    }
  }

  private static List<Path> sortedDirectories(Stream<Path> stream) throws IOException {
    ArrayList<Path> directories = new ArrayList<>();
    for (Path path :
        stream.sorted(Comparator.comparing(path -> path.getFileName().toString())).toList()) {
      if (isExistingDirectory(path)) {
        directories.add(path);
      }
    }
    return directories;
  }

  private Optional<AppDataNamespaceMetadata> readNamespaceFile(Path file, String expectedAppId)
      throws IOException {
    Properties properties = readProperties(file).orElse(null);
    if (properties == null) {
      return Optional.empty();
    }
    try {
      if (!"1".equals(properties.getProperty(KEY_VERSION))) {
        return Optional.empty();
      }
      String appId = properties.getProperty(KEY_APP_ID);
      if (!expectedAppId.equals(AppDataRecord.normalizeAppId(appId))) {
        return Optional.empty();
      }
      String namespace = properties.getProperty(KEY_NAMESPACE);
      int schemaVersion = positiveInt(properties.getProperty(KEY_SCHEMA_VERSION));
      Instant createdAt = instant(properties.getProperty(KEY_CREATED_AT));
      Instant updatedAt = instant(properties.getProperty(KEY_UPDATED_AT));
      List<AppDataMigrationRecord> migrations = migrations(properties);
      Instant lastMigrationAt = migrations.isEmpty() ? null : migrations.getLast().migratedAt();
      return Optional.of(
          new AppDataNamespaceMetadata(
              appId,
              namespace,
              schemaVersion,
              0,
              0L,
              createdAt,
              updatedAt,
              lastMigrationAt,
              migrations));
    } catch (RuntimeException _) {
      return Optional.empty();
    }
  }

  private Optional<AppDataRecord> readRecordDirectory(
      Path recordDirectory, String expectedAppId, String expectedNamespace, String expectedKey)
      throws IOException {
    try {
      StoredRecordMetadata metadata =
          readRecordMetadata(recordDirectory, expectedAppId, expectedNamespace, expectedKey)
              .orElse(null);
      if (metadata == null) {
        return Optional.empty();
      }
      byte[] value =
          readBoundedValue(metadata.valueFile(), metadata.summary().valueBytes()).orElse(null);
      if (value == null) {
        throw valueFileUnavailable();
      }
      AppDataRecord appDataRecord =
          new AppDataRecord(
              metadata.appId(),
              metadata.summary().namespace(),
              metadata.summary().key(),
              new AppDataRecord.Payload(
                  metadata.summary().contentType(), metadata.summary().schemaVersion(), value),
              metadata.summary().createdAt(),
              metadata.summary().updatedAt());
      if (appDataRecord.valueBytes() != metadata.summary().valueBytes()) {
        throw valueFileUnavailable();
      }
      if (!appDataRecord.sha256().equals(metadata.summary().sha256())) {
        throw valueFileUnavailable();
      }
      return Optional.of(appDataRecord);
    } catch (RuntimeException _) {
      return Optional.empty();
    }
  }

  private Optional<AppDataRecordSummary> readRecordSummaryDirectory(
      Path recordDirectory, String expectedAppId, String expectedNamespace) throws IOException {
    return readRecordMetadata(recordDirectory, expectedAppId, expectedNamespace, null)
        .map(StoredRecordMetadata::summary);
  }

  private Optional<StoredRecordMetadata> readRecordMetadata(
      Path recordDirectory, String expectedAppId, String expectedNamespace, String expectedKey)
      throws IOException {
    try {
      if (directoryMissingOrHasSymlinkAncestor(recordDirectory)) {
        return Optional.empty();
      }
      Properties current = readProperties(recordDirectory.resolve(CURRENT_FILE)).orElse(null);
      if (current == null || !"1".equals(current.getProperty(KEY_VERSION))) {
        return Optional.empty();
      }
      String generation = AppDataRecord.normalizeKey(current.getProperty(KEY_GENERATION));
      Path generationsDirectory = recordDirectory.resolve(GENERATIONS_DIRECTORY).normalize();
      Path generationDirectory = generationsDirectory.resolve(generation).normalize();
      if (!generationDirectory.startsWith(generationsDirectory)) {
        return Optional.empty();
      }
      Properties properties = readProperties(generationDirectory.resolve(RECORD_FILE)).orElse(null);
      if (properties == null || !"1".equals(properties.getProperty(KEY_VERSION))) {
        return Optional.empty();
      }
      String appId = AppDataRecord.normalizeAppId(properties.getProperty(KEY_APP_ID));
      if (!expectedAppId.equals(appId)) {
        return Optional.empty();
      }
      int valueBytes = nonNegativeInt(properties.getProperty(KEY_VALUE_BYTES));
      if (valueBytes > maxRecordBytes) {
        return Optional.empty();
      }
      AppDataRecordSummary summary =
          new AppDataRecordSummary(
              properties.getProperty(KEY_NAMESPACE),
              properties.getProperty(KEY_KEY),
              properties.getProperty(KEY_CONTENT_TYPE),
              positiveInt(properties.getProperty(KEY_SCHEMA_VERSION)),
              valueBytes,
              properties.getProperty(KEY_SHA_256),
              instant(properties.getProperty(KEY_CREATED_AT)),
              instant(properties.getProperty(KEY_UPDATED_AT)));
      if (!expectedNamespace.equals(summary.namespace())) {
        return Optional.empty();
      }
      if (expectedKey != null && !expectedKey.equals(summary.key())) {
        return Optional.empty();
      }
      Path valueFile = generationDirectory.resolve(VALUE_FILE);
      validateCurrentValueFile(valueFile, valueBytes);
      return Optional.of(new StoredRecordMetadata(appId, summary, valueFile));
    } catch (RuntimeException _) {
      return Optional.empty();
    }
  }

  private void validateCurrentValueFile(Path valueFile, int expectedBytes) throws IOException {
    if (regularFileMissingOrHasSymlinkAncestor(valueFile)) {
      throw valueFileUnavailable();
    }
    long fileBytes = fileSizeNoFollow(valueFile);
    if (fileBytes > maxRecordBytes || fileBytes != expectedBytes) {
      throw valueFileUnavailable();
    }
  }

  private static IOException valueFileUnavailable() {
    return new IOException("app-data value file is unavailable");
  }

  private Optional<byte[]> readBoundedValue(Path valueFile, int expectedBytes) throws IOException {
    if (expectedBytes > maxRecordBytes) {
      return Optional.empty();
    }
    Optional<Path> root = existingManagedRootRealPath();
    if (root.isEmpty()) {
      return Optional.empty();
    }
    Path relative = managedRelativePath(valueFile);
    if (!forcePlainPathReadFallback) {
      try (DirectoryStream<Path> rootStream = Files.newDirectoryStream(root.get())) {
        if (rootStream instanceof SecureDirectoryStream<?>) {
          return readBoundedValueFromSecureDirectory(
              secureDirectoryStream(rootStream), relative, expectedBytes);
        }
      }
    }
    return readBoundedValueFromPlainPath(valueFile, expectedBytes);
  }

  private static SecureDirectoryStream<Path> secureDirectoryStream(DirectoryStream<Path> stream) {
    return (SecureDirectoryStream<Path>) stream;
  }

  private static Optional<byte[]> readBoundedValueFromSecureDirectory(
      SecureDirectoryStream<Path> directory, Path relative, int expectedBytes) throws IOException {
    int nameCount = relative.getNameCount();
    if (nameCount == 0) {
      return Optional.empty();
    }
    if (nameCount == 1) {
      return readBoundedValueFile(directory, relative.getFileName(), expectedBytes);
    }
    try (SecureDirectoryStream<Path> childDirectory =
        directory.newDirectoryStream(relative.getName(0), LinkOption.NOFOLLOW_LINKS)) {
      return readBoundedValueFromSecureDirectory(
          childDirectory, relative.subpath(1, nameCount), expectedBytes);
    }
  }

  private static Optional<byte[]> readBoundedValueFile(
      SecureDirectoryStream<Path> directory, Path fileName, int expectedBytes) throws IOException {
    Set<OpenOption> options = Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
    try (SeekableByteChannel channel = directory.newByteChannel(fileName, options)) {
      return readBoundedValueChannel(channel, expectedBytes);
    }
  }

  private Optional<byte[]> readBoundedValueFromPlainPath(Path valueFile, int expectedBytes)
      throws IOException {
    return readBoundedPlainPathFile(valueFile, expectedBytes);
  }

  private Optional<byte[]> readBoundedPlainPathFile(Path valueFile, int expectedBytes)
      throws IOException {
    Optional<Path> managedFile = existingManagedPath(valueFile);
    if (managedFile.isEmpty() || regularFileMissingOrHasSymlinkAncestor(valueFile)) {
      return Optional.empty();
    }
    Set<OpenOption> options = Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
    try (SeekableByteChannel channel = FileChannel.open(managedFile.get(), options)) {
      Optional<byte[]> value = readBoundedValueChannel(channel, expectedBytes);
      if (value.isEmpty()) {
        return Optional.empty();
      }
      if (regularFileMissingOrHasSymlinkAncestor(valueFile)
          || fileSizeNoFollow(managedFile.get()) != expectedBytes) {
        return Optional.empty();
      }
      return value;
    }
  }

  private static Optional<byte[]> readBoundedValueChannel(
      SeekableByteChannel channel, int expectedBytes) throws IOException {
    if (channel.size() != expectedBytes) {
      return Optional.empty();
    }
    byte[] value = new byte[expectedBytes];
    ByteBuffer buffer = ByteBuffer.wrap(value);
    while (buffer.hasRemaining()) {
      if (channel.read(buffer) < 0) {
        return Optional.empty();
      }
    }
    ByteBuffer extraByte = ByteBuffer.allocate(1);
    if (channel.read(extraByte) != -1) {
      return Optional.empty();
    }
    return Optional.of(value);
  }

  private Optional<Properties> readProperties(Path file) throws IOException {
    Properties properties = new Properties();
    if (regularFileMissingOrHasSymlinkAncestor(file)) {
      return Optional.empty();
    }
    long propertiesBytes = fileSizeNoFollow(file);
    if (propertiesBytes > MAX_PROPERTIES_FILE_BYTES) {
      return Optional.empty();
    }
    Optional<byte[]> bytes = readBoundedPlainPathFile(file, (int) propertiesBytes);
    if (bytes.isEmpty()) {
      return Optional.empty();
    }
    try (Reader reader =
        new java.io.StringReader(new String(bytes.get(), StandardCharsets.UTF_8))) {
      properties.load(reader);
      return Optional.of(properties);
    } catch (IllegalArgumentException _) {
      return Optional.empty();
    }
  }

  private AppDataNamespaceMetadata withDerivedTotals(AppDataNamespaceMetadata metadata)
      throws IOException {
    List<AppDataRecordSummary> namespaceRecords =
        listRecordSummaries(metadata.appId(), metadata.namespace());
    long totalBytes = namespaceRecords.stream().mapToLong(AppDataRecordSummary::valueBytes).sum();
    Instant updatedAt = metadata.updatedAt();
    for (AppDataRecordSummary recordSummary : namespaceRecords) {
      if (recordSummary.updatedAt().isAfter(updatedAt)) {
        updatedAt = recordSummary.updatedAt();
      }
    }
    return metadata.withTotals(namespaceRecords.size(), totalBytes, updatedAt);
  }

  private Path appStoreDirectory(String appId) {
    return appDataRoot.resolve(AppDataRecord.normalizeAppId(appId)).resolve(STORE_DIRECTORY);
  }

  private Path namespacesDirectory(String appId) {
    return appStoreDirectory(appId).resolve(NAMESPACES_DIRECTORY);
  }

  private Path namespaceDirectory(String appId, String namespace) {
    return namespacesDirectory(appId).resolve(AppDataRecord.normalizeNamespace(namespace));
  }

  private Path recordsDirectory(String appId, String namespace) {
    return namespaceDirectory(appId, namespace).resolve(RECORDS_DIRECTORY);
  }

  private Path recordDirectory(String appId, String namespace, String key) {
    String hashedKey =
        HEX.formatHex(
            sha256Bytes(AppDataRecord.normalizeKey(key).getBytes(StandardCharsets.UTF_8)));
    return recordsDirectory(appId, namespace).resolve(hashedKey);
  }

  private static String generationId(AppDataRecord appDataRecord) {
    String input =
        appDataRecord.key()
            + "\n"
            + appDataRecord.contentType()
            + "\n"
            + appDataRecord.schemaVersion()
            + "\n"
            + appDataRecord.updatedAt()
            + "\n"
            + appDataRecord.sha256();
    return "g-"
        + HEX.formatHex(sha256Bytes(input.getBytes(StandardCharsets.UTF_8))).substring(0, 40);
  }

  private static byte[] sha256Bytes(byte[] bytes) {
    try {
      return java.security.MessageDigest.getInstance("SHA-256").digest(bytes);
    } catch (java.security.NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static List<AppDataMigrationRecord> migrations(Properties properties) {
    int count = nonNegativeInt(properties.getProperty(KEY_MIGRATION_COUNT));
    java.util.ArrayList<AppDataMigrationRecord> migrations = new java.util.ArrayList<>();
    for (int index = 0; index < count; index++) {
      String prefix = KEY_MIGRATION_PREFIX + index;
      migrations.add(
          new AppDataMigrationRecord(
              positiveInt(properties.getProperty(prefix + KEY_FROM_SCHEMA_VERSION)),
              positiveInt(properties.getProperty(prefix + KEY_TO_SCHEMA_VERSION)),
              properties.getProperty(prefix + KEY_SUMMARY, ""),
              instant(properties.getProperty(prefix + KEY_MIGRATED_AT))));
    }
    return List.copyOf(migrations);
  }

  private void ensureDirectory(Path directory) throws IOException {
    Path relative = managedRelativePath(directory);
    Path current = ensureManagedRootRealPath();
    for (Path segment : relative) {
      current = current.resolve(segment);
      ensureSingleDirectory(current);
    }
    if (!isExistingDirectory(current)) {
      throw new IOException("managed app-data directory is unavailable");
    }
  }

  private static void ensureSingleDirectory(Path directory) throws IOException {
    if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
      if (Files.isSymbolicLink(directory)
          || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
        throw new IOException("managed app-data directory is unavailable");
      }
      return;
    }
    try {
      Files.createDirectory(directory);
    } catch (FileAlreadyExistsException _) {
      if (Files.isSymbolicLink(directory)
          || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
        throw new IOException("managed app-data directory is unavailable");
      }
    }
  }

  private boolean directoryMissingOrHasSymlinkAncestor(Path directory) throws IOException {
    Optional<Path> root = existingManagedRootRealPath();
    if (root.isEmpty()) {
      return true;
    }
    Path current = root.get();
    for (Path segment : managedRelativePath(directory)) {
      current = current.resolve(segment);
      if (Files.notExists(current, LinkOption.NOFOLLOW_LINKS)) {
        return true;
      }
      if (Files.isSymbolicLink(current) || !isExistingDirectory(current)) {
        return true;
      }
    }
    return !isExistingDirectory(current);
  }

  private boolean regularFileMissingOrHasSymlinkAncestor(Path file) throws IOException {
    Path normalized = file.toAbsolutePath().normalize();
    Path parent = normalized.getParent();
    if (parent == null || directoryMissingOrHasSymlinkAncestor(parent)) {
      return true;
    }
    Optional<Path> managedFile = existingManagedPath(normalized);
    if (managedFile.isEmpty()) {
      return true;
    }
    Path safeFile = managedFile.get();
    if (Files.notExists(safeFile, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(safeFile)) {
      return true;
    }
    return !Files.readAttributes(safeFile, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)
        .isRegularFile();
  }

  private Optional<Path> existingManagedPath(Path path) throws IOException {
    Optional<Path> root = existingManagedRootRealPath();
    if (root.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(root.get().resolve(managedRelativePath(path)).normalize());
  }

  private Optional<Path> existingManagedRootRealPath() throws IOException {
    if (Files.notExists(appDataRoot, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    if (!Files.isDirectory(appDataRoot)) {
      throw new IOException("managed app-data root is unavailable");
    }
    return Optional.of(appDataRoot.toRealPath());
  }

  private Path ensureManagedRootRealPath() throws IOException {
    if (Files.notExists(appDataRoot, LinkOption.NOFOLLOW_LINKS)) {
      Files.createDirectories(appDataRoot);
    }
    if (!Files.isDirectory(appDataRoot)) {
      throw new IOException("managed app-data root is unavailable");
    }
    return appDataRoot.toRealPath();
  }

  private Path managedRelativePath(Path path) throws IOException {
    Path normalized = path.toAbsolutePath().normalize();
    if (!normalized.startsWith(appDataRoot)) {
      throw new IOException("managed app-data path is outside root");
    }
    return appDataRoot.relativize(normalized);
  }

  private static boolean isExistingDirectory(Path path) throws IOException {
    if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
      return false;
    }
    return Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)
        .isDirectory();
  }

  private static long fileSizeNoFollow(Path path) throws IOException {
    return Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).size();
  }

  private void writePropertiesAtomically(Path file, Properties properties, String comment)
      throws IOException {
    ensureDirectory(file.getParent());
    Path tempFile = Files.createTempFile(file.getParent(), ".app-data-", ".tmp");
    boolean moved = false;
    try {
      try (Writer writer = Files.newBufferedWriter(tempFile, StandardCharsets.UTF_8)) {
        properties.store(writer, comment);
      }
      forceFile(tempFile);
      moveReplacing(tempFile, file);
      moved = true;
    } finally {
      if (!moved) {
        Files.deleteIfExists(tempFile);
      }
    }
  }

  private void writeBytesAtomically(Path file, byte[] bytes) throws IOException {
    ensureDirectory(file.getParent());
    Path tempFile = Files.createTempFile(file.getParent(), ".app-data-value-", ".tmp");
    boolean moved = false;
    try {
      try (FileChannel channel =
          FileChannel.open(
              tempFile, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        writeFully(channel, buffer);
        channel.force(true);
      }
      moveReplacing(tempFile, file);
      moved = true;
    } finally {
      if (!moved) {
        Files.deleteIfExists(tempFile);
      }
    }
  }

  private static void forceFile(Path file) throws IOException {
    try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
      channel.force(true);
    }
  }

  private static void writeFully(FileChannel channel, ByteBuffer buffer) throws IOException {
    while (buffer.hasRemaining()) {
      int written = channel.write(buffer);
      if (written == 0) {
        throw new IOException("app-data value write made no progress");
      }
    }
  }

  private static void moveReplacing(Path source, Path target) throws IOException {
    try {
      Files.move(
          source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (AtomicMoveNotSupportedException _) {
      if (target.getFileName().toString().equals(CURRENT_FILE)) {
        throw new IOException("Atomic app-data generation commit is unavailable.");
      }
      Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private void pruneOldGenerations(Path generationsDirectory, String currentGeneration) {
    try (Stream<Path> stream = Files.list(generationsDirectory)) {
      stream
          .filter(path -> Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS))
          .filter(path -> !path.getFileName().toString().equals(currentGeneration))
          .forEach(
              path -> {
                try {
                  deleteTree(path);
                } catch (IOException _) {
                  // Best-effort cleanup only; stale generations are unreachable without pointer.
                }
              });
    } catch (IOException _) {
      // Best-effort cleanup only.
    }
  }

  private void deleteTree(Path root) throws IOException {
    Path normalized = root.toAbsolutePath().normalize();
    Path parent = normalized.getParent();
    if (parent != null && directoryMissingOrHasSymlinkAncestor(parent)) {
      return;
    }
    if (!Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    if (Files.isSymbolicLink(normalized)
        || !Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS)) {
      Files.deleteIfExists(normalized);
      return;
    }
    List<Path> paths;
    try (Stream<Path> stream = Files.walk(normalized)) {
      paths = stream.sorted(Comparator.reverseOrder()).toList();
    }
    for (Path path : paths) {
      Files.deleteIfExists(path);
    }
  }

  private static Instant instant(String value) {
    return Instant.parse(value);
  }

  private static int positiveInt(String value) {
    int parsed = Integer.parseInt(value);
    if (parsed <= 0) {
      throw new IllegalArgumentException("value must be positive");
    }
    return parsed;
  }

  private static int nonNegativeInt(String value) {
    if (value == null || value.isBlank()) {
      return 0;
    }
    int parsed = Integer.parseInt(value);
    if (parsed < 0) {
      throw new IllegalArgumentException("value must be non-negative");
    }
    return parsed;
  }
}
