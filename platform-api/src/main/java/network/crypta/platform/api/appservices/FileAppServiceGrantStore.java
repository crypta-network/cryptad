package network.crypta.platform.api.appservices;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.stream.Stream;
import network.crypta.platform.apphost.OwnerOnlyFilePermissions;

/**
 * File-backed store for local app-service grants and redacted audit events.
 *
 * <p>The store persists one properties file per grant and one properties file per audit event under
 * a host-managed root, normally {@code layout.dataDir()/apps/app-services}. The format is
 * intentionally simple so release certification and support tooling can inspect bounded metadata
 * without needing provider app processes, app data directories, or raw request bodies.
 *
 * <p>Writes use a temporary file followed by an atomic move where the filesystem supports it.
 * Directories and files are hardened with owner-only permissions through the same AppHost helper
 * used by adjacent app-platform stores. Audit retention is enforced on append and list so a
 * frequently invoked service grant does not grow the local store without bound.
 *
 * <p>The store treats malformed or oversized properties files as read failures. That behavior is
 * intentional: durable state should never silently become an authorization decision when it cannot
 * be decoded with the same validators used for fresh grants and audit events.
 */
public final class FileAppServiceGrantStore implements AppServiceGrantStore {
  private static final String GRANTS_DIRECTORY = "grants";
  private static final String BUNDLES_DIRECTORY = "bundles";
  private static final String AUDIT_DIRECTORY = "audit";
  private static final String PROPERTIES_SUFFIX = ".properties";
  private static final String KEY_VERSION = "version";
  private static final String KEY_GRANT_ID = "grantId";
  private static final String KEY_BUNDLE_ID = "bundleId";
  private static final String KEY_EVENT_ID = "eventId";
  private static final String KEY_CONSUMER_APP_ID = "consumerAppId";
  private static final String KEY_PROVIDER_APP_ID = "providerAppId";
  private static final String KEY_SERVICE_ID = "serviceId";
  private static final String KEY_SCOPES = "scopes";
  private static final String KEY_CONTEXTS = "contexts";
  private static final String KEY_PURPOSE = "purpose";
  private static final String KEY_STATUS = "status";
  private static final String KEY_CREATED_AT = "createdAt";
  private static final String KEY_UPDATED_AT = "updatedAt";
  private static final String KEY_APPROVED_AT = "approvedAt";
  private static final String KEY_EXPIRES_AT = "expiresAt";
  private static final String KEY_RENEWED_AT = "renewedAt";
  private static final String KEY_DEPENDENCY_ALIASES = "dependencyAliases";
  private static final String KEY_DEPENDENCY_FINGERPRINTS = "dependencyFingerprints";
  private static final String KEY_GRANT_IDS = "grantIds";
  private static final int MAX_PROPERTIES_BYTES = 16 * 1024;
  private static final int MAX_AUDIT_EVENTS = 512;

  private final Path root;

  /**
   * Creates a store below a host-managed app-platform root.
   *
   * <p>The path is normalized immediately, but the directory is created lazily on the first write.
   * Public JSON produced from stored records never includes this root path.
   *
   * @param root store root, normally {@code layout.dataDir()/apps/app-services}
   */
  public FileAppServiceGrantStore(Path root) {
    this.root = java.util.Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
  }

  /**
   * Lists stored grants in deterministic creation-time order.
   *
   * <p>Missing store directories are treated as an empty store. Every properties file is decoded
   * into an immutable grant record before sorting, so malformed persisted records fail the read
   * rather than being silently skipped as authorization input.
   *
   * @return immutable grant list ordered by creation time and grant id
   * @throws IOException when a grant file cannot be read or decoded
   */
  @Override
  public synchronized List<AppServiceGrant> listGrants() throws IOException {
    Path directory = grantsDirectory();
    if (!Files.isDirectory(directory)) {
      return List.of();
    }
    ArrayList<AppServiceGrant> grants = new ArrayList<>();
    try (Stream<Path> stream = Files.list(directory)) {
      for (Path path : sortedProperties(stream)) {
        grants.add(readGrantFile(path));
      }
    }
    grants.sort(
        Comparator.comparing(AppServiceGrant::createdAt).thenComparing(AppServiceGrant::grantId));
    return List.copyOf(grants);
  }

  /**
   * Reads one stored grant by normalized id.
   *
   * <p>The id is validated before the filename is constructed. Unknown ids return {@link
   * Optional#empty()} so the coordinator can translate that result into its stable Platform API
   * not-found error.
   *
   * @param grantId stable local grant id to read
   * @return grant record when the id exists
   * @throws IOException when the grant file cannot be read or decoded
   */
  @Override
  public synchronized Optional<AppServiceGrant> readGrant(String grantId) throws IOException {
    String normalized = AppServiceManifestParser.normalizeGrantId(grantId);
    Path file = grantsDirectory().resolve(normalized + PROPERTIES_SUFFIX);
    if (!Files.isRegularFile(file)) {
      return Optional.empty();
    }
    return Optional.of(readGrantFile(file));
  }

  /**
   * Creates or replaces the durable properties file for one grant.
   *
   * <p>The file contains only normalized public grant metadata, lifecycle timestamps, use counts,
   * and an optional token fingerprint. It never stores raw service tokens or provider-private
   * payloads.
   *
   * @param grant validated grant record to persist
   * @throws IOException when the grant cannot be written safely
   */
  @Override
  public synchronized void writeGrant(AppServiceGrant grant) throws IOException {
    ensureStoreDirectories();
    Properties properties = new Properties();
    properties.setProperty(KEY_VERSION, "1");
    properties.setProperty(KEY_GRANT_ID, grant.grantId());
    properties.setProperty(KEY_CONSUMER_APP_ID, grant.consumerAppId());
    properties.setProperty(KEY_PROVIDER_APP_ID, grant.providerAppId());
    properties.setProperty(KEY_SERVICE_ID, grant.serviceId());
    properties.setProperty(KEY_SCOPES, String.join(",", grant.scopes()));
    properties.setProperty(KEY_CONTEXTS, String.join(",", grant.contexts()));
    properties.setProperty(KEY_PURPOSE, grant.purpose());
    properties.setProperty(KEY_STATUS, grant.status().jsonValue());
    properties.setProperty(KEY_CREATED_AT, grant.createdAt().toString());
    properties.setProperty(KEY_UPDATED_AT, grant.updatedAt().toString());
    setInstant(properties, KEY_APPROVED_AT, grant.approvedAt());
    setInstant(properties, "revokedAt", grant.revokedAt());
    setInstant(properties, "lastUsedAt", grant.lastUsedAt());
    properties.setProperty("useCount", Long.toString(grant.useCount()));
    if (grant.tokenFingerprint() != null) {
      properties.setProperty("tokenFingerprint", grant.tokenFingerprint());
    }
    setText(properties, KEY_BUNDLE_ID, grant.bundleId());
    setInstant(properties, KEY_EXPIRES_AT, grant.expiresAt());
    setInstant(properties, KEY_RENEWED_AT, grant.renewedAt());
    setText(properties, "compatibilityFingerprint", grant.compatibilityFingerprint());
    setText(
        properties, "providerServiceVersionAtApproval", grant.providerServiceVersionAtApproval());
    writeProperties(grantsDirectory().resolve(grant.grantId() + PROPERTIES_SUFFIX), properties);
  }

  @Override
  public synchronized List<AppServiceGrantBundle> listBundles() throws IOException {
    Path directory = bundlesDirectory();
    if (!Files.isDirectory(directory)) {
      return List.of();
    }
    ArrayList<AppServiceGrantBundle> bundles = new ArrayList<>();
    try (Stream<Path> stream = Files.list(directory)) {
      for (Path path : sortedProperties(stream)) {
        bundles.add(readBundleFile(path));
      }
    }
    bundles.sort(
        Comparator.comparing(AppServiceGrantBundle::createdAt)
            .thenComparing(AppServiceGrantBundle::bundleId));
    return List.copyOf(bundles);
  }

  @Override
  public synchronized Optional<AppServiceGrantBundle> readBundle(String bundleId)
      throws IOException {
    String normalized = AppServiceManifestParser.normalizeBundleId(bundleId);
    Path file = bundlesDirectory().resolve(normalized + PROPERTIES_SUFFIX);
    if (!Files.isRegularFile(file)) {
      return Optional.empty();
    }
    return Optional.of(readBundleFile(file));
  }

  @Override
  public synchronized void writeBundle(AppServiceGrantBundle bundle) throws IOException {
    ensureStoreDirectories();
    Properties properties = new Properties();
    properties.setProperty(KEY_VERSION, "1");
    properties.setProperty(KEY_BUNDLE_ID, bundle.bundleId());
    properties.setProperty(KEY_CONSUMER_APP_ID, bundle.consumerAppId());
    setText(properties, "bundleAlias", bundle.bundleAlias());
    properties.setProperty(KEY_DEPENDENCY_ALIASES, String.join(",", bundle.dependencyAliases()));
    properties.setProperty(
        KEY_DEPENDENCY_FINGERPRINTS, String.join(",", bundle.dependencyFingerprints()));
    properties.setProperty("includeOptional", Boolean.toString(bundle.includeOptional()));
    properties.setProperty(KEY_PURPOSE, bundle.purpose());
    properties.setProperty(KEY_STATUS, bundle.status().jsonValue());
    properties.setProperty(KEY_CREATED_AT, bundle.createdAt().toString());
    properties.setProperty(KEY_UPDATED_AT, bundle.updatedAt().toString());
    setInstant(properties, KEY_APPROVED_AT, bundle.approvedAt());
    setInstant(properties, "rejectedAt", bundle.rejectedAt());
    setInstant(properties, KEY_EXPIRES_AT, bundle.expiresAt());
    setInstant(properties, KEY_RENEWED_AT, bundle.renewedAt());
    properties.setProperty(KEY_GRANT_IDS, String.join(",", bundle.grantIds()));
    writeProperties(bundlesDirectory().resolve(bundle.bundleId() + PROPERTIES_SUFFIX), properties);
  }

  /**
   * Appends a redacted audit event and prunes old audit files.
   *
   * <p>The event id is used as the filename, so callers must provide collision-resistant ids for
   * same-tick bursts. After the writing succeeds, the store keeps only the newest bounded audit
   * set.
   *
   * @param event redacted audit event to persist
   * @throws IOException when the event cannot be written or retention cleanup fails
   */
  @Override
  public synchronized void appendAuditEvent(AppServiceAuditEvent event) throws IOException {
    ensureStoreDirectories();
    Properties properties = new Properties();
    properties.setProperty(KEY_VERSION, "1");
    properties.setProperty(KEY_EVENT_ID, event.eventId());
    properties.setProperty("timestamp", event.timestamp().toString());
    properties.setProperty("eventType", event.eventType());
    setText(properties, KEY_CONSUMER_APP_ID, event.consumerAppId());
    setText(properties, KEY_PROVIDER_APP_ID, event.providerAppId());
    setText(properties, KEY_SERVICE_ID, event.serviceId());
    setText(properties, KEY_GRANT_ID, event.grantId());
    setText(properties, "scope", event.scope());
    setText(properties, "context", event.context());
    properties.setProperty(KEY_STATUS, event.status());
    properties.setProperty("reasonCode", event.reasonCode());
    setText(properties, "subjectUriHash", event.subjectUriHash());
    writeProperties(auditDirectory().resolve(event.eventId() + PROPERTIES_SUFFIX), properties);
    pruneAuditEvents(auditDirectory());
  }

  /**
   * Lists recent audit events in newest-first order.
   *
   * <p>The requested limit is bounded again at the store boundary. The method also runs retention
   * pruning before listing so older stores are trimmed even if no new audit event is appended.
   *
   * @param limit maximum number of events requested by the caller
   * @return immutable audit list ordered newest first, then event id
   * @throws IOException when audit files cannot be read, decoded, or pruned
   */
  @Override
  public synchronized List<AppServiceAuditEvent> listAuditEvents(int limit) throws IOException {
    int boundedLimit = Math.clamp(limit, 0, 200);
    Path directory = auditDirectory();
    if (!Files.isDirectory(directory)) {
      return List.of();
    }
    pruneAuditEvents(directory);
    if (boundedLimit == 0) {
      return List.of();
    }
    ArrayList<AppServiceAuditEvent> events = new ArrayList<>();
    for (AuditFile auditFile : auditFiles(directory)) {
      events.add(auditFile.event());
    }
    events.sort(
        Comparator.comparing(AppServiceAuditEvent::timestamp)
            .reversed()
            .thenComparing(AppServiceAuditEvent::eventId));
    return events.stream().limit(boundedLimit).toList();
  }

  private void pruneAuditEvents(Path directory) throws IOException {
    List<AuditFile> auditFiles = auditFiles(directory);
    if (auditFiles.size() <= MAX_AUDIT_EVENTS) {
      return;
    }
    auditFiles.sort(
        Comparator.comparing((AuditFile auditFile) -> auditFile.event().timestamp())
            .thenComparing(auditFile -> auditFile.event().eventId()));
    int removeCount = auditFiles.size() - MAX_AUDIT_EVENTS;
    for (int index = 0; index < removeCount; index++) {
      Files.deleteIfExists(auditFiles.get(index).path());
    }
  }

  private List<AuditFile> auditFiles(Path directory) throws IOException {
    ArrayList<AuditFile> files = new ArrayList<>();
    try (Stream<Path> stream = Files.list(directory)) {
      for (Path path : sortedProperties(stream)) {
        files.add(new AuditFile(path, readAuditFile(path)));
      }
    }
    return files;
  }

  private AppServiceGrant readGrantFile(Path file) throws IOException {
    Properties properties = readProperties(file);
    try {
      return new AppServiceGrant(
          require(properties, KEY_GRANT_ID),
          require(properties, KEY_CONSUMER_APP_ID),
          require(properties, KEY_PROVIDER_APP_ID),
          require(properties, KEY_SERVICE_ID),
          AppServiceManifestParser.commaList(require(properties, KEY_SCOPES), KEY_SCOPES),
          AppServiceManifestParser.commaList(properties.getProperty(KEY_CONTEXTS), KEY_CONTEXTS),
          require(properties, KEY_PURPOSE),
          AppServiceGrantStatus.parse(require(properties, KEY_STATUS)),
          Instant.parse(require(properties, KEY_CREATED_AT)),
          Instant.parse(require(properties, KEY_UPDATED_AT)),
          optionalInstant(properties, KEY_APPROVED_AT),
          optionalInstant(properties, "revokedAt"),
          optionalInstant(properties, "lastUsedAt"),
          Long.parseLong(require(properties, "useCount")),
          properties.getProperty("tokenFingerprint"),
          properties.getProperty(KEY_BUNDLE_ID),
          optionalInstant(properties, KEY_EXPIRES_AT),
          optionalInstant(properties, KEY_RENEWED_AT),
          properties.getProperty("compatibilityFingerprint"),
          properties.getProperty("providerServiceVersionAtApproval"));
    } catch (RuntimeException exception) {
      throw malformedRecord("grant", exception);
    }
  }

  private AppServiceGrantBundle readBundleFile(Path file) throws IOException {
    Properties properties = readProperties(file);
    try {
      return new AppServiceGrantBundle(
          require(properties, KEY_BUNDLE_ID),
          require(properties, KEY_CONSUMER_APP_ID),
          properties.getProperty("bundleAlias"),
          AppServiceManifestParser.normalizeAliases(
              KEY_DEPENDENCY_ALIASES,
              AppServiceManifestParser.commaList(
                  properties.getProperty(KEY_DEPENDENCY_ALIASES), KEY_DEPENDENCY_ALIASES)),
          commaSeparatedValues(properties.getProperty(KEY_DEPENDENCY_FINGERPRINTS)),
          Boolean.parseBoolean(require(properties, "includeOptional")),
          require(properties, KEY_PURPOSE),
          AppServiceGrantBundleStatus.parse(require(properties, KEY_STATUS)),
          Instant.parse(require(properties, KEY_CREATED_AT)),
          Instant.parse(require(properties, KEY_UPDATED_AT)),
          optionalInstant(properties, KEY_APPROVED_AT),
          optionalInstant(properties, "rejectedAt"),
          optionalInstant(properties, KEY_EXPIRES_AT),
          optionalInstant(properties, KEY_RENEWED_AT),
          grantIdList(properties.getProperty(KEY_GRANT_IDS)));
    } catch (RuntimeException exception) {
      throw malformedRecord("bundle", exception);
    }
  }

  private AppServiceAuditEvent readAuditFile(Path file) throws IOException {
    Properties properties = readProperties(file);
    try {
      return new AppServiceAuditEvent(
          require(properties, KEY_EVENT_ID),
          Instant.parse(require(properties, "timestamp")),
          require(properties, "eventType"),
          properties.getProperty(KEY_CONSUMER_APP_ID),
          properties.getProperty(KEY_PROVIDER_APP_ID),
          properties.getProperty(KEY_SERVICE_ID),
          properties.getProperty(KEY_GRANT_ID),
          properties.getProperty("scope"),
          properties.getProperty("context"),
          require(properties, KEY_STATUS),
          require(properties, "reasonCode"),
          properties.getProperty("subjectUriHash"));
    } catch (RuntimeException exception) {
      throw malformedRecord(AUDIT_DIRECTORY, exception);
    }
  }

  private Properties readProperties(Path file) throws IOException {
    if (Files.size(file) > MAX_PROPERTIES_BYTES) {
      throw new IOException("app-service store record is too large");
    }
    Properties properties = new Properties();
    try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
      properties.load(reader);
    }
    return properties;
  }

  private void writeProperties(Path file, Properties properties) throws IOException {
    Path parent = file.getParent();
    Files.createDirectories(parent);
    Path temp = Files.createTempFile(parent, file.getFileName().toString(), ".tmp");
    try (Writer writer = Files.newBufferedWriter(temp, StandardCharsets.UTF_8)) {
      properties.store(writer, "Cryptad app-service metadata");
    }
    OwnerOnlyFilePermissions.hardenSensitiveFile(temp);
    try {
      Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
    }
    OwnerOnlyFilePermissions.hardenSensitiveFile(file);
  }

  private void ensureStoreDirectories() throws IOException {
    Files.createDirectories(grantsDirectory());
    Files.createDirectories(bundlesDirectory());
    Files.createDirectories(auditDirectory());
    OwnerOnlyFilePermissions.hardenDirectory(root);
    OwnerOnlyFilePermissions.hardenDirectory(grantsDirectory());
    OwnerOnlyFilePermissions.hardenDirectory(bundlesDirectory());
    OwnerOnlyFilePermissions.hardenDirectory(auditDirectory());
  }

  private Path grantsDirectory() {
    return root.resolve(GRANTS_DIRECTORY);
  }

  private Path bundlesDirectory() {
    return root.resolve(BUNDLES_DIRECTORY);
  }

  private Path auditDirectory() {
    return root.resolve(AUDIT_DIRECTORY);
  }

  private static List<Path> sortedProperties(Stream<Path> stream) {
    return stream
        .filter(path -> path.getFileName().toString().endsWith(PROPERTIES_SUFFIX))
        .sorted(Comparator.comparing(path -> path.getFileName().toString()))
        .toList();
  }

  private static String require(Properties properties, String key) throws IOException {
    String value = properties.getProperty(key);
    if (value == null || value.isBlank()) {
      throw new IOException("app-service store record is missing " + key);
    }
    return value;
  }

  private static Instant optionalInstant(Properties properties, String key) {
    String value = properties.getProperty(key);
    return value == null || value.isBlank() ? null : Instant.parse(value);
  }

  private static List<String> grantIdList(String raw) {
    return commaSeparatedValues(raw).stream()
        .map(AppServiceManifestParser::normalizeGrantId)
        .toList();
  }

  private static List<String> commaSeparatedValues(String raw) {
    if (raw == null || raw.isBlank()) {
      return List.of();
    }
    ArrayList<String> values = new ArrayList<>();
    for (String part : raw.split(",", -1)) {
      String trimmed = part.trim();
      if (trimmed.isEmpty()) {
        throw new IllegalArgumentException("comma-separated list contains an empty value");
      }
      values.add(trimmed);
    }
    return List.copyOf(values);
  }

  private static IOException malformedRecord(String kind, RuntimeException cause) {
    return new IOException("malformed app-service " + kind + " record", cause);
  }

  private static void setInstant(Properties properties, String key, Instant value) {
    if (value != null) {
      properties.setProperty(key, value.toString());
    }
  }

  private static void setText(Properties properties, String key, String value) {
    if (value != null) {
      properties.setProperty(key, value);
    }
  }

  private record AuditFile(Path path, AppServiceAuditEvent event) {}
}
