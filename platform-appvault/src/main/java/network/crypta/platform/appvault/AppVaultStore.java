package network.crypta.platform.appvault;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

/**
 * File-backed metadata, envelope, grant, and access-block store for the app vault.
 *
 * <p>This class owns the local persistent layout under {@link AppVaultPaths}. It writes redacted
 * properties files for safe listing and separate JSON envelopes for encrypted secret values and
 * private identity material. The service layer performs authorization and cryptographic decisions;
 * the store focuses on durable, path-safe, and corruption-detecting file operations.
 *
 * <p>Writes use temporary files followed by an atomic move when the filesystem supports it. Secret
 * and identity writes commit envelope data before metadata and attempt to restore the previous
 * files on failure so list responses do not point at missing or mismatched encrypted material.
 *
 * <p>POSIX file permissions are hardened on platforms that expose {@link PosixFileAttributeView}.
 * On other platforms this class makes no stronger permission claim than the underlying operating
 * system provides.
 */
public final class AppVaultStore {
  /** Owner-only directory permissions used when POSIX attributes are available. */
  private static final Set<PosixFilePermission> OWNER_DIRECTORY =
      Set.of(
          PosixFilePermission.OWNER_READ,
          PosixFilePermission.OWNER_WRITE,
          PosixFilePermission.OWNER_EXECUTE);

  /** Owner read/write file permissions used when POSIX attributes are available. */
  private static final Set<PosixFilePermission> OWNER_FILE =
      Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

  private static final String GRANT_FILE_EXTENSION = ".properties";
  private static final String METADATA_FILE_NAME = "metadata.properties";
  private static final String PROPERTY_APP_ID = "appId";
  private static final String PROPERTY_CREATED_AT = "createdAt";
  private static final String PROPERTY_IDENTITY_ID = "identityId";
  private static final String PROPERTY_METADATA_PREFIX = "metadata.";
  private static final String PROPERTY_PUBLIC_SUMMARY_PREFIX = "publicSummary.";
  private static final String PROPERTY_UPDATED_AT = "updatedAt";

  /** Path derivation helper for every file and directory in the vault layout. */
  private final AppVaultPaths paths;

  /** Optional test hook invoked after a file has been atomically moved into place. */
  private final FileCommitHook fileCommitHook;

  /**
   * Creates a store rooted in the supplied vault path helper.
   *
   * <p>The constructor does not create directories. Call {@link #initialize()} before using a store
   * opened from production runtime composition.
   *
   * @param paths path helper rooted at the local vault directory
   */
  public AppVaultStore(AppVaultPaths paths) {
    this(paths, _ -> {});
  }

  /**
   * Creates a store with a commit hook used by focused failure tests.
   *
   * @param paths path helper rooted at the local vault directory
   * @param fileCommitHook hook invoked after each atomic file replacement
   */
  AppVaultStore(AppVaultPaths paths, FileCommitHook fileCommitHook) {
    this.paths = Objects.requireNonNull(paths, "paths");
    this.fileCommitHook = Objects.requireNonNull(fileCommitHook, "fileCommitHook");
  }

  /**
   * Returns the path helper used by this store.
   *
   * @return vault path helper for diagnostics and tests
   */
  public AppVaultPaths paths() {
    return paths;
  }

  /**
   * Initializes the root directory structure.
   *
   * <p>The method creates all top-level directories used by the v1 layout and applies owner-only
   * permissions where supported. It is idempotent for an existing directory tree.
   *
   * @throws IOException if a directory cannot be created or permission hardening fails
   */
  public void initialize() throws IOException {
    createDirectory(paths.root());
    createDirectory(paths.secretsRoot());
    createDirectory(paths.identitiesRoot());
    createDirectory(paths.grantsRoot());
    createDirectory(paths.appAccessBlocksRoot());
    createDirectory(paths.keyFile().getParent());
  }

  /**
   * Builds one app secret record without committing metadata or value files.
   *
   * <p>The prepared record preserves the original creation timestamp and last-used timestamp when a
   * secret is replaced. Caller metadata is redacted here so plaintext credentials are not written
   * to properties files or returned in list responses.
   *
   * @param appId app id that owns the secret
   * @param secretName app-local secret name
   * @param secretKind caller-supplied kind label, defaulting to {@code generic} when blank
   * @param valueSizeBytes plaintext value size used to compute the coarse size class
   * @param metadata caller-supplied metadata to normalize and redact
   * @return redacted metadata record ready to pair with an encrypted envelope
   * @throws IOException if the existing metadata record cannot be read
   */
  public AppSecretRecord prepareSecretRecord(
      String appId,
      String secretName,
      String secretKind,
      int valueSizeBytes,
      Map<String, String> metadata)
      throws IOException {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    String normalizedName = AppVaultPaths.normalizeSecretName(secretName);
    AppSecretRecord existing = readSecretRecord(normalizedAppId, normalizedName);
    Instant now = Instant.now();
    Instant createdAt = existing == null ? now : existing.createdAt();
    return new AppSecretRecord(
        normalizedAppId,
        normalizedName,
        normalizeKind(secretKind),
        createdAt,
        now,
        existing == null ? null : existing.lastUsedAt(),
        sizeClass(valueSizeBytes),
        AppVaultMetadata.redactSecretMetadata(metadata));
  }

  /**
   * Writes one encrypted secret envelope and commits its matching metadata after it is durable.
   *
   * <p>The envelope is written first so a listed metadata record never points at a missing new
   * value after a successful metadata commit. If either file write fails, the method attempts to
   * restore the previous envelope and metadata contents before rethrowing the original failure.
   *
   * @param secretRecord redacted secret metadata that matches the envelope AAD
   * @param envelope encrypted value envelope to persist
   * @throws IOException if either file cannot be written or restored
   */
  public void writeSecret(AppSecretRecord secretRecord, AppVaultEnvelope envelope)
      throws IOException {
    Objects.requireNonNull(secretRecord, "secretRecord");
    Objects.requireNonNull(envelope, "envelope");
    Path root = paths.secretRoot(secretRecord.appId(), secretRecord.secretName());
    createDirectory(root);
    Path envelopePath = paths.secretEnvelopePath(secretRecord.appId(), secretRecord.secretName());
    Path metadataPath = paths.secretMetadataPath(secretRecord.appId(), secretRecord.secretName());
    String previousEnvelope =
        Files.isRegularFile(envelopePath) ? Files.readString(envelopePath) : null;
    String previousMetadata =
        Files.isRegularFile(metadataPath) ? Files.readString(metadataPath) : null;
    try {
      writeString(envelopePath, envelope.toJson());
      writeProperties(metadataPath, secretProperties(secretRecord));
    } catch (IOException exception) {
      restoreTextFile(envelopePath, previousEnvelope, exception);
      restoreTextFile(metadataPath, previousMetadata, exception);
      throw exception;
    }
  }

  /**
   * Reads one app secret metadata record, or {@code null} when absent.
   *
   * <p>The method validates that embedded app id and secret name match the requested path. A copied
   * or misplaced metadata file is treated as a corrupt vault record rather than returned to
   * callers.
   *
   * @param appId expected owner app id
   * @param secretName expected app-local secret name
   * @return redacted secret metadata record, or {@code null} when no metadata file exists
   * @throws IOException if the properties file cannot be read
   */
  public AppSecretRecord readSecretRecord(String appId, String secretName) throws IOException {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    String normalizedName = AppVaultPaths.normalizeSecretName(secretName);
    Path path = paths.secretMetadataPath(normalizedAppId, normalizedName);
    if (!Files.isRegularFile(path)) {
      return null;
    }
    AppSecretRecord secretRecord = secretRecord(readProperties(path));
    requireSecretRecordMatches(normalizedAppId, normalizedName, secretRecord);
    return secretRecord;
  }

  /**
   * Reads one app secret envelope.
   *
   * <p>The caller is responsible for decrypting with AAD computed from the corresponding metadata
   * record. Missing envelope files are reported as {@code secret_not_found} so callers do not learn
   * a local path.
   *
   * @param appId owner app id for path derivation
   * @param secretName app-local secret name for path derivation
   * @return parsed encrypted secret envelope
   * @throws IOException if the envelope file cannot be read
   */
  public AppVaultEnvelope readSecretEnvelope(String appId, String secretName) throws IOException {
    Path path = paths.secretEnvelopePath(appId, secretName);
    if (!Files.isRegularFile(path)) {
      throw new AppVaultException(404, "secret_not_found", "Secret not found.");
    }
    return AppVaultEnvelope.fromJson(Files.readString(path));
  }

  /**
   * Marks one secret as used.
   *
   * <p>Only the metadata properties file is updated. The encrypted value envelope and its AAD-bound
   * creation timestamp are unchanged.
   *
   * @param secretRecord current redacted secret metadata record
   * @param lastUsedAt timestamp to store as the most recent successful read
   * @throws IOException if the metadata file cannot be rewritten
   */
  public void markSecretUsed(AppSecretRecord secretRecord, Instant lastUsedAt) throws IOException {
    AppSecretRecord updated =
        new AppSecretRecord(
            secretRecord.appId(),
            secretRecord.secretName(),
            secretRecord.secretKind(),
            secretRecord.createdAt(),
            secretRecord.updatedAt(),
            lastUsedAt,
            secretRecord.sizeClass(),
            secretRecord.metadata());
    writeProperties(
        paths.secretMetadataPath(secretRecord.appId(), secretRecord.secretName()),
        secretProperties(updated));
  }

  /**
   * Lists redacted secret metadata for one app.
   *
   * <p>Each candidate directory must contain metadata whose embedded app id and secret name match
   * its path. That validation prevents a copied directory from leaking another app's metadata in a
   * list response.
   *
   * @param appId app id whose secret metadata should be listed
   * @return immutable list sorted by secret name
   * @throws IOException if a candidate metadata file cannot be read
   */
  public List<AppSecretRecord> listSecrets(String appId) throws IOException {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    Path appRoot = paths.secretsRoot().resolve(normalizedAppId);
    if (!Files.isDirectory(appRoot)) {
      return List.of();
    }
    ArrayList<AppSecretRecord> records = new ArrayList<>();
    try (var stream = Files.list(appRoot)) {
      for (Path candidate : stream.sorted().toList()) {
        Path metadata = candidate.resolve(METADATA_FILE_NAME);
        if (Files.isRegularFile(metadata)) {
          AppSecretRecord secretRecord = secretRecord(readProperties(metadata));
          requireSecretRecordMatches(
              normalizedAppId, candidate.getFileName().toString(), secretRecord);
          records.add(secretRecord);
        }
      }
    }
    records.sort(Comparator.comparing(AppSecretRecord::secretName));
    return List.copyOf(records);
  }

  /**
   * Deletes one app-owned secret if present.
   *
   * <p>The whole secret directory is removed, including metadata and encrypted value envelope. A
   * missing directory is not an error.
   *
   * @param appId app id that owns the secret
   * @param secretName app-local secret name
   * @return {@code true} when a secret directory existed and was removed
   * @throws IOException if recursive deletion fails
   */
  public boolean deleteSecret(String appId, String secretName) throws IOException {
    Path root = paths.secretRoot(appId, secretName);
    if (!Files.exists(root)) {
      return false;
    }
    deleteRecursively(root);
    return true;
  }

  /**
   * Deletes every app-owned secret directory for one app if present.
   *
   * <p>This is the storage primitive behind uninstall cleanup. It does not enumerate secret names
   * in its return value or errors.
   *
   * @param appId app id whose secret tree should be removed
   * @return {@code true} when the app secret tree existed and was removed
   * @throws IOException if recursive deletion fails
   */
  public boolean deleteSecretsForApp(String appId) throws IOException {
    Path root = paths.secretsRoot().resolve(AppVaultPaths.normalizeAppId(appId));
    if (!Files.exists(root)) {
      return false;
    }
    deleteRecursively(root);
    return true;
  }

  /**
   * Writes or replaces one identity metadata record and encrypted private material.
   *
   * <p>The private envelope is committed before metadata. If a later metadata write fails, the
   * method attempts to restore both previous files before rethrowing the original error, preventing
   * a listed identity from pointing at missing private material.
   *
   * @param identityRecord public identity metadata that matches the private envelope AAD
   * @param privateEnvelope encrypted private-material envelope
   * @throws IOException if either file cannot be written or restored
   */
  public void writeIdentity(AppIdentityRecord identityRecord, AppVaultEnvelope privateEnvelope)
      throws IOException {
    Objects.requireNonNull(identityRecord, "identityRecord");
    Objects.requireNonNull(privateEnvelope, "privateEnvelope");
    createDirectory(paths.identityRoot(identityRecord.identityId()));
    Path metadataPath = paths.identityMetadataPath(identityRecord.identityId());
    Path privatePath = paths.identityPrivateEnvelopePath(identityRecord.identityId());
    String previousMetadata =
        Files.isRegularFile(metadataPath) ? Files.readString(metadataPath) : null;
    String previousPrivate =
        Files.isRegularFile(privatePath) ? Files.readString(privatePath) : null;
    try {
      writeString(privatePath, privateEnvelope.toJson());
      writeProperties(metadataPath, identityProperties(identityRecord));
    } catch (IOException exception) {
      restoreTextFile(privatePath, previousPrivate, exception);
      restoreTextFile(metadataPath, previousMetadata, exception);
      throw exception;
    }
  }

  /**
   * Writes only identity metadata.
   *
   * <p>This helper is reserved for metadata-only updates where private material has already been
   * written and remains valid for the identity AAD.
   *
   * @param identityRecord public identity metadata to persist
   * @throws IOException if the metadata file cannot be written
   */
  @SuppressWarnings("unused")
  public void writeIdentityMetadata(AppIdentityRecord identityRecord) throws IOException {
    createDirectory(paths.identityRoot(identityRecord.identityId()));
    writeProperties(
        paths.identityMetadataPath(identityRecord.identityId()),
        identityProperties(identityRecord));
  }

  /**
   * Reads one identity metadata record, or {@code null} when absent.
   *
   * <p>The embedded identity id must match the requested directory. Mismatches are treated as
   * corrupt records so copied or restored directories cannot confuse operator listings or cleanup.
   *
   * @param identityId identity id to read
   * @return public identity metadata, or {@code null} when no metadata file exists
   * @throws IOException if the metadata file cannot be read
   */
  public AppIdentityRecord readIdentity(String identityId) throws IOException {
    String normalizedIdentityId = AppVaultPaths.normalizeIdentityId(identityId);
    Path path = paths.identityMetadataPath(normalizedIdentityId);
    if (!Files.isRegularFile(path)) {
      return null;
    }
    AppIdentityRecord identityRecord = identityRecord(readProperties(path));
    requireIdentityRecordMatches(normalizedIdentityId, identityRecord);
    return identityRecord;
  }

  /**
   * Reads one identity private envelope.
   *
   * <p>The caller decrypts the envelope with AAD computed from the public identity metadata.
   * Missing private envelopes map to a stable identity-not-found vault error.
   *
   * @param identityId identity id whose private envelope should be read
   * @return parsed encrypted private-material envelope
   * @throws IOException if the envelope file cannot be read
   */
  public AppVaultEnvelope readIdentityPrivateEnvelope(String identityId) throws IOException {
    Path path = paths.identityPrivateEnvelopePath(identityId);
    if (!Files.isRegularFile(path)) {
      throw new AppVaultException(404, "identity_not_found", "Identity not found.");
    }
    return AppVaultEnvelope.fromJson(Files.readString(path));
  }

  /**
   * Lists all identity metadata records.
   *
   * <p>Each identity directory is validated against the embedded identity id before being included.
   * Private envelopes are not read during listing.
   *
   * @return immutable list sorted by identity id
   * @throws IOException if a candidate metadata file cannot be read
   */
  public List<AppIdentityRecord> listIdentities() throws IOException {
    Path root = paths.identitiesRoot();
    if (!Files.isDirectory(root)) {
      return List.of();
    }
    ArrayList<AppIdentityRecord> records = new ArrayList<>();
    try (var stream = Files.list(root)) {
      for (Path candidate : stream.sorted().toList()) {
        Path metadata = candidate.resolve(METADATA_FILE_NAME);
        if (Files.isRegularFile(metadata)) {
          AppIdentityRecord identityRecord = identityRecord(readProperties(metadata));
          requireIdentityRecordMatches(candidate.getFileName().toString(), identityRecord);
          records.add(identityRecord);
        }
      }
    }
    records.sort(Comparator.comparing(AppIdentityRecord::identityId));
    return List.copyOf(records);
  }

  /**
   * Deletes one identity and its encrypted private material.
   *
   * <p>The caller is responsible for revoking grants before deletion when authorization state
   * should be retained for audit. The store only removes the identity directory.
   *
   * @param identityId identity id to remove
   * @return {@code true} when an identity directory existed and was removed
   * @throws IOException if recursive deletion fails
   */
  public boolean deleteIdentity(String identityId) throws IOException {
    Path root = paths.identityRoot(identityId);
    if (!Files.exists(root)) {
      return false;
    }
    deleteRecursively(root);
    return true;
  }

  /**
   * Writes one identity grant.
   *
   * <p>Grant metadata is stored in a single properties file named by grant id. The embedded grant
   * id is validated on reads and list operations to detect copied or renamed files.
   *
   * @param grant grant record to persist
   * @throws IOException if the grant file cannot be written
   */
  public void writeGrant(AppIdentityGrant grant) throws IOException {
    createDirectory(paths.grantsRoot());
    writeProperties(paths.grantPath(grant.grantId()), grantProperties(grant));
  }

  /**
   * Reads one grant by id, or {@code null} when absent.
   *
   * <p>The embedded grant id must match the requested file. Mismatches are corrupt records because
   * authorization scans rely on file names and embedded ids agreeing.
   *
   * @param grantId grant id to read
   * @return grant record, or {@code null} when no grant file exists
   * @throws IOException if the grant file cannot be read
   */
  public AppIdentityGrant readGrant(String grantId) throws IOException {
    String normalizedGrantId = AppVaultPaths.normalizeGrantId(grantId);
    Path path = paths.grantPath(normalizedGrantId);
    if (!Files.isRegularFile(path)) {
      return null;
    }
    AppIdentityGrant grantRecord = grantRecord(readProperties(path));
    if (!normalizedGrantId.equals(grantRecord.grantId())) {
      throw new AppVaultException(400, "corrupt_vault_record", "Vault record metadata mismatch.");
    }
    return grantRecord;
  }

  /**
   * Lists all identity grants.
   *
   * <p>Only {@code .properties} grant files are considered. Each embedded grant id must match its
   * filename before the record is returned, which prevents renamed active grants from continuing to
   * authorize after the original grant is revoked.
   *
   * @return immutable list sorted by grant id
   * @throws IOException if a candidate grant file cannot be read
   */
  public List<AppIdentityGrant> listGrants() throws IOException {
    Path root = paths.grantsRoot();
    if (!Files.isDirectory(root)) {
      return List.of();
    }
    ArrayList<AppIdentityGrant> records = new ArrayList<>();
    try (var stream = Files.list(root)) {
      for (Path candidate : stream.sorted().toList()) {
        if (Files.isRegularFile(candidate)
            && candidate.getFileName().toString().endsWith(GRANT_FILE_EXTENSION)) {
          AppIdentityGrant grantRecord = grantRecord(readProperties(candidate));
          requireGrantRecordMatches(candidate, grantRecord);
          records.add(grantRecord);
        }
      }
    }
    records.sort(Comparator.comparing(AppIdentityGrant::grantId));
    return List.copyOf(records);
  }

  /**
   * Deletes one grant.
   *
   * <p>The service normally revokes grants instead of deleting them so operator audit metadata is
   * retained. This primitive exists for future explicit purge paths and focused tests.
   *
   * @param grantId grant id whose properties file should be removed
   * @return {@code true} when a grant file was deleted
   * @throws IOException if deletion fails
   */
  @SuppressWarnings("unused")
  public boolean deleteGrant(String grantId) throws IOException {
    Path path = paths.grantPath(grantId);
    return Files.deleteIfExists(path);
  }

  /**
   * Records that app-facing vault access for an app id is disabled pending cleanup.
   *
   * <p>The access block is a durable fail-closed marker used by uninstall cleanup. It prevents a
   * later same-id install from reading retained secrets or using retained grants until cleanup
   * completes and the block is cleared.
   *
   * @param appId app id whose app-facing vault access should be blocked
   * @param reasonCode stable Reason code for operator status, or {@code unspecified} when blank
   * @throws IOException if the access-block file cannot be written
   */
  public void writeAppAccessBlock(String appId, String reasonCode) throws IOException {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    Properties properties = new Properties();
    properties.setProperty(PROPERTY_APP_ID, normalizedAppId);
    properties.setProperty(
        "reasonCode", reasonCode == null || reasonCode.isBlank() ? "unspecified" : reasonCode);
    properties.setProperty(PROPERTY_CREATED_AT, Instant.now().toString());
    writeProperties(paths.appAccessBlockPath(normalizedAppId), properties);
  }

  /**
   * Returns whether app-facing vault access is disabled for an app id.
   *
   * @param appId app id to check for a durable access block
   * @return {@code true} when an access-block file exists
   */
  public boolean appAccessBlocked(String appId) {
    return Files.isRegularFile(paths.appAccessBlockPath(appId));
  }

  /**
   * Clears an app-facing vault access block when cleanup has fully completed.
   *
   * @param appId app id whose access block should be removed
   * @return {@code true} when an existing access block was deleted
   * @throws IOException if deletion fails
   */
  public boolean clearAppAccessBlock(String appId) throws IOException {
    return Files.deleteIfExists(paths.appAccessBlockPath(appId));
  }

  /**
   * Returns whether any retained cleanup state exists for an uninstalled app id.
   *
   * <p>Retained state includes an access block, app-owned secret directories, app-owned identities,
   * or non-revoked app-bound grants. Revoked historical grants alone do not keep app-facing access
   * blocked.
   *
   * @param appId app id to inspect for retained vault state
   * @return {@code true} when cleanup should still be retried or surfaced
   * @throws IOException if retained state cannot be inspected
   */
  public boolean hasRetainedAppState(String appId) throws IOException {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    return appAccessBlocked(normalizedAppId)
        || Files.exists(paths.secretsRoot().resolve(normalizedAppId))
        || hasGrantFileForApp(normalizedAppId)
        || hasOwnedIdentityForApp(normalizedAppId);
  }

  private boolean hasGrantFileForApp(String appId) throws IOException {
    Path root = paths.grantsRoot();
    if (!Files.isDirectory(root)) {
      return false;
    }
    try (var stream = Files.list(root)) {
      for (Path candidate : stream.sorted().toList()) {
        if (!Files.isRegularFile(candidate)
            || !candidate.getFileName().toString().endsWith(GRANT_FILE_EXTENSION)) {
          continue;
        }
        AppIdentityGrant grant = grantRecord(readProperties(candidate));
        if (appId.equals(grant.appId()) && grant.status() != AppIdentityGrantStatus.REVOKED) {
          return true;
        }
      }
    }
    return false;
  }

  private boolean hasOwnedIdentityForApp(String appId) throws IOException {
    for (AppIdentityRecord identity : listIdentities()) {
      if (appId.equals(identity.ownerAppId())) {
        return true;
      }
    }
    return false;
  }

  private static String normalizeKind(String value) {
    String text =
        value == null || value.isBlank()
            ? "generic"
            : value.trim().toLowerCase(java.util.Locale.ROOT);
    if (!text.matches("[a-z0-9][a-z0-9._:-]{0,63}")) {
      throw new AppVaultException(400, "invalid_secret_kind", "Invalid secret kind.");
    }
    return text;
  }

  private static Properties secretProperties(AppSecretRecord secretRecord) {
    Properties properties = new Properties();
    properties.setProperty(PROPERTY_APP_ID, secretRecord.appId());
    properties.setProperty("secretName", secretRecord.secretName());
    properties.setProperty("secretKind", secretRecord.secretKind());
    properties.setProperty(PROPERTY_CREATED_AT, secretRecord.createdAt().toString());
    properties.setProperty(PROPERTY_UPDATED_AT, secretRecord.updatedAt().toString());
    if (secretRecord.lastUsedAt() != null) {
      properties.setProperty("lastUsedAt", secretRecord.lastUsedAt().toString());
    }
    properties.setProperty("sizeClass", secretRecord.sizeClass());
    for (Map.Entry<String, String> entry : secretRecord.metadata().entrySet()) {
      if (entry.getKey().matches("[A-Za-z0-9_.-]{1,64}") && entry.getValue() != null) {
        properties.setProperty(PROPERTY_METADATA_PREFIX + entry.getKey(), entry.getValue());
      }
    }
    return properties;
  }

  private static AppSecretRecord secretRecord(Properties properties) {
    LinkedHashMap<String, String> metadata = LinkedHashMap.newLinkedHashMap(4);
    for (String name : properties.stringPropertyNames()) {
      if (name.startsWith(PROPERTY_METADATA_PREFIX)) {
        metadata.put(
            name.substring(PROPERTY_METADATA_PREFIX.length()), properties.getProperty(name));
      }
    }
    return new AppSecretRecord(
        properties.getProperty(PROPERTY_APP_ID),
        properties.getProperty("secretName"),
        properties.getProperty("secretKind"),
        parseRequiredInstant(properties, PROPERTY_CREATED_AT),
        parseRequiredInstant(properties, PROPERTY_UPDATED_AT),
        parseInstant(properties.getProperty("lastUsedAt")),
        properties.getProperty("sizeClass"),
        metadata);
  }

  private static void requireSecretRecordMatches(
      String expectedAppId, String expectedSecretName, AppSecretRecord secretRecord) {
    if (!expectedAppId.equals(secretRecord.appId())
        || !expectedSecretName.equals(secretRecord.secretName())) {
      throw new AppVaultException(400, "corrupt_vault_record", "Vault record metadata mismatch.");
    }
  }

  private static Properties identityProperties(AppIdentityRecord identityRecord) {
    Properties properties = new Properties();
    properties.setProperty(PROPERTY_IDENTITY_ID, identityRecord.identityId());
    properties.setProperty("kind", identityRecord.kind().jsonValue());
    properties.setProperty("label", identityRecord.label());
    properties.setProperty(
        "ownerAppId", identityRecord.ownerAppId() == null ? "" : identityRecord.ownerAppId());
    properties.setProperty(PROPERTY_CREATED_AT, identityRecord.createdAt().toString());
    properties.setProperty(PROPERTY_UPDATED_AT, identityRecord.updatedAt().toString());
    properties.setProperty("fingerprint", identityRecord.fingerprint());
    properties.setProperty("usageScopes", joinScopes(identityRecord.usageScopes()));
    for (Map.Entry<String, String> entry : identityRecord.publicSummary().entrySet()) {
      if (entry.getKey().matches("[A-Za-z0-9_.-]{1,64}") && entry.getValue() != null) {
        properties.setProperty(PROPERTY_PUBLIC_SUMMARY_PREFIX + entry.getKey(), entry.getValue());
      }
    }
    return properties;
  }

  private static AppIdentityRecord identityRecord(Properties properties) {
    LinkedHashMap<String, String> publicSummary = LinkedHashMap.newLinkedHashMap(4);
    for (String name : properties.stringPropertyNames()) {
      if (name.startsWith(PROPERTY_PUBLIC_SUMMARY_PREFIX)) {
        publicSummary.put(
            name.substring(PROPERTY_PUBLIC_SUMMARY_PREFIX.length()), properties.getProperty(name));
      }
    }
    String ownerAppId = properties.getProperty("ownerAppId");
    return new AppIdentityRecord(
        properties.getProperty(PROPERTY_IDENTITY_ID),
        AppIdentityKind.fromJsonValue(properties.getProperty("kind")),
        properties.getProperty("label"),
        ownerAppId == null || ownerAppId.isBlank() ? null : ownerAppId,
        parseRequiredInstant(properties, PROPERTY_CREATED_AT),
        parseRequiredInstant(properties, PROPERTY_UPDATED_AT),
        publicSummary,
        properties.getProperty("fingerprint"),
        parseScopes(properties.getProperty("usageScopes")));
  }

  private static void requireIdentityRecordMatches(
      String expectedIdentityId, AppIdentityRecord identityRecord) {
    try {
      if (AppVaultPaths.normalizeIdentityId(expectedIdentityId)
          .equals(identityRecord.identityId())) {
        return;
      }
    } catch (AppVaultException exception) {
      throw new AppVaultException(
          400, "corrupt_vault_record", "Vault record metadata mismatch.", exception);
    }
    throw new AppVaultException(400, "corrupt_vault_record", "Vault record metadata mismatch.");
  }

  private static Properties grantProperties(AppIdentityGrant grant) {
    Properties properties = new Properties();
    properties.setProperty("grantId", grant.grantId());
    properties.setProperty(PROPERTY_IDENTITY_ID, grant.identityId());
    properties.setProperty(PROPERTY_APP_ID, grant.appId());
    properties.setProperty("scopes", joinScopes(grant.scopes()));
    properties.setProperty("status", grant.status().jsonValue());
    properties.setProperty(PROPERTY_CREATED_AT, grant.createdAt().toString());
    properties.setProperty(PROPERTY_UPDATED_AT, grant.updatedAt().toString());
    if (grant.expiresAt() != null) {
      properties.setProperty("expiresAt", grant.expiresAt().toString());
    }
    setIfPresent(properties, "grantedBy", grant.grantedBy());
    setIfPresent(properties, "reason", grant.reason());
    setIfPresent(properties, "sourceReviewReceiptId", grant.sourceReviewReceiptId());
    return properties;
  }

  private static AppIdentityGrant grantRecord(Properties properties) {
    return new AppIdentityGrant(
        properties.getProperty("grantId"),
        properties.getProperty(PROPERTY_IDENTITY_ID),
        properties.getProperty(PROPERTY_APP_ID),
        parseScopes(properties.getProperty("scopes")),
        AppIdentityGrantStatus.fromJsonValue(properties.getProperty("status")),
        parseRequiredInstant(properties, PROPERTY_CREATED_AT),
        parseRequiredInstant(properties, PROPERTY_UPDATED_AT),
        parseInstant(properties.getProperty("expiresAt")),
        properties.getProperty("grantedBy"),
        properties.getProperty("reason"),
        properties.getProperty("sourceReviewReceiptId"));
  }

  private static void requireGrantRecordMatches(Path path, AppIdentityGrant grantRecord) {
    String fileName = path.getFileName().toString();
    String expectedGrantId =
        fileName.substring(0, fileName.length() - GRANT_FILE_EXTENSION.length());
    try {
      if (AppVaultPaths.normalizeGrantId(expectedGrantId).equals(grantRecord.grantId())) {
        return;
      }
    } catch (AppVaultException exception) {
      throw new AppVaultException(
          400, "corrupt_vault_record", "Vault record metadata mismatch.", exception);
    }
    throw new AppVaultException(400, "corrupt_vault_record", "Vault record metadata mismatch.");
  }

  private static Set<AppIdentityGrantScope> parseScopes(String source) {
    TreeSet<AppIdentityGrantScope> scopes = new TreeSet<>();
    if (source != null && !source.isBlank()) {
      for (String part : source.split(",", -1)) {
        if (!part.isBlank()) {
          scopes.add(AppIdentityGrantScope.fromJsonValue(part));
        }
      }
    }
    return Set.copyOf(scopes);
  }

  private static String joinScopes(Set<AppIdentityGrantScope> scopes) {
    return scopes.stream()
        .sorted()
        .map(AppIdentityGrantScope::jsonValue)
        .collect(java.util.stream.Collectors.joining(","));
  }

  private static String sizeClass(int bytes) {
    if (bytes == 0) {
      return "empty";
    }
    if (bytes <= 1024) {
      return "small";
    }
    if (bytes <= 16 * 1024) {
      return "medium";
    }
    return "large";
  }

  private static void setIfPresent(Properties properties, String key, String value) {
    if (value != null && !value.isBlank()) {
      properties.setProperty(key, value);
    }
  }

  private static Instant parseInstant(String value) {
    return value == null || value.isBlank() ? null : parseStoredInstant(value);
  }

  private static Instant parseRequiredInstant(Properties properties, String fieldName) {
    String value = properties.getProperty(fieldName);
    if (value == null || value.isBlank()) {
      throw new AppVaultException(
          400, "corrupt_vault_record", "Vault record timestamp is missing.");
    }
    return parseStoredInstant(value);
  }

  private static Instant parseStoredInstant(String value) {
    try {
      return Instant.parse(value);
    } catch (DateTimeException exception) {
      throw new AppVaultException(
          400, "corrupt_vault_record", "Vault record timestamp is malformed.", exception);
    }
  }

  private static Properties readProperties(Path path) throws IOException {
    Properties properties = new Properties();
    try (InputStream input = Files.newInputStream(path)) {
      properties.load(input);
    }
    return properties;
  }

  private void writeProperties(Path path, Properties properties) throws IOException {
    createDirectory(path.getParent());
    Path temp = Files.createTempFile(path.getParent(), path.getFileName().toString(), ".tmp");
    try (OutputStream output =
        Files.newOutputStream(
            temp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
      properties.store(output, "Crypta app vault metadata");
    }
    hardenFileIfSupported(temp);
    atomicMove(temp, path);
    fileCommitHook.afterAtomicMove(path);
    hardenFileIfSupported(path);
  }

  private void writeString(Path path, String value) throws IOException {
    createDirectory(path.getParent());
    Path temp = Files.createTempFile(path.getParent(), path.getFileName().toString(), ".tmp");
    Files.writeString(temp, value, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
    hardenFileIfSupported(temp);
    atomicMove(temp, path);
    fileCommitHook.afterAtomicMove(path);
    hardenFileIfSupported(path);
  }

  private void restoreTextFile(Path path, String previousContent, IOException originalFailure) {
    try {
      if (previousContent == null) {
        Files.deleteIfExists(path);
      } else {
        writeString(path, previousContent);
      }
    } catch (IOException restoreFailure) {
      originalFailure.addSuppressed(restoreFailure);
    }
  }

  private static void atomicMove(Path temp, Path target) throws IOException {
    try {
      Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static void createDirectory(Path directory) throws IOException {
    Files.createDirectories(directory);
    hardenDirectoryIfSupported(directory);
  }

  private static void hardenFileIfSupported(Path file) throws IOException {
    PosixFileAttributeView view = Files.getFileAttributeView(file, PosixFileAttributeView.class);
    if (view != null) {
      view.setPermissions(OWNER_FILE);
    }
  }

  private static void hardenDirectoryIfSupported(Path directory) throws IOException {
    PosixFileAttributeView view =
        Files.getFileAttributeView(directory, PosixFileAttributeView.class);
    if (view != null) {
      view.setPermissions(OWNER_DIRECTORY);
    }
  }

  private static void deleteRecursively(Path root) throws IOException {
    if (!Files.exists(root)) {
      return;
    }
    try (var walk = Files.walk(root)) {
      for (Path path : walk.sorted(Comparator.reverseOrder()).toList()) {
        Files.deleteIfExists(path);
      }
    }
  }

  @FunctionalInterface
  interface FileCommitHook {
    void afterAtomicMove(Path target) throws IOException;
  }
}
