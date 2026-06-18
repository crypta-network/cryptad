package network.crypta.platform.appcatalog;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleStructureValidator;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.PackagedAppBundle;

/**
 * Creates deterministic third-party app submission packages.
 *
 * <p>The writer validates the staged bundle with appdist and packages a deterministic app-bundle
 * ZIP. It embeds the staged bundle and review documents at fixed package paths, writes top-level
 * JSON metadata, scans all evidence for forbidden secrets, and emits a STORED-entry ZIP.
 *
 * <p>This is the author-facing construction API behind {@code crypta-app submission create}. It
 * lets app authors provide a staged bundle plus review rationale files without knowing the daemon's
 * internal catalog or receipt formats. The output package is safe to hand to an offline reviewer:
 * it contains enough metadata and deterministic artifacts for pre-review, but it does not require
 * live network access or production reviewer credentials.
 *
 * <p>The writer treats the staged bundle as read-only input. It rejects outputs inside the bundle
 * tree, symlinked output parents that resolve into the bundle, oversized entries, and redaction
 * findings before writing the final ZIP. Repeated calls with the same request inputs produce the
 * same package bytes when the creation instant and submission id are fixed.
 */
public final class AppSubmissionPackageWriter {
  private static final Instant DEFAULT_CREATED_AT = Instant.EPOCH;
  private static final String SECURITY_NOTES_ENTRY = "review/security-notes.md";
  private static final String CHANGELOG_ENTRY = "review/changelog.md";
  private static final String MAINTAINER_ENTRY = "metadata/maintainer.json";
  private static final String SOURCE_ENTRY = "metadata/source.json";
  private static final String CATALOG_ENTRY_ARTIFACT = "artifacts/catalog-entry.properties";
  private static final long FIXED_ZIP_TIME_MILLIS = 0L;
  private static final int READ_BUFFER_BYTES = 64 * 1024;
  private static final String SUBMISSION_INPUT_SIZE_CAP_MESSAGE =
      "submission input exceeds size cap";
  private static final String OUTPUT_INSIDE_BUNDLE_MESSAGE =
      "submission output must not be inside the bundle directory";
  private static final String OUTPUT_PARENT_DIRECTORY_MESSAGE =
      "submission output parent must be a directory";
  private static final Set<PosixFilePermission> OWNER_ONLY_FILE_PERMISSIONS =
      Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

  private AppSubmissionPackageWriter() {}

  /**
   * Request for creating a submission package.
   *
   * <p>All paths are local inputs supplied by CLI tooling. Optional review documents are copied
   * into fixed package locations and then scanned, so callers should provide public rationale text
   * rather than private notes, tokens, raw fetched content, or local file paths. The {@code
   * nonProduction} flag is preserved in metadata and should be set for fixture submissions, CI
   * self-tests, and local dry runs.
   *
   * @param bundleDirectory staged app bundle root containing {@code cryptad-app.properties}
   * @param outputZip destination submission ZIP to create
   * @param submissionType submission intent recorded in metadata
   * @param resubmissionOf previous submission id required for resubmissions
   * @param submissionId optional explicit submission id for reproducible fixtures
   * @param submissionCreatedAt optional explicit creation instant for reproducible fixtures
   * @param permissionRationale optional permission rationale document copied into {@code review/}
   * @param sandboxRationale optional sandbox rationale document copied into {@code review/}
   * @param dataSchema optional app-data schema document copied into {@code review/}
   * @param backupRestore optional backup/restore document copied into {@code review/}
   * @param securityNotes optional security notes document copied into {@code review/}
   * @param changelog optional changelog document copied into {@code review/}
   * @param catalogEntry optional pre-generated catalog entry descriptor copied into artifacts
   * @param maintainer public maintainer metadata serialized into {@code metadata/}
   * @param sourceReference public source reference serialized into {@code metadata/}
   * @param nonProduction whether the submission is visibly local/test evidence
   * @param overwrite whether an existing output ZIP may be replaced
   */
  public record CreateRequest(
      Path bundleDirectory,
      Path outputZip,
      AppSubmissionType submissionType,
      Optional<String> resubmissionOf,
      Optional<String> submissionId,
      Optional<Instant> submissionCreatedAt,
      Optional<Path> permissionRationale,
      Optional<Path> sandboxRationale,
      Optional<Path> dataSchema,
      Optional<Path> backupRestore,
      Optional<Path> securityNotes,
      Optional<Path> changelog,
      Optional<Path> catalogEntry,
      AppSubmissionMaintainer maintainer,
      AppSubmissionSourceReference sourceReference,
      boolean nonProduction,
      boolean overwrite) {
    /**
     * Creates a normalized request.
     *
     * <p>The constructor checks required option containers and metadata records for null values.
     * Path existence, symlink safety, staged-bundle validity, required rationale documents, and
     * redaction cleanliness are checked by {@link #create(CreateRequest)} so callers receive errors
     * in the same order as the CLI workflow.
     */
    public CreateRequest {
      Objects.requireNonNull(bundleDirectory, "bundleDirectory");
      Objects.requireNonNull(outputZip, "outputZip");
      Objects.requireNonNull(submissionType, "submissionType");
      Objects.requireNonNull(resubmissionOf, "resubmissionOf");
      Objects.requireNonNull(submissionId, "submissionId");
      Objects.requireNonNull(submissionCreatedAt, "submissionCreatedAt");
      Objects.requireNonNull(permissionRationale, "permissionRationale");
      Objects.requireNonNull(sandboxRationale, "sandboxRationale");
      Objects.requireNonNull(dataSchema, "dataSchema");
      Objects.requireNonNull(backupRestore, "backupRestore");
      Objects.requireNonNull(securityNotes, "securityNotes");
      Objects.requireNonNull(changelog, "changelog");
      Objects.requireNonNull(catalogEntry, "catalogEntry");
      Objects.requireNonNull(maintainer, "maintainer");
      Objects.requireNonNull(sourceReference, "sourceReference");
    }
  }

  /**
   * Creates a deterministic submission package.
   *
   * <p>The method validates the staged bundle, creates a deterministic app-bundle artifact, gathers
   * review documents, emits metadata, scans every package entry, writes the submission ZIP, and
   * then verifies the package it just wrote. Verification at the end catches accidental divergence
   * between generated metadata and package contents before the caller receives a usable result.
   *
   * @param request package creation request containing bundle, review evidence, and output paths
   * @return verified package snapshot for the newly written submission ZIP
   * @throws IOException if the bundle, rationale files, temporary artifact, or output cannot be
   *     used
   * @throws AppCatalogException if the bundle, request, output path, or redaction scan is invalid
   */
  public static AppSubmissionPackage create(CreateRequest request) throws IOException {
    Path bundleRoot = request.bundleDirectory().toAbsolutePath().normalize();
    Path output = request.outputZip().toAbsolutePath().normalize();
    Path bundleRealRoot = bundleRoot.toRealPath();
    requireOutputPath(output, bundleRoot, bundleRealRoot, request.overwrite());
    AppBundleManifest manifest = AppBundleStructureValidator.validate(bundleRoot).manifest();
    Path artifact = createTemporaryArtifact(output.getParent());
    try {
      PackagedAppBundle packaged = AppBundlePackager.packageBundle(bundleRoot, artifact);
      Optional<String> bundleKeyId = readBundleSignatureKeyId(bundleRoot);
      Optional<String> permissionDigest = readPermissionDigest(request);
      Optional<String> catalogDigest = readCatalogEntryDigest(request);
      validateRequiredReviewDocs(request, manifest);
      Instant createdAt = request.submissionCreatedAt().orElse(DEFAULT_CREATED_AT);
      String submissionId =
          request
              .submissionId()
              .orElseGet(
                  () ->
                      defaultSubmissionId(
                          manifest,
                          request.submissionType(),
                          request.resubmissionOf().orElse(""),
                          packaged.artifactSha256(),
                          createdAt));
      LinkedHashMap<String, byte[]> entries = new LinkedHashMap<>();
      long[] payloadBytes = {0L};
      addBundleEntries(entries, bundleRoot, payloadBytes);
      addFileEntry(
          entries,
          AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY,
          artifact,
          AppSubmissionPackageVerifier.MAX_SUBMISSION_ENTRY_BYTES,
          payloadBytes);
      addRequestFileEntries(entries, request, payloadBytes);
      addGeneratedEntry(
          entries,
          MAINTAINER_ENTRY,
          AppSubmissionJson.write(request.maintainer().toJsonValue())
              .getBytes(StandardCharsets.UTF_8),
          payloadBytes);
      addGeneratedEntry(
          entries,
          SOURCE_ENTRY,
          AppSubmissionJson.write(request.sourceReference().toJsonValue())
              .getBytes(StandardCharsets.UTF_8),
          payloadBytes);
      String redactionDigest = redactionScanDigest(entries);
      AppSubmissionMetadata metadata =
          AppSubmissionMetadata.fromManifest(
              submissionId,
              createdAt,
              request.submissionType(),
              request.resubmissionOf().orElse(null),
              manifest,
              packaged.artifactSha256(),
              bundleKeyId.orElse(null),
              catalogDigest.orElse(null),
              permissionDigest.orElse(null),
              request.backupRestore().isPresent(),
              request.maintainer(),
              request.sourceReference(),
              redactionDigest,
              request.nonProduction());
      addGeneratedEntry(
          entries,
          AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY,
          metadata.toJson().getBytes(StandardCharsets.UTF_8),
          payloadBytes);
      List<AppSubmissionFinding> findings = scanEntries(entries);
      if (!findings.isEmpty()) {
        AppSubmissionFinding first = findings.getFirst();
        throw AppCatalogSidecars.invalidEntry(first.id() + ": " + first.summary());
      }
      writeZip(output, entries);
      return AppSubmissionPackageVerifier.verify(output);
    } finally {
      Files.deleteIfExists(artifact);
    }
  }

  private static void validateRequiredReviewDocs(
      CreateRequest request, AppBundleManifest manifest) {
    if (!manifest.permissions().isEmpty() && request.permissionRationale().isEmpty()) {
      throw AppCatalogSidecars.invalidEntry("permission rationale is required");
    }
    if ((!manifest.sandboxMode().manifestValue().equals("none") || manifest.sandboxRequired())
        && request.sandboxRationale().isEmpty()) {
      throw AppCatalogSidecars.invalidEntry("sandbox rationale is required");
    }
    if (manifest.dataSchemaContract().declared() && request.dataSchema().isEmpty()) {
      throw AppCatalogSidecars.invalidEntry("data schema declaration is required");
    }
    boolean ownsDurableData =
        manifest.permissions().stream().anyMatch(permission -> permission.startsWith("app.data."))
            || manifest.dataSchemaContract().declared();
    if (ownsDurableData && request.backupRestore().isEmpty()) {
      throw AppCatalogSidecars.invalidEntry("backup/restore declaration is required");
    }
  }

  private static Optional<String> readBundleSignatureKeyId(Path bundleRoot) throws IOException {
    Path signature = bundleRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME);
    if (!Files.exists(signature, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    return Optional.of(AppBundleVerifier.read(signature).keyId());
  }

  private static Optional<String> readPermissionDigest(CreateRequest request) throws IOException {
    return request.permissionRationale().isPresent()
        ? readDigest(request.permissionRationale().orElseThrow())
        : Optional.empty();
  }

  private static Optional<String> readCatalogEntryDigest(CreateRequest request) throws IOException {
    return request.catalogEntry().isPresent()
        ? readDigest(request.catalogEntry().orElseThrow())
        : Optional.empty();
  }

  private static Optional<String> readDigest(Path file) throws IOException {
    return Optional.of(
        sha256Hex(
            readRequiredFile(file, AppSubmissionPackageVerifier.MAX_SUBMISSION_TEXT_ENTRY_BYTES)));
  }

  private static void addRequestFileEntries(
      Map<String, byte[]> entries, CreateRequest request, long[] payloadBytes) throws IOException {
    if (request.catalogEntry().isPresent()) {
      addTextFileEntry(
          entries, CATALOG_ENTRY_ARTIFACT, request.catalogEntry().orElseThrow(), payloadBytes);
    }
    if (request.permissionRationale().isPresent()) {
      addTextFileEntry(
          entries,
          AppSubmissionPackageVerifier.PERMISSION_RATIONALE_ENTRY,
          request.permissionRationale().orElseThrow(),
          payloadBytes);
    }
    if (request.sandboxRationale().isPresent()) {
      addTextFileEntry(
          entries,
          AppSubmissionPackageVerifier.SANDBOX_RATIONALE_ENTRY,
          request.sandboxRationale().orElseThrow(),
          payloadBytes);
    }
    if (request.dataSchema().isPresent()) {
      addTextFileEntry(
          entries,
          AppSubmissionPackageVerifier.DATA_SCHEMA_ENTRY,
          request.dataSchema().orElseThrow(),
          payloadBytes);
    }
    if (request.backupRestore().isPresent()) {
      addTextFileEntry(
          entries,
          AppSubmissionPackageVerifier.BACKUP_RESTORE_ENTRY,
          request.backupRestore().orElseThrow(),
          payloadBytes);
    }
    if (request.securityNotes().isPresent()) {
      addTextFileEntry(
          entries, SECURITY_NOTES_ENTRY, request.securityNotes().orElseThrow(), payloadBytes);
    }
    if (request.changelog().isPresent()) {
      addTextFileEntry(entries, CHANGELOG_ENTRY, request.changelog().orElseThrow(), payloadBytes);
    }
  }

  private static void addTextFileEntry(
      Map<String, byte[]> entries, String entryName, Path file, long[] payloadBytes)
      throws IOException {
    addFileEntry(
        entries,
        entryName,
        file,
        AppSubmissionPackageVerifier.MAX_SUBMISSION_TEXT_ENTRY_BYTES,
        payloadBytes);
  }

  private static void addFileEntry(
      Map<String, byte[]> entries, String entryName, Path file, long maxBytes, long[] payloadBytes)
      throws IOException {
    byte[] bytes = readRequiredFile(file, maxBytes);
    addGeneratedEntry(entries, entryName, bytes, payloadBytes);
  }

  private static void addGeneratedEntry(
      Map<String, byte[]> entries, String entryName, byte[] bytes, long[] payloadBytes) {
    if (bytes.length > maxEntryBytes(entryName)) {
      throw AppCatalogSidecars.invalidEntry("submission entry exceeds size cap");
    }
    payloadBytes[0] += bytes.length;
    if (payloadBytes[0] > AppSubmissionPackageVerifier.MAX_SUBMISSION_PAYLOAD_BYTES) {
      throw AppCatalogSidecars.invalidEntry("submission package payload exceeds size cap");
    }
    entries.put(entryName, bytes);
  }

  private static byte[] readRequiredFile(Path file, long maxBytes) throws IOException {
    Path normalized = file.toAbsolutePath().normalize();
    if (Files.isSymbolicLink(normalized)) {
      throw AppCatalogSidecars.invalidEntry("submission input must not be a symbolic link");
    }
    if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)) {
      throw AppCatalogSidecars.invalidEntry("missing submission input");
    }
    if (Files.size(normalized) > maxBytes) {
      throw AppCatalogSidecars.invalidEntry(SUBMISSION_INPUT_SIZE_CAP_MESSAGE);
    }
    try (InputStream input = Files.newInputStream(normalized)) {
      return readBounded(input, maxBytes);
    }
  }

  private static byte[] readBounded(InputStream input, long maxBytes) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] buffer = new byte[READ_BUFFER_BYTES];
    long total = 0L;
    int read;
    while ((read = input.read(buffer)) >= 0) {
      if (read == 0) {
        continue;
      }
      total += read;
      if (total > maxBytes) {
        throw AppCatalogSidecars.invalidEntry(SUBMISSION_INPUT_SIZE_CAP_MESSAGE);
      }
      output.write(buffer, 0, read);
    }
    return output.toByteArray();
  }

  private static Path createTemporaryArtifact(Path parent) throws IOException {
    try {
      return Files.createTempFile(
          parent, "crypta-app-submission-", ".zip", ownerOnlyFileAttribute());
    } catch (UnsupportedOperationException _) {
      Path artifact = Files.createTempFile(parent, "crypta-app-submission-", ".zip");
      trySetOwnerOnlyFilePermissions(artifact);
      return artifact;
    }
  }

  private static FileAttribute<Set<PosixFilePermission>> ownerOnlyFileAttribute() {
    return PosixFilePermissions.asFileAttribute(OWNER_ONLY_FILE_PERMISSIONS);
  }

  private static void trySetOwnerOnlyFilePermissions(Path artifact) throws IOException {
    try {
      Files.setPosixFilePermissions(artifact, OWNER_ONLY_FILE_PERMISSIONS);
    } catch (UnsupportedOperationException _) {
      restrictPortableArtifactPermissions(artifact);
    }
  }

  private static void restrictPortableArtifactPermissions(Path artifact) throws IOException {
    java.io.File file = artifact.toFile();
    if (!file.setReadable(true, true)
        || !file.setWritable(true, true)
        || !file.setExecutable(false, true)) {
      throw new IOException("failed to restrict submission artifact permissions");
    }
  }

  private static void addBundleEntries(
      Map<String, byte[]> entries, Path bundleRoot, long[] payloadBytes) throws IOException {
    List<Path> paths;
    try (var stream = Files.walk(bundleRoot)) {
      paths = stream.sorted(Comparator.comparing(path -> relativeName(bundleRoot, path))).toList();
    }
    for (Path path : paths) {
      addBundleEntry(entries, bundleRoot, path, payloadBytes);
    }
  }

  private static void addBundleEntry(
      Map<String, byte[]> entries, Path bundleRoot, Path path, long[] payloadBytes)
      throws IOException {
    if (path.equals(bundleRoot)) {
      return;
    }
    if (Files.isSymbolicLink(path)) {
      throw AppCatalogSidecars.invalidEntry("bundle entries must not be symbolic links");
    }
    if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
      throw AppCatalogSidecars.invalidEntry("bundle entries must be regular files");
    }
    String relative = relativeName(bundleRoot, path);
    addFileEntry(
        entries,
        AppSubmissionPackageVerifier.BUNDLE_PREFIX + relative,
        path,
        AppSubmissionPackageVerifier.MAX_SUBMISSION_ENTRY_BYTES,
        payloadBytes);
  }

  private static long maxEntryBytes(String entryName) {
    if (entryName.equals(AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY)
        || entryName.startsWith(AppSubmissionPackageVerifier.BUNDLE_PREFIX)) {
      return AppSubmissionPackageVerifier.MAX_SUBMISSION_ENTRY_BYTES;
    }
    return AppSubmissionPackageVerifier.MAX_SUBMISSION_TEXT_ENTRY_BYTES;
  }

  private static String relativeName(Path root, Path path) {
    return root.relativize(path).toString().replace('\\', '/');
  }

  private static List<AppSubmissionFinding> scanEntries(Map<String, byte[]> entries) {
    List<AppSubmissionFinding> findings = new ArrayList<>();
    for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
      findings.addAll(AppSubmissionRedactionScanner.scanEntry(entry.getKey(), entry.getValue()));
    }
    return List.copyOf(findings);
  }

  private static String redactionScanDigest(Map<String, byte[]> entries) {
    StringBuilder builder = new StringBuilder();
    for (String name : entries.keySet().stream().sorted().toList()) {
      builder.append(name).append('\n');
    }
    builder.append("redaction-scan-v1\n");
    return sha256Hex(builder.toString().getBytes(StandardCharsets.UTF_8));
  }

  private static String defaultSubmissionId(
      AppBundleManifest manifest,
      AppSubmissionType type,
      String resubmissionOf,
      String bundleDigest,
      Instant createdAt) {
    String input =
        manifest.appId()
            + "\n"
            + manifest.appVersion()
            + "\n"
            + type.jsonValue()
            + "\n"
            + resubmissionOf
            + "\n"
            + bundleDigest
            + "\n"
            + createdAt;
    return "sub-" + sha256Hex(input.getBytes(StandardCharsets.UTF_8)).substring(0, 24);
  }

  private static void requireOutputPath(
      Path output, Path bundleRoot, Path bundleRealRoot, boolean overwrite) throws IOException {
    rejectOutputInsideBundle(output, bundleRoot, bundleRealRoot);
    Path parent = output.getParent();
    if (parent == null) {
      throw AppCatalogSidecars.invalidEntry("submission output path must have a parent directory");
    }
    createSafeOutputParentDirectories(parent, bundleRealRoot);
    if (isInsideOrEqual(parent.toRealPath(), bundleRealRoot)) {
      throw AppCatalogSidecars.invalidEntry(OUTPUT_INSIDE_BUNDLE_MESSAGE);
    }
    if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
      if (!overwrite) {
        throw AppCatalogSidecars.invalidEntry("submission output already exists");
      }
      if (Files.isSymbolicLink(output) || !Files.isRegularFile(output, LinkOption.NOFOLLOW_LINKS)) {
        throw AppCatalogSidecars.invalidEntry("submission output must be a regular file");
      }
      rejectOutputInsideBundle(output.toRealPath(), bundleRoot, bundleRealRoot);
    }
  }

  private static void createSafeOutputParentDirectories(Path parent, Path bundleRealRoot)
      throws IOException {
    Path existingAncestor = parent;
    while (existingAncestor != null && !Files.exists(existingAncestor, LinkOption.NOFOLLOW_LINKS)) {
      existingAncestor = existingAncestor.getParent();
    }
    if (existingAncestor != null && Files.isSymbolicLink(existingAncestor)) {
      if (isInsideOrEqual(existingAncestor.toRealPath(), bundleRealRoot)) {
        throw AppCatalogSidecars.invalidEntry(OUTPUT_INSIDE_BUNDLE_MESSAGE);
      }
      throw AppCatalogSidecars.invalidEntry(OUTPUT_PARENT_DIRECTORY_MESSAGE);
    }
    if (existingAncestor == null
        || !Files.isDirectory(existingAncestor, LinkOption.NOFOLLOW_LINKS)) {
      throw AppCatalogSidecars.invalidEntry(OUTPUT_PARENT_DIRECTORY_MESSAGE);
    }
    if (isInsideOrEqual(existingAncestor.toRealPath(), bundleRealRoot)) {
      throw AppCatalogSidecars.invalidEntry(OUTPUT_INSIDE_BUNDLE_MESSAGE);
    }
    Files.createDirectories(parent);
    if (!Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
      throw AppCatalogSidecars.invalidEntry(OUTPUT_PARENT_DIRECTORY_MESSAGE);
    }
  }

  private static void rejectOutputInsideBundle(Path output, Path bundleRoot, Path bundleRealRoot) {
    if (isInsideOrEqual(output, bundleRoot) || isInsideOrEqual(output, bundleRealRoot)) {
      throw AppCatalogSidecars.invalidEntry(OUTPUT_INSIDE_BUNDLE_MESSAGE);
    }
  }

  private static boolean isInsideOrEqual(Path candidate, Path root) {
    return candidate.equals(root) || candidate.startsWith(root);
  }

  private static void writeZip(Path output, Map<String, byte[]> entries) throws IOException {
    List<Map.Entry<String, byte[]>> sorted = new ArrayList<>(entries.entrySet());
    sorted.sort(Map.Entry.comparingByKey());
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(output))) {
      for (Map.Entry<String, byte[]> entry : sorted) {
        ZipEntry zipEntry = new ZipEntry(entry.getKey());
        byte[] bytes = entry.getValue();
        CRC32 crc = new CRC32();
        crc.update(bytes);
        zipEntry.setMethod(ZipEntry.STORED);
        zipEntry.setSize(bytes.length);
        zipEntry.setCompressedSize(bytes.length);
        zipEntry.setCrc(crc.getValue());
        zipEntry.setTime(FIXED_ZIP_TIME_MILLIS);
        zip.putNextEntry(zipEntry);
        zip.write(bytes);
        zip.closeEntry();
      }
    }
  }

  private static String sha256Hex(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
