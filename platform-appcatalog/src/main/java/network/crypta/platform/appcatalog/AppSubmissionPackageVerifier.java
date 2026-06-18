package network.crypta.platform.appcatalog;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.appdist.AppBundleDigest;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppDataMigrationStep;

/**
 * Offline verifier for deterministic third-party app submission packages.
 *
 * <p>Verification is intentionally local and hermetic. It checks normalized ZIP paths, required
 * metadata, manifest binding, artifact digests, rationale presence, and redaction cleanliness
 * without using network access or trusting catalog publisher metadata.
 *
 * <p>The verifier is the boundary between untrusted author-supplied ZIP files and reviewer
 * evidence. Public entry points read the submission into a bounded byte snapshot, scan the ZIP
 * envelope for hidden bytes, parse the metadata and manifest from that snapshot, and compare the
 * packaged artifact to the reviewed {@code bundle/} tree. Blocker findings are returned through
 * {@link #inspect(Path)} for machine-readable pre-review reports or converted to an exception by
 * {@link #verify(Path)} and {@link #extractBundle(Path, Path)}.
 *
 * <p>No method in this class performs network access, signature trust evaluation, or catalog
 * promotion. Those steps remain separate so submission verification can run in CI, release
 * certification, and local reviewer tooling without production credentials.
 */
public final class AppSubmissionPackageVerifier {
  /**
   * Top-level metadata JSON entry.
   *
   * <p>This file is parsed before promotion checks bind metadata to the embedded manifest and
   * artifact bytes.
   */
  public static final String SUBMISSION_METADATA_ENTRY = "crypta-app-submission.json";

  /**
   * Bundle directory prefix inside the submission package.
   *
   * <p>Entries under this prefix represent the reviewed staged bundle tree and must match the
   * deterministic artifact payload.
   */
  public static final String BUNDLE_PREFIX = "bundle/";

  /**
   * Packaged bundle artifact entry inside the submission package.
   *
   * <p>This ZIP is the installable artifact that review receipts and catalog candidates bind to.
   */
  public static final String BUNDLE_ARTIFACT_ENTRY = "artifacts/app-bundle.zip";

  /**
   * Permission rationale review document entry.
   *
   * <p>The verifier requires this document when the manifest requests permissions and validates its
   * digest whenever metadata declares one.
   */
  public static final String PERMISSION_RATIONALE_ENTRY = "review/permission-rationale.md";

  /**
   * Sandbox rationale review document entry.
   *
   * <p>Submissions with non-default sandbox requirements use this document to explain the app-host
   * isolation expectations to reviewers.
   */
  public static final String SANDBOX_RATIONALE_ENTRY = "review/sandbox-rationale.md";

  /**
   * Durable data-schema review document entry.
   *
   * <p>Apps that declare durable app-data schema or migration behavior must provide reviewer-facing
   * schema notes here.
   */
  public static final String DATA_SCHEMA_ENTRY = "review/data-schema.md";

  /**
   * Backup/restore review document entry.
   *
   * <p>Apps that own durable data use this evidence to state supported backup/restore behavior or a
   * documented unsupported rationale.
   */
  public static final String BACKUP_RESTORE_ENTRY = "review/backup-restore.md";

  private static final String BUNDLE_MANIFEST_ENTRY =
      BUNDLE_PREFIX + AppBundleManifestParser.MANIFEST_FILE_NAME;
  private static final String BUNDLE_SIGNATURE_ENTRY =
      BUNDLE_PREFIX + AppBundleSignature.SIGNATURE_FILE_NAME;
  private static final String CATALOG_ENTRY_ARTIFACT = "artifacts/catalog-entry.properties";
  private static final String REDACTION_SCAN_VERSION = "redaction-scan-v1";

  static final long MAX_SUBMISSION_PACKAGE_BYTES = 128L * 1024L * 1024L;
  static final long MAX_SUBMISSION_PAYLOAD_BYTES = 96L * 1024L * 1024L;
  static final long MAX_SUBMISSION_ENTRY_BYTES = 48L * 1024L * 1024L;
  static final long MAX_SUBMISSION_TEXT_ENTRY_BYTES = 8L * 1024L * 1024L;
  private static final int MAX_SUBMISSION_ZIP_ENTRIES = 10_000;
  private static final int MAX_ARTIFACT_ZIP_ENTRIES = 10_000;
  private static final int READ_BUFFER_BYTES = 64 * 1024;

  private static final int END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054B50;
  private static final int CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014B50;
  private static final int END_OF_CENTRAL_DIRECTORY_MIN_BYTES = 22;
  private static final int CENTRAL_DIRECTORY_HEADER_BYTES = 46;
  private static final int ZIP64_UNSIGNED_SHORT_MARKER = 0xFFFF;
  private static final long ZIP64_UNSIGNED_INT_MARKER = 0xFFFF_FFFFL;
  private static final int UNIX_HOST_PLATFORM = 3;
  private static final int UNIX_MODE_SHIFT = 16;
  private static final int UNIX_REGULAR_FILE_TYPE = 32_768;
  private static final int UNIX_FILE_TYPE_MASK = 0xF000;
  private static final int UNIX_OWNER_EXECUTE_BIT = 0x0040;
  private static final int UNIX_GROUP_EXECUTE_BIT = 0x0008;
  private static final int UNIX_OTHERS_EXECUTE_BIT = 0x0001;
  private static final int UNIX_EXECUTE_BITS =
      UNIX_OWNER_EXECUTE_BIT | UNIX_GROUP_EXECUTE_BIT | UNIX_OTHERS_EXECUTE_BIT;
  private static final int FIXED_DOS_TIME = 0;
  private static final int FIXED_DOS_DATE = 0x21;
  private static final char UTF_8_BOM = '\uFEFF';
  private static final byte[] FIXED_TIMESTAMP_EXTRA = {0x55, 0x54, 0x05, 0x00, 0x01, 0, 0, 0, 0};
  private static final byte[] EMPTY_BYTES = new byte[0];
  private static final String PACKAGE_ENTRY_SIZE_LIMIT_ID = "package.entry-size-limit";
  private static final String SUBMISSION_ENTRY_SIZE_CAP_SUMMARY =
      "Submission entry exceeds the size cap";
  private static final Set<PosixFilePermission> OWNER_ONLY_DIRECTORY_PERMISSIONS =
      Set.of(
          PosixFilePermission.OWNER_READ,
          PosixFilePermission.OWNER_WRITE,
          PosixFilePermission.OWNER_EXECUTE);

  private AppSubmissionPackageVerifier() {}

  /**
   * Bounded artifact bytes read from the same submission snapshot that produced a verified package.
   *
   * <p>Catalog-candidate tooling uses this value when it needs to copy {@code
   * artifacts/app-bundle.zip} out of an untrusted submission. The verifier owns the read so callers
   * do not reopen the user-supplied path after verification, and the byte array is defensively
   * copied to keep the verified artifact binding immutable.
   */
  @SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
  public static final class VerifiedBundleArtifact {
    private final AppSubmissionPackage submission;
    private final byte[] bytes;

    /**
     * Creates a verified artifact result with defensive copies for mutable byte content.
     *
     * @param submission verified package metadata for the exact snapshot that contained the
     *     artifact
     * @param bytes bounded artifact bytes from {@link #BUNDLE_ARTIFACT_ENTRY}
     */
    public VerifiedBundleArtifact(AppSubmissionPackage submission, byte[] bytes) {
      this.submission = Objects.requireNonNull(submission, "submission");
      this.bytes = Objects.requireNonNull(bytes, "bytes").clone();
    }

    /**
     * Returns the verified package metadata bound to these artifact bytes.
     *
     * @return verified submission snapshot
     */
    public AppSubmissionPackage submission() {
      return submission;
    }

    /**
     * Returns a defensive copy of the bounded artifact bytes.
     *
     * @return bytes from {@link #BUNDLE_ARTIFACT_ENTRY}
     */
    public byte[] bytes() {
      return bytes.clone();
    }
  }

  /**
   * Verifies a submission package and fails closed on blocker findings.
   *
   * <p>This is the strict entry point for commands that need a verified package before continuing.
   * It delegates to {@link #inspect(Path)}, then throws the first blocker as an invalid
   * catalog-entry exception. Use {@link #inspect(Path)} when callers need a full redacted finding
   * list for pre-review reports or JSON output.
   *
   * @param submissionZip submission package ZIP to read as one bounded byte snapshot
   * @return verified package snapshot with parsed metadata, manifest, digests, and entry names
   * @throws IOException if the package file cannot be read or a temporary snapshot cannot be used
   * @throws AppCatalogException if structural, binding, or redaction blockers are present
   */
  public static AppSubmissionPackage verify(Path submissionZip) throws IOException {
    AppSubmissionVerification verification = inspect(submissionZip);
    return requireVerifiedSubmission(verification);
  }

  /**
   * Verifies a submission package and returns its canonical bundle artifact from the same snapshot.
   *
   * <p>The method reads the submission path once into the verifier's bounded package snapshot,
   * performs the normal structural and redaction verification, then reads {@link
   * #BUNDLE_ARTIFACT_ENTRY} from that verified snapshot with the artifact size cap enforced while
   * streaming. It is intended for CLI workflows that need to copy the reviewed artifact to a
   * catalog-candidate location without reopening a mutable submission path.
   *
   * @param submissionZip submission package ZIP to verify and read
   * @return verified package metadata plus bounded artifact bytes
   * @throws IOException if the package file cannot be read or a temporary snapshot cannot be used
   * @throws AppCatalogException if verification fails or the artifact entry is missing/oversized
   */
  public static VerifiedBundleArtifact readVerifiedBundleArtifact(Path submissionZip)
      throws IOException {
    Path normalized = requireSubmissionZip(submissionZip);
    byte[] submissionBytes = readSubmissionBytes(normalized);
    AppSubmissionPackage submission =
        requireVerifiedSubmission(
            inspectSubmissionBytes(normalized.getFileName().toString(), submissionBytes));
    try (SubmissionSnapshot parsedZip = writeSubmissionSnapshot(submissionBytes);
        ZipFile zip = new ZipFile(parsedZip.path().toFile())) {
      ZipEntry artifactEntry = zip.getEntry(BUNDLE_ARTIFACT_ENTRY);
      if (artifactEntry == null || artifactEntry.isDirectory()) {
        throw AppCatalogSidecars.invalidEntry("missing submission entry: " + BUNDLE_ARTIFACT_ENTRY);
      }
      return new VerifiedBundleArtifact(
          submission, read(zip, artifactEntry, AppCatalogSidecars.MAX_ARTIFACT_BYTES));
    }
  }

  private static AppSubmissionPackage requireVerifiedSubmission(
      AppSubmissionVerification verification) {
    if (verification.hasBlockers()) {
      AppSubmissionFinding first =
          verification.findings().stream()
              .filter(AppSubmissionFinding::blocksPromotion)
              .findFirst()
              .orElseThrow();
      throw AppCatalogSidecars.invalidEntry(first.id() + ": " + first.summary());
    }
    return verification.submission();
  }

  /**
   * Inspects a submission package and returns redacted findings instead of throwing for policy
   * blockers.
   *
   * <p>The returned verification result may contain a {@code null} package when parsing cannot
   * continue safely, but it will then include at least one blocker finding. This behavior lets CLI
   * and release-certification code emit deterministic fail reports for malformed submissions
   * without exposing raw package bytes, local paths, tokens, or private insert URIs.
   *
   * @param submissionZip submission package ZIP to read and inspect offline
   * @return parsed package plus redacted structural and redaction findings
   * @throws IOException if the package file cannot be read or a temporary snapshot cannot be used
   */
  public static AppSubmissionVerification inspect(Path submissionZip) throws IOException {
    Path normalized = requireSubmissionZip(submissionZip);
    return inspectSubmissionBytes(
        normalized.getFileName().toString(), readSubmissionBytes(normalized));
  }

  /**
   * Inspects a submission package and extracts the bundle from that same byte snapshot when clean.
   *
   * <p>This combines the non-throwing reporting behavior of {@link #inspect(Path)} with the
   * snapshot consistency guarantee of {@link #extractBundle(Path, Path)}. Malformed or blocked
   * packages return their redacted verification findings without touching the target directory.
   * Packages without blockers are extracted from the exact bytes whose digest and manifest metadata
   * are returned in the verification result.
   *
   * @param submissionZip submission package ZIP to read as one bounded byte snapshot
   * @param targetDirectory existing empty or creatable target directory owned by the caller
   * @return parsed package plus redacted structural and redaction findings
   * @throws IOException if the package file cannot be read or extraction fails
   * @throws AppCatalogException if the target directory is unsafe
   */
  public static AppSubmissionVerification inspectAndExtractBundle(
      Path submissionZip, Path targetDirectory) throws IOException {
    Path normalized = requireSubmissionZip(submissionZip);
    byte[] submissionBytes = readSubmissionBytes(normalized);
    AppSubmissionVerification verification =
        inspectSubmissionBytes(normalized.getFileName().toString(), submissionBytes);
    if (verification.hasBlockers()) {
      return verification;
    }
    Path target = prepareExtractionTarget(targetDirectory);
    extractBundleFromSnapshot(submissionBytes, target, verification.submission());
    return verification;
  }

  private static AppSubmissionVerification inspectSubmissionBytes(
      String submissionName, byte[] submissionBytes) throws IOException {
    String submissionDigest = sha256Hex(submissionBytes);
    List<AppSubmissionFinding> findings =
        new ArrayList<>(
            AppSubmissionRedactionScanner.scanZipEnvelope(submissionName, submissionBytes));
    if (hasBlockers(findings)) {
      return new AppSubmissionVerification(null, findings);
    }
    try (SubmissionSnapshot parsedZip = writeSubmissionSnapshot(submissionBytes);
        ZipFile zip = new ZipFile(parsedZip.path().toFile())) {
      Map<String, ZipEntry> entries = readEntries(zip, findings);
      validateNoBundlePathPrefixConflicts(entries, findings);
      if (hasBlockers(findings)) {
        return new AppSubmissionVerification(null, findings);
      }
      byte[] metadataBytes =
          requiredEntryBytes(
              zip, entries, SUBMISSION_METADATA_ENTRY, MAX_SUBMISSION_TEXT_ENTRY_BYTES, findings);
      if (metadataBytes.length == 0) {
        return new AppSubmissionVerification(null, findings);
      }
      findings.addAll(
          AppSubmissionRedactionScanner.scanEntry(SUBMISSION_METADATA_ENTRY, metadataBytes));
      if (hasBlockers(findings)) {
        return new AppSubmissionVerification(null, findings);
      }
      AppSubmissionMetadata metadata = parseMetadata(metadataBytes, findings);
      if (metadata == null) {
        return new AppSubmissionVerification(null, findings);
      }
      byte[] manifestBytes =
          requiredEntryBytes(
              zip, entries, BUNDLE_MANIFEST_ENTRY, MAX_SUBMISSION_TEXT_ENTRY_BYTES, findings);
      if (manifestBytes.length == 0) {
        return new AppSubmissionVerification(null, findings);
      }
      findings.addAll(
          AppSubmissionRedactionScanner.scanEntry(BUNDLE_MANIFEST_ENTRY, manifestBytes));
      if (hasBlockers(findings)) {
        return new AppSubmissionVerification(null, findings);
      }
      AppBundleManifest manifest = parseManifest(manifestBytes, findings);
      if (manifest == null) {
        return new AppSubmissionVerification(null, findings);
      }
      byte[] artifactBytes =
          requiredEntryBytes(
              zip, entries, BUNDLE_ARTIFACT_ENTRY, AppCatalogSidecars.MAX_ARTIFACT_BYTES, findings);
      if (artifactBytes.length == 0) {
        return new AppSubmissionVerification(null, findings);
      }
      validateMetadataBinding(metadata, manifest, artifactBytes, entries, zip, findings);
      for (ZipEntry entry : entries.values()) {
        if (!entry.isDirectory()) {
          scanEntry(zip, entry, findings);
        }
      }
      AppSubmissionPackage submission =
          new AppSubmissionPackage(
              metadata,
              manifest,
              submissionDigest,
              sha256Hex(manifestBytes),
              artifactBytes.length,
              entries.keySet().stream().sorted().toList());
      return new AppSubmissionVerification(submission, findings);
    }
  }

  /**
   * Extracts the submitted staged bundle into a caller-owned empty directory.
   *
   * <p>The method first verifies the exact byte snapshot that will be extracted. The target
   * directory must be empty or absent, must not resolve through symbolic links, and is populated
   * only with normalized entries from {@link #BUNDLE_PREFIX}. Owner execute permission is restored
   * when verified artifact metadata marks an entry executable so native app launchers remain
   * runnable without broadening access for group or other users.
   *
   * @param submissionZip submission package ZIP to verify and extract from the same byte snapshot
   * @param targetDirectory existing empty or creatable target directory owned by the caller
   * @throws IOException if extraction or temporary snapshot handling fails
   * @throws AppCatalogException if verification fails or the target directory is unsafe
   */
  @SuppressWarnings("java:S5042")
  public static void extractBundle(Path submissionZip, Path targetDirectory) throws IOException {
    Path normalized = requireSubmissionZip(submissionZip);
    byte[] submissionBytes = readSubmissionBytes(normalized);
    AppSubmissionPackage submission =
        requireVerifiedSubmission(
            inspectSubmissionBytes(normalized.getFileName().toString(), submissionBytes));
    Path target = prepareExtractionTarget(targetDirectory);
    extractBundleFromSnapshot(submissionBytes, target, submission);
  }

  @SuppressWarnings("java:S5042")
  private static void extractBundleFromSnapshot(
      byte[] submissionBytes, Path target, AppSubmissionPackage submission) throws IOException {
    try (SubmissionSnapshot parsedZip = writeSubmissionSnapshot(submissionBytes);
        ZipFile zip = new ZipFile(parsedZip.path().toFile())) {
      ZipEntry artifactEntry = zip.getEntry(BUNDLE_ARTIFACT_ENTRY);
      if (artifactEntry == null || artifactEntry.isDirectory()) {
        throw AppCatalogSidecars.invalidEntry("missing submission entry: " + BUNDLE_ARTIFACT_ENTRY);
      }
      byte[] artifactBytes = read(zip, artifactEntry, AppCatalogSidecars.MAX_ARTIFACT_BYTES);
      Map<String, Integer> artifactUnixModes = artifactUnixModes(artifactBytes);
      Enumeration<? extends ZipEntry> enumeration = zip.entries();
      while (enumeration.hasMoreElements()) {
        ZipEntry entry = enumeration.nextElement();
        String name = entry.getName();
        if (!name.startsWith(BUNDLE_PREFIX) || entry.isDirectory()) {
          continue;
        }
        String bundleRelativeName = name.substring(BUNDLE_PREFIX.length());
        Path output = target.resolve(bundleRelativeName).normalize();
        if (!output.startsWith(target)) {
          throw AppCatalogSidecars.invalidEntry("bundle entry escapes extraction directory");
        }
        createExtractionParentDirectories(output.getParent(), target);
        writeExtractionFile(output, read(zip, entry, maxReadableEntryBytes(name)));
        restoreExecutableBits(output, artifactUnixModes.getOrDefault(bundleRelativeName, 0));
      }
    }
    if (!submission
        .manifest()
        .appId()
        .equals(
            AppBundleManifestParser.parse(
                    target.resolve(AppBundleManifestParser.MANIFEST_FILE_NAME))
                .appId())) {
      throw AppCatalogSidecars.invalidEntry("extracted bundle manifest changed unexpectedly");
    }
  }

  private static Path prepareExtractionTarget(Path targetDirectory) throws IOException {
    Path target = targetDirectory.toAbsolutePath().normalize();
    rejectSymbolicLinkPath(target);
    if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
      requireExtractionDirectory(target);
      requireEmptyExtractionDirectory(target);
      return target;
    }
    createSafeDirectoryTree(target);
    return target;
  }

  private static void requireExtractionDirectory(Path target) {
    if (Files.isSymbolicLink(target) || !Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS)) {
      throw AppCatalogSidecars.invalidEntry("bundle extraction target must be an empty directory");
    }
  }

  private static void requireEmptyExtractionDirectory(Path target) throws IOException {
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(target)) {
      if (entries.iterator().hasNext()) {
        throw AppCatalogSidecars.invalidEntry("bundle extraction target must be empty");
      }
    }
  }

  private static void createExtractionParentDirectories(Path parent, Path target)
      throws IOException {
    if (parent == null || !parent.normalize().startsWith(target)) {
      throw AppCatalogSidecars.invalidEntry("bundle entry escapes extraction directory");
    }
    createSafeDirectoryTree(parent);
  }

  private static void createSafeDirectoryTree(Path directory) throws IOException {
    rejectSymbolicLinkPath(directory);
    List<Path> missing = new ArrayList<>();
    Path current = directory;
    while (current != null && !Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
      missing.add(current);
      current = current.getParent();
    }
    if (current != null) {
      requireExtractionDirectory(current);
    }
    for (int index = missing.size() - 1; index >= 0; index--) {
      Path path = missing.get(index);
      try {
        Files.createDirectory(path);
      } catch (FileAlreadyExistsException | NotDirectoryException _) {
        requireExtractionDirectory(path);
      }
    }
  }

  private static void rejectSymbolicLinkPath(Path path) {
    Path current = path.getRoot();
    for (Path component : path) {
      current = current == null ? component : current.resolve(component);
      if (Files.isSymbolicLink(current)) {
        throw AppCatalogSidecars.invalidEntry(
            "bundle extraction target must not contain symbolic links");
      }
    }
  }

  private static void writeExtractionFile(Path output, byte[] bytes) throws IOException {
    if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
      throw AppCatalogSidecars.invalidEntry("bundle extraction target contains existing entries");
    }
    try (OutputStream stream =
        Files.newOutputStream(
            output,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE,
            LinkOption.NOFOLLOW_LINKS)) {
      stream.write(bytes);
    } catch (FileAlreadyExistsException | NotDirectoryException _) {
      throw AppCatalogSidecars.invalidEntry("bundle extraction target contains existing entries");
    }
  }

  private static Map<String, Integer> artifactUnixModes(byte[] artifactBytes) {
    try {
      CentralDirectoryRange range = centralDirectoryRange(artifactBytes);
      LinkedHashMap<String, Integer> unixModes = new LinkedHashMap<>();
      int offset = range.offset();
      int centralDirectoryEnd = range.offset() + range.size();
      for (int index = 0; index < range.entryCount(); index++) {
        CentralDirectoryRead read = readArtifactCentralDirectoryEntry(artifactBytes, offset);
        ArtifactZipMetadata metadata = read.metadata();
        unixModes.put(metadata.name(), metadata.unixMode());
        offset = read.nextOffset();
        if (offset > centralDirectoryEnd) {
          throw new IllegalArgumentException("central directory entry escapes directory range");
        }
      }
      if (offset != centralDirectoryEnd) {
        throw new IllegalArgumentException("central directory contains trailing bytes");
      }
      return Map.copyOf(unixModes);
    } catch (RuntimeException _) {
      throw AppCatalogSidecars.invalidEntry("app-bundle.zip metadata is invalid");
    }
  }

  private static void restoreExecutableBits(Path output, int unixMode) throws IOException {
    if ((unixMode & UNIX_EXECUTE_BITS) == 0) {
      return;
    }
    try {
      Set<PosixFilePermission> permissions =
          new LinkedHashSet<>(Files.getPosixFilePermissions(output));
      permissions.add(PosixFilePermission.OWNER_EXECUTE);
      Files.setPosixFilePermissions(output, permissions);
    } catch (UnsupportedOperationException _) {
      if (!output.toFile().setExecutable(true, true)) {
        throw AppCatalogSidecars.invalidEntry("bundle executable permission could not be restored");
      }
    }
  }

  private static Path requireSubmissionZip(Path submissionZip) {
    Path normalized = submissionZip.toAbsolutePath().normalize();
    if (Files.isSymbolicLink(normalized)) {
      throw AppCatalogSidecars.invalidEntry("submission package must not be a symbolic link");
    }
    if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)) {
      throw AppCatalogSidecars.invalidEntry("submission package is missing");
    }
    return normalized;
  }

  // Archive inspection is safe here because the submission byte snapshot is capped, entry names are
  // redaction-scanned, and entry count, per-entry bytes, and total uncompressed bytes are bounded.
  @SuppressWarnings("java:S5042")
  private static Map<String, ZipEntry> readEntries(
      ZipFile zip, List<AppSubmissionFinding> findings) {
    LinkedHashMap<String, ZipEntry> entries = new LinkedHashMap<>();
    long declaredPayloadBytes = 0L;
    int entryCount = 0;
    Enumeration<? extends ZipEntry> enumeration = zip.entries();
    while (enumeration.hasMoreElements()) {
      ZipEntry entry = enumeration.nextElement();
      entryCount++;
      if (entryCount > MAX_SUBMISSION_ZIP_ENTRIES) {
        findings.add(
            blocker(
                "package.entry-count-limit", "Submission package contains too many ZIP entries"));
        break;
      }
      String name = entry.getName();
      AppSubmissionRedactionScanner.addPathFindings(findings, name);
      findings.addAll(
          AppSubmissionRedactionScanner.scanEntry(
              "zip-entry-name/" + entries.size() + ".txt", name.getBytes(StandardCharsets.UTF_8)));
      long maxEntryBytes = maxReadableEntryBytes(name);
      if (entry.getSize() > maxEntryBytes || entry.getCompressedSize() > maxEntryBytes) {
        findings.add(blocker(PACKAGE_ENTRY_SIZE_LIMIT_ID, name, SUBMISSION_ENTRY_SIZE_CAP_SUMMARY));
      }
      if (!entry.isDirectory() && entry.getSize() > 0L) {
        declaredPayloadBytes += entry.getSize();
        if (declaredPayloadBytes > MAX_SUBMISSION_PAYLOAD_BYTES) {
          findings.add(
              blocker(
                  "package.uncompressed-size-limit",
                  "Submission package uncompressed payload exceeds the size cap"));
        }
      }
      if (entries.putIfAbsent(name, entry) != null) {
        findings.add(blocker("package.duplicate-entry", name, "Duplicate ZIP entry"));
      }
    }
    return entries.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .collect(
            LinkedHashMap::new,
            (map, entry) -> map.put(entry.getKey(), entry.getValue()),
            LinkedHashMap::putAll);
  }

  private static void validateNoBundlePathPrefixConflicts(
      Map<String, ZipEntry> entries, List<AppSubmissionFinding> findings) {
    List<String> bundleFiles =
        entries.entrySet().stream()
            .filter(
                entry ->
                    entry.getKey().startsWith(BUNDLE_PREFIX) && !entry.getValue().isDirectory())
            .map(entry -> entry.getKey().substring(BUNDLE_PREFIX.length()))
            .filter(name -> !name.isBlank())
            .sorted()
            .toList();
    for (int index = 0; index < bundleFiles.size(); index++) {
      String parent = bundleFiles.get(index);
      String childPrefix = parent + "/";
      int childIndex = index + 1;
      if (childIndex < bundleFiles.size() && bundleFiles.get(childIndex).startsWith(childPrefix)) {
        findings.add(
            blocker(
                "package.bundle-path-prefix-conflict",
                BUNDLE_PREFIX + parent,
                "Bundle entry conflicts with a child path"));
        return;
      }
    }
  }

  private static AppSubmissionMetadata parseMetadata(
      byte[] metadataBytes, List<AppSubmissionFinding> findings) {
    try {
      return AppSubmissionMetadata.parse(new String(metadataBytes, StandardCharsets.UTF_8));
    } catch (RuntimeException _) {
      findings.add(blocker("metadata.parse-invalid", "Submission metadata is invalid"));
      return null;
    }
  }

  private static AppBundleManifest parseManifest(
      byte[] manifestBytes, List<AppSubmissionFinding> findings) {
    try {
      return AppBundleManifestParser.parseContent(
          new String(manifestBytes, StandardCharsets.UTF_8));
    } catch (IOException | RuntimeException _) {
      findings.add(blocker("manifest.parse-invalid", "Bundle manifest is invalid"));
      return null;
    }
  }

  private static void validateMetadataBinding(
      AppSubmissionMetadata metadata,
      AppBundleManifest manifest,
      byte[] artifactBytes,
      Map<String, ZipEntry> entries,
      ZipFile zip,
      List<AppSubmissionFinding> findings)
      throws IOException {
    addIf(
        findings,
        !metadata.appId().equals(manifest.appId()),
        "metadata.app-id-mismatch",
        "Submission appId does not match bundle manifest");
    addIf(
        findings,
        !metadata.appVersion().equals(manifest.appVersion()),
        "metadata.app-version-mismatch",
        "Submission appVersion does not match bundle manifest");
    addIf(
        findings,
        !metadata.bundleDigest().equals(sha256Hex(artifactBytes)),
        "metadata.bundle-digest-mismatch",
        "Submission bundleDigest does not match app-bundle.zip");
    validateSignatureKeyBinding(metadata, entries, zip, findings);
    validateCatalogEntryDigestBinding(metadata, entries, zip, findings);
    validateArtifactMatchesEmbeddedBundle(manifest, artifactBytes, entries, zip, findings);
    AppApiCompatibilityMetadata api = manifest.apiCompatibility();
    addIf(
        findings,
        !metadata.apiTargetStability().equals(api.targetStability().manifestValue()),
        "metadata.api-stability-mismatch",
        "Submission API target stability does not match bundle manifest");
    addIf(
        findings,
        metadata.experimentalCapabilitiesAccepted() != api.experimentalCapabilitiesAccepted(),
        "metadata.experimental-acceptance-mismatch",
        "Submission experimental acceptance does not match bundle manifest");
    addIf(
        findings,
        !metadata.requestedPermissions().equals(manifest.permissions()),
        "metadata.permissions-mismatch",
        "Submission permissions do not match bundle manifest");
    addIf(
        findings,
        !metadata.sandboxRequirement().equals(sandboxRequirement(manifest)),
        "metadata.sandbox-requirement-mismatch",
        "Submission sandbox requirement does not match bundle manifest");
    addIf(
        findings,
        metadata.appDataSchemaDeclared() != manifest.dataSchemaContract().declared(),
        "metadata.app-data-schema-mismatch",
        "Submission app-data schema declaration does not match bundle manifest");
    boolean manifestDeclaresAppDataMigration =
        !manifest.dataSchemaContract().migrations().isEmpty();
    addIf(
        findings,
        metadata.appDataMigrationDeclared() != manifestDeclaresAppDataMigration,
        "metadata.app-data-migration-mismatch",
        "Submission app-data migration declaration does not match bundle manifest");
    addIf(
        findings,
        metadata.backupRestoreDeclared() != entries.containsKey(BACKUP_RESTORE_ENTRY),
        "metadata.backup-restore-mismatch",
        "Submission backup/restore declaration does not match review evidence");
    validateRedactionScanDigestBinding(metadata, entries, findings);
    validatePermissionRationaleDigestBinding(metadata, entries, zip, findings);
    if (!manifest.permissions().isEmpty()) {
      addIf(
          findings,
          !entries.containsKey(PERMISSION_RATIONALE_ENTRY),
          "review.permission-rationale-missing",
          "Permission rationale is required when permissions are requested");
    }
    if (!manifest.sandboxMode().manifestValue().equals("none") || manifest.sandboxRequired()) {
      addIf(
          findings,
          !entries.containsKey(SANDBOX_RATIONALE_ENTRY),
          "review.sandbox-rationale-missing",
          "Sandbox rationale is required for non-default sandbox requirements");
    }
    boolean ownsDurableData =
        manifest.permissions().stream().anyMatch(permission -> permission.startsWith("app.data."))
            || manifest.dataSchemaContract().declared();
    if (manifest.dataSchemaContract().declared()) {
      addIf(
          findings,
          !entries.containsKey(DATA_SCHEMA_ENTRY),
          "review.data-schema-missing",
          "Data schema declaration is required when app-data schema metadata is present");
    }
    if (ownsDurableData) {
      addIf(
          findings,
          !entries.containsKey(BACKUP_RESTORE_ENTRY),
          "review.backup-restore-missing",
          "Backup/restore declaration is required for durable app data");
    }
  }

  private static void validatePermissionRationaleDigestBinding(
      AppSubmissionMetadata metadata,
      Map<String, ZipEntry> entries,
      ZipFile zip,
      List<AppSubmissionFinding> findings)
      throws IOException {
    ZipEntry rationale = entries.get(PERMISSION_RATIONALE_ENTRY);
    Optional<String> actualDigest = Optional.empty();
    if (rationale != null && !rationale.isDirectory()) {
      actualDigest = Optional.of(sha256Hex(read(zip, rationale, MAX_SUBMISSION_TEXT_ENTRY_BYTES)));
    }
    boolean shouldValidateDigest =
        rationale != null || metadata.permissionRationaleDigest().isPresent();
    addIf(
        findings,
        shouldValidateDigest && !metadata.permissionRationaleDigest().equals(actualDigest),
        "review.permission-rationale-digest-mismatch",
        "Permission rationale digest does not match submission metadata");
  }

  private static void validateSignatureKeyBinding(
      AppSubmissionMetadata metadata,
      Map<String, ZipEntry> entries,
      ZipFile zip,
      List<AppSubmissionFinding> findings)
      throws IOException {
    Optional<String> signatureKeyId = Optional.empty();
    ZipEntry signature = entries.get(BUNDLE_SIGNATURE_ENTRY);
    if (signature != null && !signature.isDirectory()) {
      try {
        signatureKeyId =
            Optional.of(parseSignatureKeyId(read(zip, signature, MAX_SUBMISSION_TEXT_ENTRY_BYTES)));
      } catch (AppCatalogException _) {
        findings.add(
            blocker(
                "signature.sidecar-invalid",
                BUNDLE_SIGNATURE_ENTRY,
                "Bundle signature sidecar is invalid"));
        return;
      }
    }
    addIf(
        findings,
        !metadata.bundleSignatureKeyId().equals(signatureKeyId),
        "metadata.bundle-signature-key-mismatch",
        "Submission bundle signature key id does not match the bundle sidecar");
  }

  private static void validateCatalogEntryDigestBinding(
      AppSubmissionMetadata metadata,
      Map<String, ZipEntry> entries,
      ZipFile zip,
      List<AppSubmissionFinding> findings)
      throws IOException {
    Optional<String> catalogEntryDigest = Optional.empty();
    ZipEntry catalogEntry = entries.get(CATALOG_ENTRY_ARTIFACT);
    if (catalogEntry != null && !catalogEntry.isDirectory()) {
      catalogEntryDigest =
          Optional.of(sha256Hex(read(zip, catalogEntry, MAX_SUBMISSION_TEXT_ENTRY_BYTES)));
    }
    addIf(
        findings,
        !metadata.catalogEntryDigest().equals(catalogEntryDigest),
        "metadata.catalog-entry-digest-mismatch",
        "Submission catalog entry digest does not match packaged review evidence");
  }

  private static void validateRedactionScanDigestBinding(
      AppSubmissionMetadata metadata,
      Map<String, ZipEntry> entries,
      List<AppSubmissionFinding> findings) {
    Optional<String> expectedDigest = Optional.of(redactionScanDigest(entries.keySet()));
    addIf(
        findings,
        !metadata.redactionScanDigest().equals(expectedDigest),
        "metadata.redaction-scan-digest-mismatch",
        "Submission redaction scan digest does not match package entries");
  }

  private static String sandboxRequirement(AppBundleManifest manifest) {
    return manifest.sandboxRequired()
        ? manifest.sandboxMode().manifestValue() + ":required"
        : manifest.sandboxMode().manifestValue();
  }

  private static String parseSignatureKeyId(byte[] signatureBytes) {
    Map<String, String> properties =
        parseSignatureSidecar(new String(signatureBytes, StandardCharsets.UTF_8));
    String versionText = removeRequiredSignatureProperty(properties, "signature.version");
    String algorithm = removeRequiredSignatureProperty(properties, "signature.algorithm");
    String keyId = removeRequiredSignatureProperty(properties, "signature.key.id");
    String payload = removeRequiredSignatureProperty(properties, "signature.payload");
    String signatureValue = removeRequiredSignatureProperty(properties, "signature.value.base64");
    if (!properties.isEmpty()) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported bundle signature sidecar property: "
              + properties.keySet().iterator().next());
    }
    if (!AppBundleSignature.SIGNATURE_ALGORITHM.equals(algorithm)) {
      throw AppCatalogSidecars.invalidEntry("unsupported bundle signature algorithm");
    }
    if (!AppBundleDigest.DIGEST_FILE_NAME.equals(payload)) {
      throw AppCatalogSidecars.invalidEntry("unsupported bundle signature payload");
    }
    try {
      return new AppBundleSignature(
              Integer.parseInt(versionText), algorithm, keyId, payload, signatureValue)
          .keyId();
    } catch (RuntimeException _) {
      throw AppCatalogSidecars.invalidEntry("bundle signature sidecar is invalid");
    }
  }

  private static Map<String, String> parseSignatureSidecar(String content) {
    LinkedHashMap<String, String> properties = new LinkedHashMap<>();
    String[] lines = stripLeadingBom(content).split("\\R", -1);
    for (String line : lines) {
      if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) {
        continue;
      }
      int separatorIndex = line.indexOf('=');
      if (separatorIndex < 0) {
        throw AppCatalogSidecars.invalidEntry("invalid bundle signature sidecar line");
      }
      String key = line.substring(0, separatorIndex).trim();
      if (key.isEmpty()) {
        throw AppCatalogSidecars.invalidEntry("invalid bundle signature sidecar key");
      }
      String value = line.substring(separatorIndex + 1);
      if (properties.putIfAbsent(key, value) != null) {
        throw AppCatalogSidecars.invalidEntry(
            "duplicate bundle signature sidecar property: " + key);
      }
    }
    return properties;
  }

  private static String stripLeadingBom(String content) {
    if (!content.isEmpty() && content.charAt(0) == UTF_8_BOM) {
      return content.substring(1);
    }
    return content;
  }

  private static String removeRequiredSignatureProperty(
      Map<String, String> properties, String fieldName) {
    String value = properties.remove(fieldName);
    if (value == null) {
      throw AppCatalogSidecars.invalidEntry("missing bundle signature sidecar field: " + fieldName);
    }
    return value;
  }

  private static String redactionScanDigest(Set<String> entryNames) {
    StringBuilder builder = new StringBuilder();
    entryNames.stream()
        .filter(name -> !name.equals(SUBMISSION_METADATA_ENTRY))
        .sorted()
        .forEach(name -> builder.append(name).append('\n'));
    builder.append(REDACTION_SCAN_VERSION).append('\n');
    return sha256Hex(builder.toString().getBytes(StandardCharsets.UTF_8));
  }

  private static void validateArtifactMatchesEmbeddedBundle(
      AppBundleManifest manifest,
      byte[] artifactBytes,
      Map<String, ZipEntry> entries,
      ZipFile zip,
      List<AppSubmissionFinding> findings)
      throws IOException {
    if (artifactBytes.length > AppCatalogSidecars.MAX_ARTIFACT_BYTES) {
      findings.add(blocker("artifact.size-limit", "app-bundle.zip exceeds the artifact size cap"));
      return;
    }
    Map<String, ArtifactZipMetadata> artifactMetadata =
        artifactZipMetadata(artifactBytes, manifest, findings);
    Map<String, byte[]> embeddedBundle = embeddedBundleEntries(entries, zip);
    Map<String, byte[]> artifactBundle =
        artifactBundleEntries(artifactBytes, artifactMetadata, manifest, findings);
    if (artifactBundle.isEmpty()) {
      findings.add(blocker("artifact.empty", "app-bundle.zip does not contain bundle files"));
      return;
    }
    if (artifactMetadata.isEmpty()) {
      findings.add(
          blocker(
              "artifact.zip-metadata-missing",
              "app-bundle.zip central directory metadata is missing"));
      return;
    }
    if (!artifactMetadata.keySet().equals(artifactBundle.keySet())) {
      findings.add(
          new AppSubmissionFinding(
              "artifact.metadata-entry-set-mismatch",
              AppSubmissionFindingSeverity.BLOCKER,
              "app-bundle.zip central directory entries do not match payload entries",
              Map.of(
                  "centralDirectoryEntryCount",
                  artifactMetadata.size(),
                  "payloadEntryCount",
                  artifactBundle.size())));
    }
    validateArtifactManifest(manifest, artifactBundle, findings);
    if (!embeddedBundle.keySet().equals(artifactBundle.keySet())) {
      findings.add(
          new AppSubmissionFinding(
              "artifact.entry-set-mismatch",
              AppSubmissionFindingSeverity.BLOCKER,
              "app-bundle.zip entries do not match the reviewed bundle tree",
              Map.of(
                  "reviewedEntryCount",
                  embeddedBundle.size(),
                  "artifactEntryCount",
                  artifactBundle.size())));
      return;
    }
    for (Map.Entry<String, byte[]> entry : embeddedBundle.entrySet()) {
      String name = entry.getKey();
      if (!MessageDigest.isEqual(entry.getValue(), artifactBundle.get(name))) {
        findings.add(
            blocker(
                "artifact.bundle-entry-mismatch",
                name,
                "app-bundle.zip content does not match the reviewed bundle tree"));
        return;
      }
    }
  }

  private static Map<String, byte[]> embeddedBundleEntries(
      Map<String, ZipEntry> entries, ZipFile zip) throws IOException {
    LinkedHashMap<String, byte[]> bundleEntries = new LinkedHashMap<>();
    for (Map.Entry<String, ZipEntry> entry : entries.entrySet()) {
      String name = entry.getKey();
      ZipEntry zipEntry = entry.getValue();
      if (!name.startsWith(BUNDLE_PREFIX) || zipEntry.isDirectory()) {
        continue;
      }
      bundleEntries.put(
          name.substring(BUNDLE_PREFIX.length()), read(zip, zipEntry, maxReadableEntryBytes(name)));
    }
    return bundleEntries.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .collect(
            LinkedHashMap::new,
            (map, entry) -> map.put(entry.getKey(), entry.getValue()),
            LinkedHashMap::putAll);
  }

  // Archive expansion is safe here because artifact bytes are capped before parsing, central
  // directory metadata is validated separately, and extracted payload plus entry count are bounded.
  @SuppressWarnings("java:S5042")
  private static Map<String, byte[]> artifactBundleEntries(
      byte[] artifactBytes,
      Map<String, ArtifactZipMetadata> artifactMetadata,
      AppBundleManifest manifest,
      List<AppSubmissionFinding> findings) {
    LinkedHashMap<String, byte[]> artifactEntries = new LinkedHashMap<>();
    long[] extractedBytes = {0L};
    int entryCount = 0;
    Set<String> allowedExecutables = allowedExecutableEntries(manifest);
    try (ZipInputStream input =
        new ZipInputStream(new ByteArrayInputStream(artifactBytes), StandardCharsets.UTF_8)) {
      ZipEntry entry;
      while ((entry = input.getNextEntry()) != null) {
        entryCount++;
        if (entryCount > MAX_ARTIFACT_ZIP_ENTRIES) {
          findings.add(
              blocker("artifact.entry-count-limit", "app-bundle.zip contains too many entries"));
          return Map.of();
        }
        String name = entry.getName();
        String nestedName = BUNDLE_ARTIFACT_ENTRY + "!" + name;
        AppSubmissionRedactionScanner.addPathFindings(findings, nestedName);
        if (entry.isDirectory()) {
          findings.add(
              blocker(
                  "artifact.directory-entry", name, "app-bundle.zip contains a directory entry"));
          input.closeEntry();
          continue;
        }
        byte[] bytes = readBoundedArtifactEntry(input, extractedBytes);
        validateArtifactEntryMetadata(
            name, entry, artifactMetadata.get(name), bytes, allowedExecutables, findings);
        if (artifactEntries.putIfAbsent(name, bytes) != null) {
          findings.add(
              blocker(
                  "artifact.duplicate-entry", name, "app-bundle.zip contains a duplicate entry"));
        }
        input.closeEntry();
      }
    } catch (IOException | IllegalArgumentException _) {
      findings.add(blocker("artifact.unreadable", "app-bundle.zip cannot be inspected safely"));
    }
    return artifactEntries.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .collect(
            LinkedHashMap::new,
            (map, entry) -> map.put(entry.getKey(), entry.getValue()),
            LinkedHashMap::putAll);
  }

  private static Map<String, ArtifactZipMetadata> artifactZipMetadata(
      byte[] artifactBytes, AppBundleManifest manifest, List<AppSubmissionFinding> findings) {
    try {
      CentralDirectoryRange range = centralDirectoryRange(artifactBytes);
      if (range.entryCount() > MAX_ARTIFACT_ZIP_ENTRIES) {
        findings.add(
            blocker("artifact.entry-count-limit", "app-bundle.zip contains too many entries"));
        return Map.of();
      }
      LinkedHashMap<String, ArtifactZipMetadata> metadata = new LinkedHashMap<>();
      int offset = range.offset();
      int centralDirectoryEnd = range.offset() + range.size();
      Set<String> allowedExecutables = allowedExecutableEntries(manifest);
      for (int index = 0; index < range.entryCount(); index++) {
        CentralDirectoryRead read = readArtifactCentralDirectoryEntry(artifactBytes, offset);
        ArtifactZipMetadata entry = read.metadata();
        AppSubmissionRedactionScanner.addPathFindings(
            findings, BUNDLE_ARTIFACT_ENTRY + "!" + entry.name());
        validateCentralDirectoryMetadata(entry, allowedExecutables, findings);
        if (metadata.putIfAbsent(entry.name(), entry) != null) {
          findings.add(
              blocker(
                  "artifact.duplicate-entry",
                  entry.name(),
                  "app-bundle.zip central directory contains a duplicate entry"));
        }
        offset = read.nextOffset();
        if (offset > centralDirectoryEnd) {
          throw new IllegalArgumentException("central directory entry escapes directory range");
        }
      }
      if (offset != centralDirectoryEnd) {
        findings.add(
            blocker(
                "artifact.zip-metadata-invalid",
                "app-bundle.zip central directory contains trailing bytes"));
      }
      return metadata.entrySet().stream()
          .sorted(Map.Entry.comparingByKey())
          .collect(
              LinkedHashMap::new,
              (map, entry) -> map.put(entry.getKey(), entry.getValue()),
              LinkedHashMap::putAll);
    } catch (RuntimeException _) {
      findings.add(blocker("artifact.zip-metadata-invalid", "app-bundle.zip metadata is invalid"));
      return Map.of();
    }
  }

  private static void validateCentralDirectoryMetadata(
      ArtifactZipMetadata metadata,
      Set<String> allowedExecutables,
      List<AppSubmissionFinding> findings) {
    List<String> violations = centralDirectoryMetadataViolations(metadata);
    int executeBits = metadata.unixMode() & UNIX_EXECUTE_BITS;
    if (executeBits != 0 && !allowedExecutables.contains(metadata.name())) {
      findings.add(
          blocker(
              "artifact.executable-surprise",
              metadata.name(),
              "app-bundle.zip restores executable bits for an undeclared entry"));
    }
    if (!violations.isEmpty()) {
      Map<String, Object> details =
          new LinkedHashMap<>(AppSubmissionRedactionScanner.redactedPathDetails(metadata.name()));
      details.put("violations", List.copyOf(violations));
      findings.add(
          new AppSubmissionFinding(
              "artifact.zip-entry-metadata",
              AppSubmissionFindingSeverity.BLOCKER,
              "app-bundle.zip entry metadata is not canonical",
              details));
    }
  }

  private static List<String> centralDirectoryMetadataViolations(ArtifactZipMetadata metadata) {
    List<String> violations = new ArrayList<>();
    if (metadata.directory()) {
      violations.add("directory");
    }
    if (metadata.method() != ZipEntry.STORED) {
      violations.add("method");
    }
    if (metadata.modTime() != FIXED_DOS_TIME || metadata.modDate() != FIXED_DOS_DATE) {
      violations.add("time");
    }
    if (!metadata.canonicalExtra()) {
      violations.add("extra");
    }
    if (metadata.commentLength() != 0) {
      violations.add("comment");
    }
    if (metadata.compressedSize() != metadata.size()) {
      violations.add("size");
    }
    if (metadata.hostPlatform() != UNIX_HOST_PLATFORM) {
      violations.add("host-platform");
    }
    if ((metadata.unixMode() & UNIX_FILE_TYPE_MASK) != UNIX_REGULAR_FILE_TYPE) {
      violations.add("unix-file-type");
    }
    return violations;
  }

  // Metadata inspection is safe here because bytes have already been read through
  // readBoundedArtifactEntry and are compared against canonical central-directory metadata.
  @SuppressWarnings("java:S5042")
  private static void validateArtifactEntryMetadata(
      String name,
      ZipEntry entry,
      ArtifactZipMetadata metadata,
      byte[] bytes,
      Set<String> allowedExecutables,
      List<AppSubmissionFinding> findings) {
    if (metadata == null) {
      return;
    }
    List<String> violations = new ArrayList<>();
    if (entry.getMethod() != ZipEntry.STORED) {
      violations.add("local-method");
    }
    if (entry.getTime() != 0L) {
      violations.add("local-time");
    }
    if (!isCanonicalExtra(entry.getExtra())) {
      violations.add("local-extra");
    }
    if (entry.getSize() != bytes.length || metadata.size() != bytes.length) {
      violations.add("size");
    }
    if (entry.getCompressedSize() >= 0L && entry.getCompressedSize() != bytes.length) {
      violations.add("compressed-size");
    }
    if (metadata.crc() != crc32(bytes)) {
      violations.add("crc");
    }
    int executeBits = metadata.unixMode() & UNIX_EXECUTE_BITS;
    if (executeBits != 0 && !allowedExecutables.contains(name)) {
      violations.add("executable");
    }
    if (!violations.isEmpty()) {
      Map<String, Object> details =
          new LinkedHashMap<>(AppSubmissionRedactionScanner.redactedPathDetails(name));
      details.put("violations", List.copyOf(violations));
      findings.add(
          new AppSubmissionFinding(
              "artifact.zip-entry-metadata",
              AppSubmissionFindingSeverity.BLOCKER,
              "app-bundle.zip entry metadata does not match the reviewed artifact policy",
              details));
    }
  }

  private static Set<String> allowedExecutableEntries(AppBundleManifest manifest) {
    LinkedHashSet<String> entries = new LinkedHashSet<>();
    entries.add(manifest.execPathText());
    for (AppDataMigrationStep step : manifest.dataSchemaContract().migrations()) {
      entries.add(step.command().pathText());
    }
    return Set.copyOf(entries);
  }

  private static CentralDirectoryRange centralDirectoryRange(byte[] zipBytes) {
    if (zipBytes.length < END_OF_CENTRAL_DIRECTORY_MIN_BYTES) {
      throw new IllegalArgumentException("missing end-of-central-directory record");
    }
    ByteBuffer buffer = ByteBuffer.wrap(zipBytes).order(ByteOrder.LITTLE_ENDIAN);
    int offset = zipBytes.length - END_OF_CENTRAL_DIRECTORY_MIN_BYTES;
    if (buffer.getInt(offset) == END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
      return readCentralDirectoryRange(buffer, offset, zipBytes.length);
    }
    throw new IllegalArgumentException("missing end-of-central-directory record");
  }

  private static CentralDirectoryRange readCentralDirectoryRange(
      ByteBuffer buffer, int offset, int zipLength) {
    int diskNumber = unsignedShort(buffer, offset + 4);
    int centralDirectoryDisk = unsignedShort(buffer, offset + 6);
    int diskEntries = unsignedShort(buffer, offset + 8);
    int totalEntries = unsignedShort(buffer, offset + 10);
    long centralDirectorySize = unsignedInt(buffer, offset + 12);
    long centralDirectoryOffset = unsignedInt(buffer, offset + 16);
    int commentLength = unsignedShort(buffer, offset + 20);
    if (diskNumber != 0 || centralDirectoryDisk != 0 || diskEntries != totalEntries) {
      throw new IllegalArgumentException("multi-disk ZIP artifacts are unsupported");
    }
    if (commentLength != 0 || offset + END_OF_CENTRAL_DIRECTORY_MIN_BYTES != zipLength) {
      throw new IllegalArgumentException("ZIP artifact comments are unsupported");
    }
    if (totalEntries == ZIP64_UNSIGNED_SHORT_MARKER
        || centralDirectorySize == ZIP64_UNSIGNED_INT_MARKER
        || centralDirectoryOffset == ZIP64_UNSIGNED_INT_MARKER) {
      throw new IllegalArgumentException("ZIP64 artifact metadata is unsupported");
    }
    long centralDirectoryEnd = centralDirectoryOffset + centralDirectorySize;
    if (centralDirectoryOffset > zipLength
        || centralDirectorySize > zipLength - centralDirectoryOffset
        || centralDirectoryEnd != offset) {
      throw new IllegalArgumentException("central directory escapes ZIP bounds");
    }
    return new CentralDirectoryRange(
        totalEntries,
        Math.toIntExact(centralDirectoryOffset),
        Math.toIntExact(centralDirectorySize));
  }

  private static CentralDirectoryRead readArtifactCentralDirectoryEntry(
      byte[] zipBytes, int offset) {
    if (offset + CENTRAL_DIRECTORY_HEADER_BYTES > zipBytes.length) {
      throw new IllegalArgumentException("truncated central directory entry");
    }
    ByteBuffer buffer = ByteBuffer.wrap(zipBytes).order(ByteOrder.LITTLE_ENDIAN);
    if (buffer.getInt(offset) != CENTRAL_DIRECTORY_HEADER_SIGNATURE) {
      throw new IllegalArgumentException("malformed central directory entry");
    }
    int versionMadeBy = unsignedShort(buffer, offset + 4);
    int hostPlatform = (versionMadeBy >>> 8) & 0xFF;
    int method = unsignedShort(buffer, offset + 10);
    int modTime = unsignedShort(buffer, offset + 12);
    int modDate = unsignedShort(buffer, offset + 14);
    long crc = unsignedInt(buffer, offset + 16);
    long compressedSize = unsignedInt(buffer, offset + 20);
    long size = unsignedInt(buffer, offset + 24);
    int nameLength = unsignedShort(buffer, offset + 28);
    int extraLength = unsignedShort(buffer, offset + 30);
    int commentLength = unsignedShort(buffer, offset + 32);
    long externalAttributes = unsignedInt(buffer, offset + 38);
    int nameOffset = offset + CENTRAL_DIRECTORY_HEADER_BYTES;
    int extraOffset = nameOffset + nameLength;
    long nextOffset = (long) nameOffset + nameLength + extraLength + commentLength;
    if (nextOffset > zipBytes.length) {
      throw new IllegalArgumentException("central directory entry escapes ZIP bounds");
    }
    String name = new String(zipBytes, nameOffset, nameLength, StandardCharsets.UTF_8);
    byte[] extra = Arrays.copyOfRange(zipBytes, extraOffset, extraOffset + extraLength);
    boolean canonicalExtra = isCanonicalExtra(extra);
    int unixMode =
        hostPlatform == UNIX_HOST_PLATFORM
            ? (int) ((externalAttributes >>> UNIX_MODE_SHIFT) & 0xFFFF)
            : 0;
    ArtifactZipMetadata metadata =
        new ArtifactZipMetadata(
            name,
            name.endsWith("/"),
            hostPlatform,
            method,
            modTime,
            modDate,
            size,
            compressedSize,
            crc,
            canonicalExtra,
            commentLength,
            unixMode);
    return new CentralDirectoryRead(metadata, Math.toIntExact(nextOffset));
  }

  private static byte[] readBoundedArtifactEntry(ZipInputStream input, long[] extractedBytes)
      throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] buffer = new byte[16 * 1024];
    int read;
    while ((read = input.read(buffer)) >= 0) {
      if (read == 0) {
        continue;
      }
      extractedBytes[0] += read;
      if (extractedBytes[0] > AppCatalogSidecars.MAX_ARTIFACT_BYTES) {
        throw new IOException("app-bundle.zip extracted payload exceeds the artifact size cap");
      }
      output.write(buffer, 0, read);
    }
    return output.toByteArray();
  }

  private static void validateArtifactManifest(
      AppBundleManifest reviewedManifest,
      Map<String, byte[]> artifactBundle,
      List<AppSubmissionFinding> findings) {
    byte[] artifactManifestBytes = artifactBundle.get(AppBundleManifestParser.MANIFEST_FILE_NAME);
    if (artifactManifestBytes == null) {
      findings.add(
          blocker("artifact.manifest-missing", "app-bundle.zip is missing the root manifest"));
      return;
    }
    try {
      AppBundleManifest artifactManifest =
          AppBundleManifestParser.parseContent(
              new String(artifactManifestBytes, StandardCharsets.UTF_8));
      Set<String> mismatches = new java.util.LinkedHashSet<>();
      if (!artifactManifest.appId().equals(reviewedManifest.appId())) {
        mismatches.add("appId");
      }
      if (!artifactManifest.appVersion().equals(reviewedManifest.appVersion())) {
        mismatches.add("appVersion");
      }
      if (!mismatches.isEmpty()) {
        findings.add(
            new AppSubmissionFinding(
                "artifact.manifest-mismatch",
                AppSubmissionFindingSeverity.BLOCKER,
                "app-bundle.zip manifest does not match the reviewed bundle manifest",
                Map.of("fields", List.copyOf(mismatches))));
      }
    } catch (IOException | RuntimeException _) {
      findings.add(blocker("artifact.manifest-invalid", "app-bundle.zip manifest is invalid"));
    }
  }

  // Required entries are safe to read here because callers provide explicit per-entry caps and this
  // helper returns a blocker finding instead of expanding over the cap.
  @SuppressWarnings("java:S5042")
  private static byte[] requiredEntryBytes(
      ZipFile zip,
      Map<String, ZipEntry> entries,
      String entryName,
      long maxBytes,
      List<AppSubmissionFinding> findings)
      throws IOException {
    ZipEntry entry = entries.get(entryName);
    if (entry == null || entry.isDirectory()) {
      findings.add(
          blocker(
              "package.required-entry-missing", entryName, "Required submission entry is missing"));
      return EMPTY_BYTES;
    }
    if (entry.getSize() > maxBytes || entry.getCompressedSize() > maxBytes) {
      findings.add(
          blocker(PACKAGE_ENTRY_SIZE_LIMIT_ID, entryName, SUBMISSION_ENTRY_SIZE_CAP_SUMMARY));
      return EMPTY_BYTES;
    }
    try {
      return read(zip, entry, maxBytes);
    } catch (AppCatalogException _) {
      findings.add(
          blocker(PACKAGE_ENTRY_SIZE_LIMIT_ID, entryName, SUBMISSION_ENTRY_SIZE_CAP_SUMMARY));
      return EMPTY_BYTES;
    }
  }

  private static void scanEntry(ZipFile zip, ZipEntry entry, List<AppSubmissionFinding> findings)
      throws IOException {
    try {
      findings.addAll(
          AppSubmissionRedactionScanner.scanEntry(
              entry.getName(), read(zip, entry, maxReadableEntryBytes(entry.getName()))));
    } catch (AppCatalogException _) {
      findings.add(
          blocker(PACKAGE_ENTRY_SIZE_LIMIT_ID, entry.getName(), SUBMISSION_ENTRY_SIZE_CAP_SUMMARY));
    }
  }

  private static long maxReadableEntryBytes(String entryName) {
    if (entryName.equals(BUNDLE_ARTIFACT_ENTRY) || entryName.startsWith(BUNDLE_PREFIX)) {
      return MAX_SUBMISSION_ENTRY_BYTES;
    }
    return MAX_SUBMISSION_TEXT_ENTRY_BYTES;
  }

  // Zip entry reads are safe here because caller-selected caps are checked against declared
  // metadata and enforced again while streaming the actual payload.
  @SuppressWarnings("java:S5042")
  private static byte[] read(ZipFile zip, ZipEntry entry, long maxBytes) throws IOException {
    if (entry.getSize() > maxBytes || entry.getCompressedSize() > maxBytes) {
      throw AppCatalogSidecars.invalidEntry(
          "submission entry exceeds size cap: " + entry.getName());
    }
    try (InputStream input = zip.getInputStream(entry)) {
      return readBounded(input, maxBytes, "submission entry exceeds size cap: " + entry.getName());
    }
  }

  private static byte[] readSubmissionBytes(Path file) throws IOException {
    if (Files.size(file) > MAX_SUBMISSION_PACKAGE_BYTES) {
      throw AppCatalogSidecars.invalidEntry("submission package exceeds size cap");
    }
    try (InputStream input = Files.newInputStream(file)) {
      return readBounded(
          input, MAX_SUBMISSION_PACKAGE_BYTES, "submission package exceeds size cap");
    }
  }

  private static SubmissionSnapshot writeSubmissionSnapshot(byte[] submissionBytes)
      throws IOException {
    Path snapshotDirectory = createPrivateSnapshotDirectory();
    Path snapshot = snapshotDirectory.resolve("submission.zip");
    try {
      Files.write(
          snapshot,
          submissionBytes,
          StandardOpenOption.CREATE_NEW,
          StandardOpenOption.WRITE,
          LinkOption.NOFOLLOW_LINKS);
      return new SubmissionSnapshot(snapshot, snapshotDirectory);
    } catch (IOException exception) {
      deleteSubmissionSnapshot(snapshot, snapshotDirectory, exception);
      throw exception;
    }
  }

  // The directory name is generated atomically by the JDK, and POSIX hosts receive owner-only
  // permissions at creation time. The fallback immediately tightens permissions before the
  // verifier writes the immutable submission snapshot into the directory.
  @SuppressWarnings("java:S5443")
  private static Path createPrivateSnapshotDirectory() throws IOException {
    try {
      return Files.createTempDirectory(
          "crypta-app-submission-inspect-", ownerOnlyDirectoryAttribute());
    } catch (UnsupportedOperationException _) {
      Path directory = Files.createTempDirectory("crypta-app-submission-inspect-");
      trySetOwnerOnlyDirectoryPermissions(directory);
      return directory;
    }
  }

  private static FileAttribute<Set<PosixFilePermission>> ownerOnlyDirectoryAttribute() {
    return PosixFilePermissions.asFileAttribute(OWNER_ONLY_DIRECTORY_PERMISSIONS);
  }

  private static void trySetOwnerOnlyDirectoryPermissions(Path directory) throws IOException {
    try {
      Files.setPosixFilePermissions(directory, OWNER_ONLY_DIRECTORY_PERMISSIONS);
    } catch (UnsupportedOperationException _) {
      // Non-POSIX filesystems rely on the platform temp-directory ACLs.
    }
  }

  private static void deleteSubmissionSnapshot(
      Path snapshot, Path snapshotDirectory, IOException exception) {
    try {
      Files.deleteIfExists(snapshot);
    } catch (IOException deleteException) {
      exception.addSuppressed(deleteException);
    }
    try {
      Files.deleteIfExists(snapshotDirectory);
    } catch (IOException deleteException) {
      exception.addSuppressed(deleteException);
    }
  }

  private static byte[] readBounded(InputStream input, long maxBytes, String failureMessage)
      throws IOException {
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
        throw AppCatalogSidecars.invalidEntry(failureMessage);
      }
      output.write(buffer, 0, read);
    }
    return output.toByteArray();
  }

  private static long crc32(byte[] bytes) {
    CRC32 crc = new CRC32();
    crc.update(bytes);
    return crc.getValue();
  }

  private static boolean isCanonicalExtra(byte[] extra) {
    return Arrays.equals(FIXED_TIMESTAMP_EXTRA, extra);
  }

  private static int unsignedShort(ByteBuffer buffer, int offset) {
    return Short.toUnsignedInt(buffer.getShort(offset));
  }

  private static long unsignedInt(ByteBuffer buffer, int offset) {
    return Integer.toUnsignedLong(buffer.getInt(offset));
  }

  private static void addIf(
      List<AppSubmissionFinding> findings, boolean condition, String id, String summary) {
    if (condition) {
      findings.add(blocker(id, summary));
    }
  }

  private static boolean hasBlockers(List<AppSubmissionFinding> findings) {
    return findings.stream().anyMatch(AppSubmissionFinding::blocksPromotion);
  }

  private static AppSubmissionFinding blocker(String id, String summary) {
    return new AppSubmissionFinding(id, AppSubmissionFindingSeverity.BLOCKER, summary, Map.of());
  }

  private static AppSubmissionFinding blocker(String id, String path, String summary) {
    return new AppSubmissionFinding(
        id,
        AppSubmissionFindingSeverity.BLOCKER,
        summary,
        AppSubmissionRedactionScanner.redactedPathDetails(path));
  }

  private static String sha256Hex(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private record CentralDirectoryRange(int entryCount, int offset, int size) {}

  private record CentralDirectoryRead(ArtifactZipMetadata metadata, int nextOffset) {}

  private record SubmissionSnapshot(Path path, Path directory) implements AutoCloseable {
    @Override
    public void close() throws IOException {
      IOException failure = null;
      try {
        Files.deleteIfExists(path);
      } catch (IOException exception) {
        failure = exception;
      }
      try {
        Files.deleteIfExists(directory);
      } catch (IOException exception) {
        if (failure == null) {
          failure = exception;
        } else {
          failure.addSuppressed(exception);
        }
      }
      if (failure != null) {
        throw failure;
      }
    }
  }

  private record ArtifactZipMetadata(
      String name,
      boolean directory,
      int hostPlatform,
      int method,
      int modTime,
      int modDate,
      long size,
      long compressedSize,
      long crc,
      boolean canonicalExtra,
      int commentLength,
      int unixMode) {}
}
