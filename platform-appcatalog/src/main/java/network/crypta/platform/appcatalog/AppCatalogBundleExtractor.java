package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;
import network.crypta.platform.appdist.AppBundleDigest;
import network.crypta.platform.appdist.AppBundleDigestVerifier;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Extracts a verified catalog ZIP artifact into a staged app bundle root.
 *
 * <p>The extractor rejects ZIP entries that can escape or alias the staging root before any bundle
 * verifier sees the files. After extraction, it requires a root-level app manifest, verifies the
 * existing signed-bundle sidecars with {@link AppBundleVerifier}, and checks that the signed
 * manifest app id and version match the authenticated catalog entry.
 *
 * <p>This class is the last untrusted-input boundary before AppHost receives a staged directory. It
 * never extracts into the final installation tree, rejects absolute paths, parent traversal,
 * duplicate normalized names, unsupported ZIP64 central directory markers, and parent/file
 * conflicts, and caps both entry count and extracted byte count. POSIX executable bits recorded by
 * ZIP creators are restored when possible so the signed appdist digest can still verify bundles
 * whose launch command is an executable file.
 */
public final class AppCatalogBundleExtractor {
  private static final int COPY_BUFFER_BYTES = 64 * 1024;
  private static final int MAX_ZIP_ENTRIES = AppBundlePackager.MAX_CATALOG_ZIP_ENTRIES;
  private static final long MAX_EXTRACTED_BYTES = AppCatalogSidecars.MAX_ARTIFACT_BYTES;
  private static final int END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054B50;
  private static final int CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014B50;
  private static final int END_OF_CENTRAL_DIRECTORY_MIN_BYTES = 22;
  private static final int ZIP_MAX_COMMENT_BYTES = 65_535;
  private static final int CENTRAL_DIRECTORY_HEADER_BYTES = 46;
  private static final int ZIP64_UNSIGNED_SHORT_MARKER = 0xFFFF;
  private static final long ZIP64_UNSIGNED_INT_MARKER = 0xFFFF_FFFFL;
  private static final int UNIX_HOST_PLATFORM = 3;
  private static final int UNIX_MODE_SHIFT = 16;
  private static final int UNIX_FILE_TYPE_MASK = 61440;
  private static final int UNIX_DIRECTORY_TYPE = 16384;
  private static final int UNIX_OWNER_EXECUTE = 64;
  private static final int UNIX_GROUP_EXECUTE = 8;
  private static final int UNIX_OTHER_EXECUTE = 1;
  private static final int UNIX_EXECUTE_BITS =
      UNIX_OWNER_EXECUTE | UNIX_GROUP_EXECUTE | UNIX_OTHER_EXECUTE;
  private static final String PARENT_DIRECTORY_CONFLICT_MESSAGE =
      "zip artifact parent directory conflicts with a file";
  private static final String STAGED_BUNDLE_DIRECTORY_PARAMETER = "stagedBundleDirectory";

  /**
   * Creates a stateless bundle extractor.
   *
   * <p>All extraction state is allocated per {@link #extract(AppCatalogEntry, Path, Path,
   * TrustedAppKeys)} call. A single instance can therefore be shared by a catalog manager without
   * carrying path, trust, or artifact state between install and update operations.
   */
  public AppCatalogBundleExtractor() {
    // The public constructor documents intentional stateless instantiation for doclint and tooling.
  }

  /**
   * Safely inspects a local ZIP artifact and requires signed-bundle sidecars.
   *
   * <p>This method is intended for offline catalog-authoring tools before they write catalog entry
   * descriptors. It expands the artifact through the same ZIP safety path used by install/update
   * extraction, requires canonical root {@code cryptad-app.digests} and {@code
   * cryptad-app.signature} entries, validates the signature sidecar format, and verifies that the
   * digest sidecar matches the extracted bundle contents.
   *
   * <p>Because catalog entry generation does not receive a trusted-key registry, this inspection
   * does not make a publisher trust decision. Runtime install and update paths must use {@link
   * #extract(AppCatalogEntry, Path, Path, AppCatalogBundleVerificationPolicy)} so an explicit
   * policy authorizes the signed digest through either ordinary trusted app keys or a bounded pilot
   * approval.
   *
   * @param artifactZip local artifact ZIP to inspect
   * @param scratchDirectory host-owned scratch directory used for temporary extraction
   * @return parsed artifact manifest after sidecar and digest checks
   * @throws IOException if filesystem, ZIP, sidecar, or bundle validation fails
   */
  public static AppBundleManifest inspectSignedArtifact(Path artifactZip, Path scratchDirectory)
      throws IOException {
    Path zipPath = requireReadableArtifactZip(artifactZip);
    Path scratchRoot =
        Objects.requireNonNull(scratchDirectory, "scratchDirectory").toAbsolutePath().normalize();
    Files.createDirectories(scratchRoot);
    Path stagedRoot = Files.createTempDirectory(scratchRoot, "catalog-bundle-inspect-");
    try {
      extractZip(zipPath, stagedRoot);
      return verifyExtractedSignedArtifact(stagedRoot);
    } catch (AppDistributionException exception) {
      throw invalidBundle(exception.getMessage(), exception);
    } finally {
      deleteRecursively(stagedRoot);
    }
  }

  /**
   * Extracts, verifies, and validates one downloaded ZIP artifact.
   *
   * <p>The method creates a new child directory under {@code scratchDirectory}, expands the ZIP
   * into that directory, and then invokes {@link AppBundleVerifier} against the extracted root. If
   * any extraction, bundle-verification, or manifest-matching check fails, the staged root is
   * removed before the failure is propagated. The caller remains responsible for deleting the
   * broader scratch directory after AppHost has copied the staged bundle.
   *
   * @param entry catalog entry that supplied the artifact metadata and expected manifest identity
   * @param artifactZip downloaded and SHA-256-verified artifact ZIP
   * @param scratchDirectory host-owned scratch directory used for extraction
   * @param trustedKeys explicit trusted keys used for signed-bundle verification
   * @return staged bundle root ready for AppHost installation or update
   * @throws IOException if filesystem cleanup, extraction, or signed-bundle verification fails
   */
  public Path extract(
      AppCatalogEntry entry, Path artifactZip, Path scratchDirectory, TrustedAppKeys trustedKeys)
      throws IOException {
    return extract(
        entry,
        artifactZip,
        scratchDirectory,
        stagedRoot -> AppBundleVerifier.verify(stagedRoot, trustedKeys));
  }

  /**
   * Extracts and verifies one downloaded ZIP with an explicit publisher-authorization policy.
   *
   * <p>The extractor retains its archive confinement and catalog-entry manifest checks. Only the
   * publisher trust decision is delegated, allowing a protected runtime to apply an app-aware
   * approval without adding the publisher to the ordinary app-key registry.
   *
   * @param entry authenticated catalog entry and expected manifest identity
   * @param artifactZip downloaded and digest-verified bundle ZIP
   * @param scratchDirectory host-owned extraction root
   * @param verificationPolicy publisher authorization applied to the extracted bundle
   * @return staged bundle root ready for AppHost
   * @throws IOException if extraction, verification, or manifest binding fails
   */
  public Path extract(
      AppCatalogEntry entry,
      Path artifactZip,
      Path scratchDirectory,
      AppCatalogBundleVerificationPolicy verificationPolicy)
      throws IOException {
    return extractBundle(entry, null, artifactZip, scratchDirectory, verificationPolicy)
        .stagedBundleDirectory();
  }

  /**
   * Extracts and contextually authorizes one catalog bundle for an installation plan.
   *
   * @param context exact authenticated catalog and app entry identity
   * @param artifactZip downloaded and digest-verified bundle ZIP
   * @param scratchDirectory host-owned extraction root
   * @param verificationPolicy publisher authorization applied to the extracted bundle
   * @return staged directory and exact publisher-authorization result
   * @throws IOException if extraction, verification, or manifest binding fails
   */
  VerifiedBundle extract(
      AppCatalogBundleVerificationContext context,
      Path artifactZip,
      Path scratchDirectory,
      AppCatalogBundleVerificationPolicy verificationPolicy)
      throws IOException {
    AppCatalogBundleVerificationContext checkedContext = Objects.requireNonNull(context, "context");
    return extractBundle(
        checkedContext.entry(), checkedContext, artifactZip, scratchDirectory, verificationPolicy);
  }

  private static VerifiedBundle extractBundle(
      AppCatalogEntry entry,
      AppCatalogBundleVerificationContext context,
      Path artifactZip,
      Path scratchDirectory,
      AppCatalogBundleVerificationPolicy verificationPolicy)
      throws IOException {
    AppCatalogEntry checkedEntry = Objects.requireNonNull(entry, "entry");
    Path zipPath = Objects.requireNonNull(artifactZip, "artifactZip").toAbsolutePath().normalize();
    Path scratchRoot = Objects.requireNonNull(scratchDirectory, "scratchDirectory");
    Files.createDirectories(scratchRoot);
    Path stagedRoot = Files.createTempDirectory(scratchRoot, "catalog-bundle-");
    try {
      extractZip(zipPath, stagedRoot);
      AppCatalogBundleVerificationResult verificationResult =
          verifyExtractedBundle(checkedEntry, context, stagedRoot, verificationPolicy);
      return new VerifiedBundle(stagedRoot, verificationResult);
    } catch (IOException | RuntimeException exception) {
      deleteRecursively(stagedRoot);
      throw exception;
    }
  }

  /**
   * Re-verifies a retained staged bundle in its original authenticated context.
   *
   * @param context exact catalog and app entry identity retained by the plan
   * @param stagedBundleDirectory retained private staging directory
   * @param verificationPolicy publisher authorization applied before plan use
   * @return current exact publisher-authorization result
   * @throws IOException if the staged bundle is no longer exact or authorized
   */
  AppCatalogBundleVerificationResult verifyStagedBundle(
      AppCatalogBundleVerificationContext context,
      Path stagedBundleDirectory,
      AppCatalogBundleVerificationPolicy verificationPolicy)
      throws IOException {
    AppCatalogBundleVerificationContext checkedContext = Objects.requireNonNull(context, "context");
    Path stagedRoot =
        Objects.requireNonNull(stagedBundleDirectory, STAGED_BUNDLE_DIRECTORY_PARAMETER)
            .toAbsolutePath()
            .normalize();
    return verifyExtractedBundle(
        checkedContext.entry(), checkedContext, stagedRoot, verificationPolicy);
  }

  private static Path requireReadableArtifactZip(Path artifactZip) {
    Path normalized =
        Objects.requireNonNull(artifactZip, "artifactZip").toAbsolutePath().normalize();
    if (Files.isSymbolicLink(normalized)) {
      throw invalidBundle("zip artifact must not be a symbolic link");
    }
    if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)) {
      throw invalidBundle("zip artifact must be a regular file");
    }
    return normalized;
  }

  private static void extractZip(Path zipPath, Path stagedRoot) throws IOException {
    extractZip(zipPath, stagedRoot, MAX_EXTRACTED_BYTES);
  }

  // Archive expansion is safe here because every entry is path-normalized, duplicate-checked,
  // rooted under the private staging directory, and bounded by entry-count and byte caps.
  @SuppressWarnings("java:S5042")
  static void extractZip(Path zipPath, Path stagedRoot, long maxExtractedBytes) throws IOException {
    Path extractionRoot = stagedRoot.toAbsolutePath().normalize();
    ExtractionState state = new ExtractionState(maxExtractedBytes);
    Map<String, Integer> unixModesByPath = readCentralDirectoryUnixModes(zipPath);
    try (InputStream fileInput = Files.newInputStream(zipPath);
        ZipInputStream zipInput = new ZipInputStream(fileInput)) {
      ZipEntry entry;
      while ((entry = zipInput.getNextEntry()) != null) {
        String normalizedName = normalizeZipEntryName(entry.getName(), entry.isDirectory());
        if (isIgnoredArchiveMetadata(normalizedName)) {
          state.recordIgnoredEntry();
          drainEntry(zipInput, state);
          zipInput.closeEntry();
          continue;
        }
        state.recordEntry(normalizedName);
        Path target = resolveZipEntryTarget(extractionRoot, normalizedName);
        if (entry.isDirectory()) {
          createDirectory(target);
        } else {
          createFile(zipInput, target, state, unixModesByPath.get(normalizedName));
        }
        zipInput.closeEntry();
      }
    } catch (ZipException exception) {
      throw invalidBundle("zip artifact is corrupt", exception);
    }
  }

  private static void drainEntry(ZipInputStream zipInput, ExtractionState state)
      throws IOException {
    byte[] buffer = new byte[COPY_BUFFER_BYTES];
    int bytesRead;
    while ((bytesRead = zipInput.read(buffer)) >= 0) {
      if (bytesRead == 0) {
        continue;
      }
      state.recordExtractedBytes(bytesRead);
    }
  }

  private static Path resolveZipEntryTarget(Path extractionRoot, String normalizedName) {
    try {
      Path target = extractionRoot.resolve(normalizedName).normalize();
      if (!target.startsWith(extractionRoot)) {
        throw invalidBundle("zip artifact entry escapes staged root: " + normalizedName);
      }
      return target;
    } catch (InvalidPathException exception) {
      throw invalidBundle(
          "zip artifact contains an invalid entry name: " + normalizedName, exception);
    }
  }

  private static void createDirectory(Path target) throws IOException {
    Path parent = target.getParent();
    if (parent != null) {
      createParentDirectories(parent);
    }
    try {
      if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)
          && !Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS)) {
        throw invalidBundle("zip artifact directory conflicts with a file");
      }
      if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
        Files.createDirectory(target);
      }
    } catch (FileAlreadyExistsException | NotDirectoryException _) {
      throw invalidBundle("zip artifact directory conflicts with a file");
    }
  }

  private static void createFile(
      ZipInputStream zipInput, Path target, ExtractionState state, Integer unixMode)
      throws IOException {
    Path parent = target.getParent();
    if (parent == null) {
      throw invalidBundle("zip artifact file has no parent directory");
    }
    createParentDirectories(parent);
    if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
      throw invalidBundle("zip artifact overwrites an existing entry");
    }
    byte[] buffer = new byte[COPY_BUFFER_BYTES];
    try (OutputStream output = Files.newOutputStream(target, StandardOpenOption.CREATE_NEW)) {
      int bytesRead;
      while ((bytesRead = zipInput.read(buffer)) >= 0) {
        if (bytesRead == 0) {
          continue;
        }
        state.recordExtractedBytes(bytesRead);
        output.write(buffer, 0, bytesRead);
      }
    }
    applyExecutableMode(target, unixMode);
  }

  private static void createParentDirectories(Path parent) throws IOException {
    if (Files.exists(parent, LinkOption.NOFOLLOW_LINKS)) {
      if (!Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
        throw invalidBundle(PARENT_DIRECTORY_CONFLICT_MESSAGE);
      }
      return;
    }
    rejectExistingFileAncestor(parent);
    try {
      Files.createDirectories(parent);
    } catch (FileAlreadyExistsException | NotDirectoryException _) {
      throw invalidBundle(PARENT_DIRECTORY_CONFLICT_MESSAGE);
    }
  }

  private static void rejectExistingFileAncestor(Path path) {
    Path current = path.getParent();
    while (current != null && !Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
      current = current.getParent();
    }
    if (current != null && !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
      throw invalidBundle(PARENT_DIRECTORY_CONFLICT_MESSAGE);
    }
  }

  private static void applyExecutableMode(Path target, Integer unixMode) throws IOException {
    if (unixMode == null || (unixMode & UNIX_EXECUTE_BITS) == 0) {
      return;
    }
    if (Files.getFileStore(target).supportsFileAttributeView("posix")) {
      Set<PosixFilePermission> permissions =
          Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS);
      setExecutablePermission(
          permissions, PosixFilePermission.OWNER_EXECUTE, unixMode, UNIX_OWNER_EXECUTE);
      setExecutablePermission(
          permissions, PosixFilePermission.GROUP_EXECUTE, unixMode, UNIX_GROUP_EXECUTE);
      setExecutablePermission(
          permissions, PosixFilePermission.OTHERS_EXECUTE, unixMode, UNIX_OTHER_EXECUTE);
      Files.setPosixFilePermissions(target, permissions);
    } else {
      boolean executableRestored = target.toFile().setExecutable(true, false);
      if (!executableRestored && !Files.isExecutable(target)) {
        throw invalidBundle("zip artifact executable mode could not be restored");
      }
    }
  }

  private static void setExecutablePermission(
      Set<PosixFilePermission> permissions,
      PosixFilePermission permission,
      int unixMode,
      int executeBit) {
    if ((unixMode & executeBit) != 0) {
      permissions.add(permission);
    } else {
      permissions.remove(permission);
    }
  }

  private static Map<String, Integer> readCentralDirectoryUnixModes(Path zipPath)
      throws IOException {
    try (SeekableByteChannel channel = Files.newByteChannel(zipPath, StandardOpenOption.READ)) {
      EndOfCentralDirectory endOfCentralDirectory = readEndOfCentralDirectory(channel);
      Map<String, Integer> unixModesByPath = new HashMap<>();
      channel.position(endOfCentralDirectory.centralDirectoryOffset());
      long centralDirectoryEnd =
          endOfCentralDirectory.centralDirectoryOffset()
              + endOfCentralDirectory.centralDirectorySize();
      for (int entryIndex = 0; entryIndex < endOfCentralDirectory.entryCount(); entryIndex++) {
        CentralDirectoryEntry entry = readCentralDirectoryEntry(channel, centralDirectoryEnd);
        if (entry.unixMode() != null && (entry.unixMode() & UNIX_EXECUTE_BITS) != 0) {
          String normalizedName = normalizeZipEntryName(entry.name(), entry.directory());
          if (isIgnoredArchiveMetadata(normalizedName)) {
            continue;
          }
          unixModesByPath.putIfAbsent(normalizedName, entry.unixMode());
        }
      }
      return Map.copyOf(unixModesByPath);
    }
  }

  private static EndOfCentralDirectory readEndOfCentralDirectory(SeekableByteChannel channel)
      throws IOException {
    long zipSize = channel.size();
    if (zipSize < END_OF_CENTRAL_DIRECTORY_MIN_BYTES) {
      throw invalidBundle("zip artifact missing end-of-central-directory record");
    }
    int tailBytes =
        (int) Math.min(zipSize, (long) END_OF_CENTRAL_DIRECTORY_MIN_BYTES + ZIP_MAX_COMMENT_BYTES);
    ByteBuffer tail = ByteBuffer.allocate(tailBytes).order(ByteOrder.LITTLE_ENDIAN);
    channel.position(zipSize - tailBytes);
    readFully(channel, tail, "zip artifact end-of-central-directory record");
    for (int offset = tailBytes - END_OF_CENTRAL_DIRECTORY_MIN_BYTES; offset >= 0; offset--) {
      if (tail.getInt(offset) == END_OF_CENTRAL_DIRECTORY_SIGNATURE
          && endOfCentralDirectoryRecordEndsAtTailEnd(tail, offset, tailBytes)) {
        return readEndOfCentralDirectory(tail, offset, zipSize);
      }
    }
    throw invalidBundle("zip artifact missing end-of-central-directory record");
  }

  private static boolean endOfCentralDirectoryRecordEndsAtTailEnd(
      ByteBuffer tail, int offset, int tailBytes) {
    int commentLength = unsignedShort(tail, offset + 20);
    return offset + END_OF_CENTRAL_DIRECTORY_MIN_BYTES + commentLength == tailBytes;
  }

  private static EndOfCentralDirectory readEndOfCentralDirectory(
      ByteBuffer tail, int offset, long zipSize) {
    int diskNumber = unsignedShort(tail, offset + 4);
    int centralDirectoryDisk = unsignedShort(tail, offset + 6);
    int entriesOnDisk = unsignedShort(tail, offset + 8);
    int totalEntries = unsignedShort(tail, offset + 10);
    long centralDirectorySize = unsignedInt(tail, offset + 12);
    long centralDirectoryOffset = unsignedInt(tail, offset + 16);
    if (diskNumber != 0 || centralDirectoryDisk != 0 || entriesOnDisk != totalEntries) {
      throw invalidBundle("zip artifact must not span multiple disks");
    }
    if (totalEntries == ZIP64_UNSIGNED_SHORT_MARKER
        || centralDirectorySize == ZIP64_UNSIGNED_INT_MARKER
        || centralDirectoryOffset == ZIP64_UNSIGNED_INT_MARKER) {
      throw invalidBundle("zip64 catalog artifacts are not supported");
    }
    if (totalEntries > MAX_ZIP_ENTRIES) {
      throw invalidBundle("zip artifact contains too many entries");
    }
    if (centralDirectoryOffset > zipSize
        || centralDirectorySize > zipSize - centralDirectoryOffset) {
      throw invalidBundle("zip artifact central directory escapes artifact");
    }
    return new EndOfCentralDirectory(totalEntries, centralDirectoryOffset, centralDirectorySize);
  }

  private static CentralDirectoryEntry readCentralDirectoryEntry(
      SeekableByteChannel channel, long centralDirectoryEnd) throws IOException {
    long headerOffset = channel.position();
    if (headerOffset + CENTRAL_DIRECTORY_HEADER_BYTES > centralDirectoryEnd) {
      throw invalidBundle("zip artifact central directory is truncated");
    }
    ByteBuffer header =
        readBuffer(
            channel, CENTRAL_DIRECTORY_HEADER_BYTES, "zip artifact central directory header");
    if (header.getInt(0) != CENTRAL_DIRECTORY_HEADER_SIGNATURE) {
      throw invalidBundle("zip artifact central directory is malformed");
    }
    int versionMadeBy = unsignedShort(header, 4);
    int hostPlatform = (versionMadeBy >>> 8) & 0xFF;
    int nameLength = unsignedShort(header, 28);
    int extraLength = unsignedShort(header, 30);
    int commentLength = unsignedShort(header, 32);
    long externalAttributes = unsignedInt(header, 38);
    long variableEnd = channel.position() + nameLength + extraLength + commentLength;
    if (variableEnd > centralDirectoryEnd) {
      throw invalidBundle("zip artifact central directory entry is truncated");
    }
    byte[] nameBytes = readBytes(channel, nameLength);
    skip(channel, extraLength + commentLength);
    String name = decodeZipEntryName(nameBytes);
    Integer unixMode = null;
    if (hostPlatform == UNIX_HOST_PLATFORM) {
      unixMode = (int) ((externalAttributes >>> UNIX_MODE_SHIFT) & 0xFFFF);
    }
    return new CentralDirectoryEntry(name, unixMode);
  }

  private static String decodeZipEntryName(byte[] nameBytes) {
    return new String(nameBytes, StandardCharsets.UTF_8);
  }

  private static ByteBuffer readBuffer(
      SeekableByteChannel channel, int byteCount, String description) throws IOException {
    ByteBuffer buffer = ByteBuffer.allocate(byteCount).order(ByteOrder.LITTLE_ENDIAN);
    readFully(channel, buffer, description);
    return buffer;
  }

  private static byte[] readBytes(SeekableByteChannel channel, int byteCount) throws IOException {
    ByteBuffer buffer = readBuffer(channel, byteCount, "zip artifact central directory entry name");
    byte[] bytes = new byte[byteCount];
    buffer.get(bytes);
    return bytes;
  }

  private static void readFully(SeekableByteChannel channel, ByteBuffer buffer, String description)
      throws IOException {
    while (buffer.hasRemaining()) {
      if (channel.read(buffer) < 0) {
        throw invalidBundle(description + " is truncated");
      }
    }
    buffer.flip();
  }

  private static void skip(SeekableByteChannel channel, int byteCount) throws IOException {
    channel.position(channel.position() + byteCount);
  }

  private static int unsignedShort(ByteBuffer buffer, int offset) {
    return Short.toUnsignedInt(buffer.getShort(offset));
  }

  private static long unsignedInt(ByteBuffer buffer, int offset) {
    return Integer.toUnsignedLong(buffer.getInt(offset));
  }

  private static String normalizeZipEntryName(String rawName, boolean directory) {
    if (rawName == null || rawName.isBlank()) {
      throw invalidBundle("zip artifact contains a blank entry name");
    }
    if (rawName.indexOf('\\') >= 0) {
      throw invalidBundle("zip artifact entries must use '/' separators");
    }
    String name =
        directory && rawName.endsWith("/") ? rawName.substring(0, rawName.length() - 1) : rawName;
    if (name.startsWith("/") || startsWithWindowsDrive(name)) {
      throw invalidBundle("zip artifact contains an absolute entry: " + rawName);
    }
    for (String segment : name.split("/", -1)) {
      if (segment.isEmpty() || ".".equals(segment) || "..".equals(segment)) {
        throw invalidBundle("zip artifact entry escapes staged root: " + rawName);
      }
    }
    return name;
  }

  private static boolean startsWithWindowsDrive(String name) {
    return name.length() >= 2 && Character.isLetter(name.charAt(0)) && name.charAt(1) == ':';
  }

  private static boolean isIgnoredArchiveMetadata(String normalizedName) {
    for (String segment : normalizedName.split("/", -1)) {
      if (segment.equals("__MACOSX") || segment.startsWith("._") || segment.equals(".DS_Store")) {
        return true;
      }
    }
    return false;
  }

  private static AppBundleManifest verifyExtractedSignedArtifact(Path stagedRoot)
      throws IOException {
    Path manifestFile = stagedRoot.resolve(AppBundleManifestParser.MANIFEST_FILE_NAME);
    if (!Files.isRegularFile(manifestFile, LinkOption.NOFOLLOW_LINKS)) {
      throw invalidBundle("zip artifact must contain cryptad-app.properties at the root");
    }
    requireCanonicalSignedSidecars(stagedRoot);
    AppBundleVerifier.read(stagedRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME));
    AppBundleDigestVerifier.verify(stagedRoot);
    return AppBundleManifestParser.parse(manifestFile);
  }

  private static void requireCanonicalSignedSidecars(Path stagedRoot) throws IOException {
    boolean digest = false;
    boolean signature = false;
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(stagedRoot)) {
      for (Path entry : entries) {
        String name = Objects.requireNonNull(entry.getFileName(), "artifact root entry").toString();
        String normalized = name.toLowerCase(Locale.ROOT);
        if (!isRootDistributionSidecar(normalized)) {
          continue;
        }
        if (!name.equals(normalized)) {
          throw invalidBundle(
              "zip artifact contains a non-canonical distribution sidecar name: " + name);
        }
        switch (normalized) {
          case AppBundleDigest.DIGEST_FILE_NAME -> digest = true;
          case AppBundleSignature.SIGNATURE_FILE_NAME -> signature = true;
          default -> throw invalidBundle("zip artifact must not contain catalog sidecars");
        }
      }
    }
    if (!digest || !signature) {
      throw invalidBundle(
          "zip artifact must contain signed bundle sidecars "
              + AppBundleDigest.DIGEST_FILE_NAME
              + " and "
              + AppBundleSignature.SIGNATURE_FILE_NAME);
    }
  }

  private static boolean isRootDistributionSidecar(String normalizedName) {
    return AppBundleDigest.DIGEST_FILE_NAME.equals(normalizedName)
        || AppBundleSignature.SIGNATURE_FILE_NAME.equals(normalizedName)
        || AppCatalogSignature.CATALOG_FILE_NAME.equals(normalizedName)
        || AppCatalogSignature.SIGNATURE_FILE_NAME.equals(normalizedName)
        || "cryptad-app.catalog".equals(normalizedName)
        || "cryptad-app.catalog.signature".equals(normalizedName);
  }

  private static AppCatalogBundleVerificationResult verifyExtractedBundle(
      AppCatalogEntry entry,
      AppCatalogBundleVerificationContext context,
      Path stagedRoot,
      AppCatalogBundleVerificationPolicy verificationPolicy)
      throws IOException {
    Path manifestFile = stagedRoot.resolve(AppBundleManifestParser.MANIFEST_FILE_NAME);
    if (!Files.isRegularFile(manifestFile, LinkOption.NOFOLLOW_LINKS)) {
      throw invalidBundle("zip artifact must contain cryptad-app.properties at the root");
    }
    try {
      AppCatalogBundleVerificationPolicy checkedPolicy =
          Objects.requireNonNull(verificationPolicy, "verificationPolicy");
      AppCatalogBundleVerificationResult verificationResult;
      if (context == null) {
        checkedPolicy.verify(stagedRoot);
        verificationResult = AppCatalogBundleVerificationResult.unrecorded();
      } else {
        verificationResult =
            Objects.requireNonNull(
                checkedPolicy.verify(context, stagedRoot), "bundle verification result");
      }
      AppBundleManifest manifest = AppBundleManifestParser.parse(manifestFile);
      if (!entry.appId().equals(manifest.appId())) {
        throw invalidBundle("catalog app id does not match extracted bundle manifest");
      }
      if (!entry.version().equals(manifest.appVersion())) {
        throw invalidBundle("catalog app version does not match extracted bundle manifest");
      }
      return verificationResult;
    } catch (AppDistributionException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_APP_BUNDLE, exception.getMessage(), exception);
    }
  }

  /** Staged bundle plus the exact authorization result produced during extraction. */
  record VerifiedBundle(
      Path stagedBundleDirectory, AppCatalogBundleVerificationResult verificationResult) {
    VerifiedBundle {
      Objects.requireNonNull(stagedBundleDirectory, STAGED_BUNDLE_DIRECTORY_PARAMETER);
      Objects.requireNonNull(verificationResult, "verificationResult");
    }
  }

  static void deleteRecursively(Path root) throws IOException {
    if (root == null || !Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    try (var stream = Files.walk(root)) {
      for (Path path : stream.sorted(java.util.Comparator.reverseOrder()).toList()) {
        Files.deleteIfExists(path);
      }
    }
  }

  private static AppCatalogException invalidBundle(String message) {
    return new AppCatalogException(AppCatalogSidecars.INVALID_APP_BUNDLE, message);
  }

  private static AppCatalogException invalidBundle(String message, Throwable cause) {
    return new AppCatalogException(AppCatalogSidecars.INVALID_APP_BUNDLE, message, cause);
  }

  private record EndOfCentralDirectory(
      int entryCount, long centralDirectoryOffset, long centralDirectorySize) {}

  private record CentralDirectoryEntry(String name, Integer unixMode) {
    private boolean directory() {
      return name.endsWith("/")
          || (unixMode != null && (unixMode & UNIX_FILE_TYPE_MASK) == UNIX_DIRECTORY_TYPE);
    }
  }

  private static final class ExtractionState {
    private final Set<String> seenPaths = new HashSet<>();
    private final long maxExtractedBytes;
    private long extractedBytes;
    private int entryCount;

    private ExtractionState(long maxExtractedBytes) {
      if (maxExtractedBytes < 0L) {
        throw new IllegalArgumentException("maxExtractedBytes must be non-negative");
      }
      this.maxExtractedBytes = maxExtractedBytes;
    }

    void recordEntry(String normalizedName) {
      recordEntryCount();
      if (!seenPaths.add(normalizedName)) {
        throw invalidBundle("zip artifact contains duplicate entry: " + normalizedName);
      }
    }

    void recordIgnoredEntry() {
      recordEntryCount();
    }

    private void recordEntryCount() {
      entryCount++;
      if (entryCount > MAX_ZIP_ENTRIES) {
        throw invalidBundle("zip artifact contains too many entries");
      }
    }

    void recordExtractedBytes(int bytesRead) {
      extractedBytes += bytesRead;
      if (extractedBytes > maxExtractedBytes) {
        throw invalidBundle("zip artifact exceeds extracted size cap");
      }
    }
  }
}
