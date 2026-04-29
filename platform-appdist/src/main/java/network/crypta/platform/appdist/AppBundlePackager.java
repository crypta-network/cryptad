package network.crypta.platform.appdist;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.jetbrains.annotations.NotNull;

/**
 * Packages a staged app bundle directory into a deterministic ZIP artifact.
 *
 * <p>The packager is a reusable library API for build and developer tooling that need the same
 * archive format consumed by catalog installation flows. Before writing anything, it validates the
 * source bundle through the existing appdist structure and digest machinery. It walks the bundle
 * without following links, rejects archive metadata that should never enter a signed payload, and
 * emits regular files in lexicographic bundle-relative order.
 *
 * <p>ZIP entries are written as {@link ZipEntry#STORED} with precomputed size and CRC values. Entry
 * names always use {@code /} separators, timestamps are fixed, and the central directory is patched
 * with Unix external attributes so POSIX executable bits can be restored by compatible extractors.
 * Existing canonical signed sidecars are preserved byte-for-byte when present; the packager does
 * not rewrite or create signatures.
 *
 * <p>The packager is intentionally stricter than a generic ZIP utility. It rejects symlink and
 * reparse-point escapes, macOS archive metadata, catalog sidecars embedded in bundles, ZIP64-only
 * file sizes, and bundles above the catalog installer's entry cap. A ZIP produced by this class is
 * suitable for catalog authoring, but it is not automatically trusted; callers still need to sign
 * the staged bundle or generated catalog through the distribution signing APIs.
 *
 * @see AppBundleStructureValidator
 * @see AppBundleDigestWriter
 */
public final class AppBundlePackager {
  /**
   * Maximum number of ZIP entries accepted by Cryptad catalog install and update paths.
   *
   * <p>The packager emits only regular-file entries and rejects bundles above this cap so artifacts
   * created by developer tooling remain installable by {@code platform-appcatalog}. The limit is
   * expressed in files rather than bytes because the catalog extractor applies an entry-count guard
   * before it verifies and installs the artifact.
   */
  public static final int MAX_CATALOG_ZIP_ENTRIES = 4096;

  private static final int COPY_BUFFER_BYTES = 64 * 1024;
  private static final long FIXED_ZIP_TIME_MILLIS = 0L;
  private static final int END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054B50;
  private static final int CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014B50;
  private static final int END_OF_CENTRAL_DIRECTORY_MIN_BYTES = 22;
  private static final int ZIP_MAX_COMMENT_BYTES = 65_535;
  private static final int CENTRAL_DIRECTORY_HEADER_BYTES = 46;
  private static final int ZIP64_UNSIGNED_SHORT_MARKER = 0xFFFF;
  private static final long ZIP64_UNSIGNED_INT_MARKER = 0xFFFF_FFFFL;
  private static final int UNIX_HOST_PLATFORM = 3;
  private static final int UNIX_MODE_SHIFT = 16;
  private static final int UNIX_REGULAR_FILE_TYPE = 32_768;
  private static final int UNIX_OWNER_READ = 256;
  private static final int UNIX_OWNER_WRITE = 128;
  private static final int UNIX_OWNER_EXECUTE = 64;
  private static final int UNIX_GROUP_READ = 32;
  private static final int UNIX_GROUP_EXECUTE = 8;
  private static final int UNIX_OTHER_READ = 4;
  private static final int UNIX_OTHER_EXECUTE = 1;
  private static final int OWNER_EXECUTE_CHAR_INDEX = 2;
  private static final int GROUP_EXECUTE_CHAR_INDEX = 5;
  private static final int OTHER_EXECUTE_CHAR_INDEX = 8;
  private static final int DEFAULT_UNIX_FILE_PERMISSIONS =
      UNIX_OWNER_READ | UNIX_OWNER_WRITE | UNIX_GROUP_READ | UNIX_OTHER_READ;
  private static final Set<String> CANONICAL_DISTRIBUTION_SIDECARS =
      Set.of(
          AppBundleDigest.DIGEST_FILE_NAME,
          AppBundleSignature.SIGNATURE_FILE_NAME,
          "cryptad-app.catalog",
          "cryptad-app.catalog.signature");

  private AppBundlePackager() {}

  /**
   * Validates and packages one staged app bundle directory.
   *
   * <p>The output path may name an existing regular file, which is replaced only after a complete
   * temporary ZIP has been written and patched in the same parent directory. The output must not be
   * inside the source bundle, must not resolve through a symlinked parent into the source bundle,
   * and must not already be a symlink or directory.
   *
   * <p>Validation runs before the temporary artifact is created. Existing digest and signature
   * sidecars are preserved when they form a canonical signed-bundle pair; partial or non-canonical
   * sidecars fail the package operation. The returned digest describes the staged bundle contents,
   * while the artifact size and SHA-256 describe the final ZIP bytes that catalogs reference.
   *
   * @param bundleRoot staged app bundle root directory to validate and package
   * @param outputZip target ZIP artifact path to create or atomically replace
   * @return immutable result describing the source digest and written ZIP artifact
   * @throws IOException if validation fails or the artifact cannot be written safely
   */
  public static PackagedAppBundle packageBundle(Path bundleRoot, Path outputZip)
      throws IOException {
    Path normalizedBundleRoot = AppDistributionSidecars.requireBundleRoot(bundleRoot);
    Path bundleRealRoot = normalizedBundleRoot.toRealPath();
    Path normalizedOutput = requireSafeOutputPath(outputZip, normalizedBundleRoot, bundleRealRoot);
    AppBundleDigest bundleDigest = validateBundleForPackaging(normalizedBundleRoot);
    ZipInventory inventory = collectZipInventory(normalizedBundleRoot, bundleRealRoot);
    Path tempZip = createTemporaryZipPath(normalizedOutput);
    try {
      writeZip(tempZip, inventory.entries());
      patchCentralDirectoryUnixModes(tempZip, inventory.unixModesByName());
      moveReplacing(tempZip, normalizedOutput);
    } catch (IOException | RuntimeException exception) {
      Files.deleteIfExists(tempZip);
      throw exception;
    }
    long sizeBytes = Files.size(normalizedOutput);
    String artifactSha256 = sha256Hex(normalizedOutput);
    return new PackagedAppBundle(
        normalizedBundleRoot, normalizedOutput, bundleDigest, sizeBytes, artifactSha256);
  }

  private static Path requireSafeOutputPath(
      Path outputZip, Path normalizedBundleRoot, Path bundleRealRoot) throws IOException {
    Path normalizedOutput =
        Objects.requireNonNull(outputZip, "outputZip").toAbsolutePath().normalize();
    if (normalizedOutput.getFileName() == null) {
      throw new AppDistributionException("output ZIP path must name a file");
    }
    rejectOutputInsideBundle(normalizedOutput, normalizedBundleRoot, bundleRealRoot);
    Path parent = normalizedOutput.getParent();
    if (parent == null) {
      throw new AppDistributionException("output ZIP path must have a parent directory");
    }
    createSafeOutputParentDirectories(parent, bundleRealRoot);
    Path parentReal = parent.toRealPath();
    if (isInsideOrEqual(parentReal, bundleRealRoot)) {
      throw new AppDistributionException("output ZIP must not be inside the bundle root");
    }
    if (Files.exists(normalizedOutput, LinkOption.NOFOLLOW_LINKS)) {
      if (Files.isSymbolicLink(normalizedOutput)) {
        throw new AppDistributionException("output ZIP path must not be a symbolic link");
      }
      if (!Files.isRegularFile(normalizedOutput, LinkOption.NOFOLLOW_LINKS)) {
        throw new AppDistributionException("output ZIP path must be a regular file");
      }
      rejectOutputInsideBundle(normalizedOutput.toRealPath(), normalizedBundleRoot, bundleRealRoot);
    }
    return normalizedOutput;
  }

  private static void createSafeOutputParentDirectories(Path parent, Path bundleRealRoot)
      throws IOException {
    Path existingAncestor = parent;
    while (existingAncestor != null && !Files.exists(existingAncestor, LinkOption.NOFOLLOW_LINKS)) {
      existingAncestor = existingAncestor.getParent();
    }
    if (existingAncestor == null
        || !Files.isDirectory(existingAncestor, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException("output ZIP parent must be a directory");
    }
    if (isInsideOrEqual(existingAncestor.toRealPath(), bundleRealRoot)) {
      throw new AppDistributionException("output ZIP must not be inside the bundle root");
    }
    Files.createDirectories(parent);
    if (!Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException("output ZIP parent must be a directory");
    }
  }

  private static void rejectOutputInsideBundle(
      Path output, Path normalizedBundleRoot, Path bundleRealRoot) throws AppDistributionException {
    if (isInsideOrEqual(output, normalizedBundleRoot) || isInsideOrEqual(output, bundleRealRoot)) {
      throw new AppDistributionException("output ZIP must not be inside the bundle root");
    }
  }

  private static boolean isInsideOrEqual(Path candidate, Path root) {
    return candidate.equals(root) || candidate.startsWith(root);
  }

  private static AppBundleDigest validateBundleForPackaging(Path normalizedBundleRoot)
      throws IOException {
    rejectNonCanonicalDistributionSidecars(normalizedBundleRoot);
    AppBundleDigest bundleDigest = AppBundleDigestWriter.create(normalizedBundleRoot);
    Path digestSidecar = normalizedBundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME);
    Path signatureSidecar = normalizedBundleRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME);
    boolean digestSidecarExists = Files.exists(digestSidecar, LinkOption.NOFOLLOW_LINKS);
    boolean signatureSidecarExists = Files.exists(signatureSidecar, LinkOption.NOFOLLOW_LINKS);
    if (Files.exists(normalizedBundleRoot.resolve("cryptad-app.catalog"), LinkOption.NOFOLLOW_LINKS)
        || Files.exists(
            normalizedBundleRoot.resolve("cryptad-app.catalog.signature"),
            LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException("bundle must not contain catalog sidecars");
    }
    if (digestSidecarExists != signatureSidecarExists) {
      throw new AppDistributionException(
          "signed bundle sidecars must include both "
              + AppBundleDigest.DIGEST_FILE_NAME
              + " and "
              + AppBundleSignature.SIGNATURE_FILE_NAME);
    }
    if (digestSidecarExists) {
      AppBundleDigestVerifier.verify(normalizedBundleRoot);
      AppBundleVerifier.read(signatureSidecar);
    }
    return bundleDigest;
  }

  private static void rejectNonCanonicalDistributionSidecars(Path normalizedBundleRoot)
      throws IOException {
    try (var entries = Files.newDirectoryStream(normalizedBundleRoot)) {
      for (Path entry : entries) {
        Path fileName = entry.getFileName();
        if (fileName == null) {
          continue;
        }
        String name = fileName.toString();
        if (AppDistributionSidecars.isDistributionSidecar(name)
            && !CANONICAL_DISTRIBUTION_SIDECARS.contains(name)) {
          throw new AppDistributionException(
              "bundle contains a non-canonical distribution sidecar name: " + name);
        }
      }
    }
  }

  private static ZipInventory collectZipInventory(Path normalizedBundleRoot, Path bundleRealRoot)
      throws IOException {
    TreeMap<String, ZipEntrySource> entriesByName = new TreeMap<>();
    Files.walkFileTree(
        normalizedBundleRoot,
        new PackagingFileVisitor(normalizedBundleRoot, bundleRealRoot, entriesByName));
    if (entriesByName.size() > MAX_CATALOG_ZIP_ENTRIES) {
      throw new AppDistributionException(
          "bundle contains too many files for a catalog ZIP artifact; maximum is "
              + MAX_CATALOG_ZIP_ENTRIES);
    }
    Map<String, Integer> unixModesByName = new HashMap<>();
    for (ZipEntrySource source : entriesByName.values()) {
      unixModesByName.put(source.name(), source.unixMode());
    }
    return new ZipInventory(List.copyOf(entriesByName.values()), Map.copyOf(unixModesByName));
  }

  private static void writeZip(Path tempZip, List<ZipEntrySource> entries) throws IOException {
    try (OutputStream output =
            Files.newOutputStream(
                tempZip, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
        ZipOutputStream zip = new ZipOutputStream(output, StandardCharsets.UTF_8)) {
      for (ZipEntrySource source : entries) {
        writeZipEntry(zip, source);
      }
    }
  }

  private static void writeZipEntry(ZipOutputStream zip, ZipEntrySource source) throws IOException {
    ZipEntry entry = new ZipEntry(source.name());
    entry.setMethod(ZipEntry.STORED);
    entry.setSize(source.size());
    entry.setCompressedSize(source.size());
    entry.setCrc(source.crc());
    entry.setTime(FIXED_ZIP_TIME_MILLIS);
    zip.putNextEntry(entry);
    copyFile(source.file(), zip);
    zip.closeEntry();
  }

  private static void copyFile(Path file, OutputStream output) throws IOException {
    byte[] buffer = new byte[COPY_BUFFER_BYTES];
    try (InputStream input = Files.newInputStream(file)) {
      int bytesRead;
      while ((bytesRead = input.read(buffer)) >= 0) {
        if (bytesRead > 0) {
          output.write(buffer, 0, bytesRead);
        }
      }
    }
  }

  private static Path createTemporaryZipPath(Path normalizedOutput) throws IOException {
    Path parent = Objects.requireNonNull(normalizedOutput.getParent(), "output ZIP parent");
    String fileName =
        Objects.requireNonNull(normalizedOutput.getFileName(), "output ZIP file name").toString();
    return Files.createTempFile(parent, fileName + ".", ".tmp");
  }

  private static void moveReplacing(Path tempZip, Path normalizedOutput) throws IOException {
    try {
      Files.move(
          tempZip,
          normalizedOutput,
          StandardCopyOption.REPLACE_EXISTING,
          StandardCopyOption.ATOMIC_MOVE);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(tempZip, normalizedOutput, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static void patchCentralDirectoryUnixModes(Path zipPath, Map<String, Integer> unixModes)
      throws IOException {
    try (SeekableByteChannel channel =
        Files.newByteChannel(zipPath, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
      EndOfCentralDirectory endOfCentralDirectory = readEndOfCentralDirectory(channel);
      channel.position(endOfCentralDirectory.centralDirectoryOffset());
      long centralDirectoryEnd =
          endOfCentralDirectory.centralDirectoryOffset()
              + endOfCentralDirectory.centralDirectorySize();
      for (int entryIndex = 0; entryIndex < endOfCentralDirectory.entryCount(); entryIndex++) {
        patchCentralDirectoryEntry(channel, centralDirectoryEnd, unixModes);
      }
    }
  }

  private static void patchCentralDirectoryEntry(
      SeekableByteChannel channel, long centralDirectoryEnd, Map<String, Integer> unixModes)
      throws IOException {
    long headerOffset = channel.position();
    if (headerOffset + CENTRAL_DIRECTORY_HEADER_BYTES > centralDirectoryEnd) {
      throw new AppDistributionException("ZIP central directory is truncated");
    }
    ByteBuffer header =
        readBuffer(channel, CENTRAL_DIRECTORY_HEADER_BYTES, "ZIP central directory header");
    if (header.getInt(0) != CENTRAL_DIRECTORY_HEADER_SIGNATURE) {
      throw new AppDistributionException("ZIP central directory is malformed");
    }
    int nameLength = unsignedShort(header, 28);
    int extraLength = unsignedShort(header, 30);
    int commentLength = unsignedShort(header, 32);
    long variableEnd = channel.position() + nameLength + extraLength + commentLength;
    if (variableEnd > centralDirectoryEnd) {
      throw new AppDistributionException("ZIP central directory entry is truncated");
    }
    String name = new String(readBytes(channel, nameLength), StandardCharsets.UTF_8);
    Integer unixMode = unixModes.get(name);
    if (unixMode == null) {
      throw new AppDistributionException(
          "ZIP central directory contains an unexpected entry: " + name);
    }
    skip(channel, extraLength + commentLength);
    int versionMadeBy = unsignedShort(header, 4);
    int zipVersion = versionMadeBy & 0xFF;
    header.putShort(4, (short) ((UNIX_HOST_PLATFORM << 8) | zipVersion));
    header.putInt(38, unixMode << UNIX_MODE_SHIFT);
    header.position(0);
    channel.position(headerOffset);
    writeFully(channel, header);
    channel.position(variableEnd);
  }

  private static EndOfCentralDirectory readEndOfCentralDirectory(SeekableByteChannel channel)
      throws IOException {
    long zipSize = channel.size();
    if (zipSize < END_OF_CENTRAL_DIRECTORY_MIN_BYTES) {
      throw new AppDistributionException("ZIP artifact missing end-of-central-directory record");
    }
    int tailBytes =
        (int) Math.min(zipSize, (long) END_OF_CENTRAL_DIRECTORY_MIN_BYTES + ZIP_MAX_COMMENT_BYTES);
    ByteBuffer tail = ByteBuffer.allocate(tailBytes).order(ByteOrder.LITTLE_ENDIAN);
    channel.position(zipSize - tailBytes);
    readFully(channel, tail, "ZIP end-of-central-directory record");
    for (int offset = tailBytes - END_OF_CENTRAL_DIRECTORY_MIN_BYTES; offset >= 0; offset--) {
      if (tail.getInt(offset) == END_OF_CENTRAL_DIRECTORY_SIGNATURE
          && endOfCentralDirectoryRecordEndsAtTailEnd(tail, offset, tailBytes)) {
        return readEndOfCentralDirectory(tail, offset, zipSize);
      }
    }
    throw new AppDistributionException("ZIP artifact missing end-of-central-directory record");
  }

  private static boolean endOfCentralDirectoryRecordEndsAtTailEnd(
      ByteBuffer tail, int offset, int tailBytes) {
    int commentLength = unsignedShort(tail, offset + 20);
    return offset + END_OF_CENTRAL_DIRECTORY_MIN_BYTES + commentLength == tailBytes;
  }

  private static EndOfCentralDirectory readEndOfCentralDirectory(
      ByteBuffer tail, int offset, long zipSize) throws AppDistributionException {
    int diskNumber = unsignedShort(tail, offset + 4);
    int centralDirectoryDisk = unsignedShort(tail, offset + 6);
    int entriesOnDisk = unsignedShort(tail, offset + 8);
    int totalEntries = unsignedShort(tail, offset + 10);
    long centralDirectorySize = unsignedInt(tail, offset + 12);
    long centralDirectoryOffset = unsignedInt(tail, offset + 16);
    if (diskNumber != 0 || centralDirectoryDisk != 0 || entriesOnDisk != totalEntries) {
      throw new AppDistributionException("ZIP artifact must not span multiple disks");
    }
    if (totalEntries == ZIP64_UNSIGNED_SHORT_MARKER
        || centralDirectorySize == ZIP64_UNSIGNED_INT_MARKER
        || centralDirectoryOffset == ZIP64_UNSIGNED_INT_MARKER) {
      throw new AppDistributionException("ZIP64 app bundle artifacts are not supported");
    }
    if (centralDirectoryOffset > zipSize
        || centralDirectorySize > zipSize - centralDirectoryOffset) {
      throw new AppDistributionException("ZIP central directory escapes artifact");
    }
    return new EndOfCentralDirectory(totalEntries, centralDirectoryOffset, centralDirectorySize);
  }

  private static ByteBuffer readBuffer(
      SeekableByteChannel channel, int byteCount, String description) throws IOException {
    ByteBuffer buffer = ByteBuffer.allocate(byteCount).order(ByteOrder.LITTLE_ENDIAN);
    readFully(channel, buffer, description);
    return buffer;
  }

  private static byte[] readBytes(SeekableByteChannel channel, int byteCount) throws IOException {
    ByteBuffer buffer = readBuffer(channel, byteCount, "ZIP central directory entry name");
    byte[] bytes = new byte[byteCount];
    buffer.get(bytes);
    return bytes;
  }

  private static void readFully(SeekableByteChannel channel, ByteBuffer buffer, String description)
      throws IOException {
    while (buffer.hasRemaining()) {
      if (channel.read(buffer) < 0) {
        throw new AppDistributionException(description + " is truncated");
      }
    }
    buffer.flip();
  }

  private static void writeFully(SeekableByteChannel channel, ByteBuffer buffer)
      throws IOException {
    while (buffer.hasRemaining()) {
      channel.write(buffer);
    }
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

  private static String sha256Hex(Path file) throws IOException {
    byte[] buffer = new byte[COPY_BUFFER_BYTES];
    var digest = AppDistributionSidecars.newSha256Digest();
    try (InputStream input = Files.newInputStream(file)) {
      int bytesRead;
      while ((bytesRead = input.read(buffer)) >= 0) {
        if (bytesRead > 0) {
          digest.update(buffer, 0, bytesRead);
        }
      }
    }
    return AppDistributionSidecars.lowercaseHex(digest.digest());
  }

  private record ZipInventory(List<ZipEntrySource> entries, Map<String, Integer> unixModesByName) {}

  private record ZipEntrySource(String name, Path file, long size, long crc, int unixMode) {}

  private record EndOfCentralDirectory(
      int entryCount, long centralDirectoryOffset, long centralDirectorySize) {}

  private static final class PackagingFileVisitor extends SimpleFileVisitor<Path> {
    private final Path normalizedBundleRoot;
    private final Path bundleRealRoot;
    private final Map<String, ZipEntrySource> entriesByName;
    private final Set<Path> visitedRealDirectories = new HashSet<>();

    private PackagingFileVisitor(
        Path normalizedBundleRoot, Path bundleRealRoot, Map<String, ZipEntrySource> entriesByName) {
      this.normalizedBundleRoot = normalizedBundleRoot;
      this.bundleRealRoot = bundleRealRoot;
      this.entriesByName = entriesByName;
    }

    @Override
    public @NotNull FileVisitResult preVisitDirectory(
        @NotNull Path directory, @NotNull BasicFileAttributes attributes) throws IOException {
      Path realDirectory =
          AppDistributionSidecars.validateBundleEntry(
              normalizedBundleRoot, bundleRealRoot, directory);
      if (!visitedRealDirectories.add(realDirectory)) {
        throw new AppDistributionException(
            "bundle must not revisit directories via links or reparse points: " + directory);
      }
      if (!directory.equals(normalizedBundleRoot)) {
        rejectArchiveMetadataEntry(normalizeRelativePath(normalizedBundleRoot, directory));
      }
      return FileVisitResult.CONTINUE;
    }

    @Override
    public @NotNull FileVisitResult visitFile(
        @NotNull Path file, @NotNull BasicFileAttributes attributes) throws IOException {
      AppDistributionSidecars.validateBundleEntry(normalizedBundleRoot, bundleRealRoot, file);
      if (!attributes.isRegularFile()) {
        throw new AppDistributionException("bundle must contain regular files only");
      }
      String relativePath = normalizeRelativePath(normalizedBundleRoot, file);
      rejectArchiveMetadataEntry(relativePath);
      FileStats stats = fileStats(file, relativePath);
      ZipEntrySource source =
          new ZipEntrySource(relativePath, file, stats.size(), stats.crc(), unixMode(file));
      ZipEntrySource previous = entriesByName.put(relativePath, source);
      if (previous != null) {
        throw new AppDistributionException(
            "bundle contains duplicate ZIP entry name: " + relativePath);
      }
      return FileVisitResult.CONTINUE;
    }

    @Override
    public @NotNull FileVisitResult visitFileFailed(
        @NotNull Path file, @NotNull IOException exception) throws IOException {
      if (isLinkOrAliasedEntry(file)) {
        throw new AppDistributionException(
            "bundle must not contain links or reparse points: " + file);
      }
      throw new AppDistributionException("failed to inspect bundle contents", exception);
    }

    private static boolean isLinkOrAliasedEntry(Path file) throws IOException {
      return Files.exists(file, LinkOption.NOFOLLOW_LINKS)
          && (Files.isSymbolicLink(file) || AppDistributionSidecars.isAliasedPathEntry(file));
    }

    private static void rejectArchiveMetadataEntry(String relativePath)
        throws AppDistributionException {
      for (String segment : relativePath.split("/", -1)) {
        if (segment.equals("__MACOSX") || segment.startsWith("._")) {
          throw new AppDistributionException(
              "bundle must not contain macOS archive metadata: " + relativePath);
        }
      }
    }

    private static String normalizeRelativePath(Path bundleRoot, Path entry)
        throws AppDistributionException {
      try {
        return AppDistributionSidecars.normalizeBundleRelativePath(bundleRoot, entry);
      } catch (IllegalArgumentException exception) {
        throw new AppDistributionException("bundle contains an invalid relative path", exception);
      }
    }

    private static FileStats fileStats(Path file, String relativePath) throws IOException {
      CRC32 crc = new CRC32();
      long size = 0L;
      byte[] buffer = new byte[COPY_BUFFER_BYTES];
      try (InputStream input = Files.newInputStream(file)) {
        int bytesRead;
        while ((bytesRead = input.read(buffer)) >= 0) {
          if (bytesRead > 0) {
            crc.update(buffer, 0, bytesRead);
            size += bytesRead;
          }
        }
      }
      if (size >= ZIP64_UNSIGNED_INT_MARKER) {
        throw new AppDistributionException(
            "bundle file is too large for a ZIP32 artifact: " + relativePath);
      }
      return new FileStats(size, crc.getValue());
    }

    private static int unixMode(Path file) throws IOException {
      return UNIX_REGULAR_FILE_TYPE | DEFAULT_UNIX_FILE_PERMISSIONS | executableBits(file);
    }

    private static int executableBits(Path file) throws IOException {
      if (Files.getFileStore(file).supportsFileAttributeView("posix")) {
        return posixExecutableBits(Files.getPosixFilePermissions(file));
      }
      if (Files.isExecutable(file)) {
        return UNIX_OWNER_EXECUTE | UNIX_GROUP_EXECUTE | UNIX_OTHER_EXECUTE;
      }
      return 0;
    }

    private static int posixExecutableBits(Set<PosixFilePermission> permissions) {
      String permissionText = PosixFilePermissions.toString(permissions);
      int bits = 0;
      if (permissionText.charAt(OWNER_EXECUTE_CHAR_INDEX) == 'x') {
        bits |= UNIX_OWNER_EXECUTE;
      }
      if (permissionText.charAt(GROUP_EXECUTE_CHAR_INDEX) == 'x') {
        bits |= UNIX_GROUP_EXECUTE;
      }
      if (permissionText.charAt(OTHER_EXECUTE_CHAR_INDEX) == 'x') {
        bits |= UNIX_OTHER_EXECUTE;
      }
      return bits;
    }

    private record FileStats(long size, long crc) {}
  }
}
