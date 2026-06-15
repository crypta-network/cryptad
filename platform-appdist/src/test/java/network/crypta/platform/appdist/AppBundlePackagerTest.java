package network.crypta.platform.appdist;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppBundlePackagerTest {
  private static final int END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054B50;
  private static final int CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014B50;
  private static final int END_OF_CENTRAL_DIRECTORY_MIN_BYTES = 22;
  private static final int CENTRAL_DIRECTORY_HEADER_BYTES = 46;
  private static final int UNIX_HOST_PLATFORM = 3;
  private static final int UNIX_REGULAR_EXECUTABLE_MODE = 32_768 | 493;

  @TempDir Path tempDir;

  @Test
  void packageBundle_whenSignedSidecarsPresent_expectSidecarsPreserved() throws Exception {
    Path bundleRoot = createBundle("signed-bundle");
    KeyPair keyPair = generateEd25519KeyPair();
    AppBundleSigner.sign(bundleRoot, "local-dev", keyPair.getPrivate());
    byte[] digestSidecar = Files.readAllBytes(bundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME));
    byte[] signatureSidecar =
        Files.readAllBytes(bundleRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME));

    PackagedAppBundle packaged =
        AppBundlePackager.packageBundle(bundleRoot, tempDir.resolve("signed.zip"));
    Map<String, byte[]> entries = readZipEntries(packaged.artifact());

    assertArrayEquals(digestSidecar, entries.get(AppBundleDigest.DIGEST_FILE_NAME));
    assertArrayEquals(signatureSidecar, entries.get(AppBundleSignature.SIGNATURE_FILE_NAME));
    assertEquals(Files.size(packaged.artifact()), packaged.sizeBytes());
    assertEquals(sha256Hex(packaged.artifact()), packaged.artifactSha256());
    assertEquals(AppBundleDigestWriter.create(bundleRoot), packaged.bundleDigest());
  }

  @Test
  void packageBundle_whenRepeatedForSameBundle_expectDeterministicStoredZip() throws Exception {
    Path bundleRoot = createBundle("deterministic-bundle");
    Files.createDirectories(bundleRoot.resolve("assets"));
    Files.writeString(bundleRoot.resolve("z-last.txt"), "tail", StandardCharsets.UTF_8);
    Files.writeString(bundleRoot.resolve("assets/a.txt"), "asset", StandardCharsets.UTF_8);

    Path firstZip = tempDir.resolve("first.zip");
    Path secondZip = tempDir.resolve("second.zip");
    PackagedAppBundle first = AppBundlePackager.packageBundle(bundleRoot, firstZip);
    PackagedAppBundle second = AppBundlePackager.packageBundle(bundleRoot, secondZip);

    assertArrayEquals(Files.readAllBytes(firstZip), Files.readAllBytes(secondZip));
    assertEquals(first.artifactSha256(), second.artifactSha256());
    List<String> names = new ArrayList<>(readZipEntries(firstZip).keySet());
    assertEquals(
        List.of("assets/a.txt", "bin/start.sh", AppBundleDigest.MANIFEST_FILE_NAME, "z-last.txt"),
        names);
    assertFalse(names.stream().anyMatch(name -> name.contains("\\")));
    assertStoredEntries(firstZip, names);
  }

  @Test
  void packageBundle_whenBundleContainsSymlink_expectFailure() throws Exception {
    Path bundleRoot = createBundle("symlink-bundle");
    Path symlink = bundleRoot.resolve("linked.txt");
    Assumptions.assumeTrue(canCreateSymlink(symlink));
    Path target = tempDir.resolve("target.txt");
    Files.writeString(target, "linked", StandardCharsets.UTF_8);
    Files.createSymbolicLink(symlink, target);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundlePackager.packageBundle(bundleRoot, tempDir.resolve("symlink.zip")));

    assertTrue(exception.getMessage().contains("symlink"));
  }

  @Test
  void packageBundle_whenBundleContainsAppleDoubleEntry_expectFailure() throws Exception {
    Path bundleRoot = createBundle("appledouble-bundle");
    Files.writeString(
        bundleRoot.resolve("._cryptad-app.properties"), "junk", StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundlePackager.packageBundle(bundleRoot, tempDir.resolve("appledouble.zip")));

    assertTrue(exception.getMessage().contains("macOS archive metadata"));
  }

  @Test
  void packageBundle_whenBundleContainsMacosxDirectory_expectFailure() throws Exception {
    Path bundleRoot = createBundle("macosx-bundle");
    Files.createDirectories(bundleRoot.resolve("__MACOSX"));

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundlePackager.packageBundle(bundleRoot, tempDir.resolve("macosx.zip")));

    assertTrue(exception.getMessage().contains("macOS archive metadata"));
  }

  @Test
  void packageBundle_whenBundleContainsDsStoreEntry_expectFailure() throws Exception {
    Path bundleRoot = createBundle("dsstore-bundle");
    Files.writeString(bundleRoot.resolve(".DS_Store"), "junk", StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundlePackager.packageBundle(bundleRoot, tempDir.resolve("dsstore.zip")));

    assertTrue(exception.getMessage().contains("macOS archive metadata"));
  }

  @Test
  void packageBundle_whenBundleContainsNestedDsStoreEntry_expectFailure() throws Exception {
    Path bundleRoot = createBundle("nested-dsstore-bundle");
    Files.writeString(
        bundleRoot.resolve("bin").resolve(".DS_Store"), "junk", StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundlePackager.packageBundle(bundleRoot, tempDir.resolve("nested-dsstore.zip")));

    assertTrue(exception.getMessage().contains("macOS archive metadata"));
  }

  @Test
  void packageBundle_whenBundleContainsCatalogSidecar_expectFailure() throws Exception {
    Path bundleRoot = createBundle("catalog-sidecar-bundle");
    Files.writeString(bundleRoot.resolve("cryptad-app.catalog"), "catalog", StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundlePackager.packageBundle(bundleRoot, tempDir.resolve("catalog.zip")));

    assertEquals("bundle must not contain catalog sidecars", exception.getMessage());
  }

  @Test
  void packageBundle_whenOutputPathIsInsideBundle_expectFailure() throws Exception {
    Path bundleRoot = createBundle("inside-output-bundle");

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundlePackager.packageBundle(bundleRoot, bundleRoot.resolve("artifact.zip")));

    assertEquals("output ZIP must not be inside the bundle root", exception.getMessage());
  }

  @Test
  void packageBundle_whenOutputParentSymlinksIntoBundle_expectFailureWithoutCreatingParent()
      throws Exception {
    Path bundleRoot = createBundle("symlinked-output-bundle");
    Path link = tempDir.resolve("bundle-link");
    Assumptions.assumeTrue(canCreateSymlink(link));
    Files.createSymbolicLink(link, bundleRoot);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundlePackager.packageBundle(bundleRoot, link.resolve("nested/artifact.zip")));

    assertEquals("output ZIP parent must be a directory", exception.getMessage());
    assertFalse(Files.exists(bundleRoot.resolve("nested")));
  }

  @Test
  void packageBundle_whenEntryNameContainsBackslash_expectFailure() throws Exception {
    Assumptions.assumeFalse(isWindows(), "Windows treats backslash as a path separator");
    Path bundleRoot = createBundle("unsafe-relative-bundle");
    Files.writeString(bundleRoot.resolve("bad\\name.txt"), "bad", StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundlePackager.packageBundle(bundleRoot, tempDir.resolve("unsafe.zip")));

    assertTrue(exception.getMessage().contains("invalid relative path"));
  }

  @Test
  void packageBundle_whenBundleExceedsCatalogEntryCap_expectFailure() throws Exception {
    Path bundleRoot = createBundle("entry-cap-bundle");
    Path assets = bundleRoot.resolve("assets");
    Files.createDirectories(assets);
    int existingFileCount = 2;
    int extraFiles = AppBundlePackager.MAX_CATALOG_ZIP_ENTRIES - existingFileCount + 1;
    for (int index = 0; index < extraFiles; index++) {
      Files.writeString(
          assets.resolve("file-" + index + ".txt"), "asset " + index, StandardCharsets.UTF_8);
    }

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundlePackager.packageBundle(bundleRoot, tempDir.resolve("too-many.zip")));

    assertTrue(exception.getMessage().contains("too many files for a catalog ZIP artifact"));
  }

  @Test
  void packageBundle_whenOutputExists_expectArtifactOverwritten() throws Exception {
    Path bundleRoot = createBundle("overwrite-bundle");
    Path outputZip = tempDir.resolve("overwrite.zip");
    AppBundlePackager.packageBundle(bundleRoot, outputZip);
    byte[] expectedBytes = Files.readAllBytes(outputZip);
    Files.writeString(outputZip, "stale zip bytes", StandardCharsets.UTF_8);

    PackagedAppBundle overwritten = AppBundlePackager.packageBundle(bundleRoot, outputZip);

    assertArrayEquals(expectedBytes, Files.readAllBytes(outputZip));
    assertEquals(sha256Hex(outputZip), overwritten.artifactSha256());
  }

  @Test
  void packageBundle_whenPosixExecutableFilePresent_expectUnixModeInCentralDirectory()
      throws Exception {
    Assumptions.assumeTrue(
        Files.getFileStore(tempDir).supportsFileAttributeView("posix"),
        "central-directory executable mode coverage requires POSIX file attributes");
    Path bundleRoot = createPosixExecutableBundle();
    Path outputZip = tempDir.resolve("posix.zip");

    AppBundlePackager.packageBundle(bundleRoot, outputZip);

    CentralDirectoryMode mode = centralDirectoryModes(outputZip).get("bin/tool");
    assertNotNull(mode);
    assertEquals(UNIX_HOST_PLATFORM, mode.hostPlatform());
    assertEquals(UNIX_REGULAR_EXECUTABLE_MODE, mode.unixMode());
  }

  @Test
  void packageBundle_whenPosixExecutableFileIsGroupWritable_expectSafeUnixModeInCentralDirectory()
      throws Exception {
    Assumptions.assumeTrue(
        Files.getFileStore(tempDir).supportsFileAttributeView("posix"),
        "central-directory executable mode coverage requires POSIX file attributes");
    Path bundleRoot = createPosixExecutableBundle("rwxrwxrwx");
    Path outputZip = tempDir.resolve("posix-safe.zip");

    AppBundlePackager.packageBundle(bundleRoot, outputZip);

    CentralDirectoryMode mode = centralDirectoryModes(outputZip).get("bin/tool");
    assertNotNull(mode);
    assertEquals(UNIX_HOST_PLATFORM, mode.hostPlatform());
    assertEquals(UNIX_REGULAR_EXECUTABLE_MODE, mode.unixMode());
  }

  private Path createBundle(String prefix) throws IOException {
    Path bundleRoot = Files.createTempDirectory(tempDir, prefix + "-");
    Files.createDirectories(bundleRoot.resolve("bin"));
    Files.writeString(
        bundleRoot.resolve(AppBundleDigest.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=sample-app
        app.name=Sample App
        app.version=1.0.0
        app.exec=bin/start.sh
        """,
        StandardCharsets.UTF_8);
    Files.writeString(
        bundleRoot.resolve("bin/start.sh"), "#!/bin/sh\necho sample\n", StandardCharsets.UTF_8);
    return bundleRoot;
  }

  private Path createPosixExecutableBundle() throws IOException {
    return createPosixExecutableBundle("rwxr-xr-x");
  }

  private Path createPosixExecutableBundle(String permissions) throws IOException {
    Path bundleRoot = Files.createTempDirectory(tempDir, "posix-bundle-");
    Files.createDirectories(bundleRoot.resolve("bin"));
    Path executable = bundleRoot.resolve("bin/tool");
    Files.writeString(
        bundleRoot.resolve(AppBundleDigest.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=sample-app
        app.name=Sample App
        app.version=1.0.0
        app.exec=bin/tool
        """,
        StandardCharsets.UTF_8);
    Files.writeString(executable, "echo sample\n", StandardCharsets.UTF_8);
    Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString(permissions));
    return bundleRoot;
  }

  private static void assertStoredEntries(Path zipFile, List<String> names) throws IOException {
    try (ZipFile zip = new ZipFile(zipFile.toFile(), StandardCharsets.UTF_8)) {
      for (String name : names) {
        ZipEntry entry = zip.getEntry(name);
        assertNotNull(entry);
        assertEquals(ZipEntry.STORED, entry.getMethod());
      }
    }
  }

  private static Map<String, byte[]> readZipEntries(Path zipFile) throws IOException {
    Map<String, byte[]> entries = new LinkedHashMap<>();
    try (ZipInputStream zip =
        new ZipInputStream(Files.newInputStream(zipFile), StandardCharsets.UTF_8)) {
      ZipEntry entry;
      while ((entry = zip.getNextEntry()) != null) {
        entries.put(entry.getName(), zip.readAllBytes());
        zip.closeEntry();
      }
    }
    return entries;
  }

  private static Map<String, CentralDirectoryMode> centralDirectoryModes(Path zipFile)
      throws IOException {
    byte[] zipBytes = Files.readAllBytes(zipFile);
    int eocdOffset = findEndOfCentralDirectory(zipBytes);
    int entryCount = unsignedShort(zipBytes, eocdOffset + 10);
    int centralDirectoryOffset = unsignedIntAsInt(zipBytes, eocdOffset + 16);
    Map<String, CentralDirectoryMode> modes = new LinkedHashMap<>();
    int offset = centralDirectoryOffset;
    for (int entryIndex = 0; entryIndex < entryCount; entryIndex++) {
      if (intLittleEndian(zipBytes, offset) != CENTRAL_DIRECTORY_HEADER_SIGNATURE) {
        throw new IOException("central directory is malformed");
      }
      int versionMadeBy = unsignedShort(zipBytes, offset + 4);
      int hostPlatform = (versionMadeBy >>> 8) & 0xFF;
      int externalAttributes = intLittleEndian(zipBytes, offset + 38);
      int unixMode = (int) ((Integer.toUnsignedLong(externalAttributes) >>> 16) & 0xFFFFL);
      int nameLength = unsignedShort(zipBytes, offset + 28);
      int extraLength = unsignedShort(zipBytes, offset + 30);
      int commentLength = unsignedShort(zipBytes, offset + 32);
      String name =
          new String(
              zipBytes,
              offset + CENTRAL_DIRECTORY_HEADER_BYTES,
              nameLength,
              StandardCharsets.UTF_8);
      modes.put(name, new CentralDirectoryMode(hostPlatform, unixMode));
      offset += CENTRAL_DIRECTORY_HEADER_BYTES + nameLength + extraLength + commentLength;
    }
    return modes;
  }

  private static int findEndOfCentralDirectory(byte[] zipBytes) throws IOException {
    for (int offset = zipBytes.length - END_OF_CENTRAL_DIRECTORY_MIN_BYTES; offset >= 0; offset--) {
      if (intLittleEndian(zipBytes, offset) == END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
        return offset;
      }
    }
    throw new IOException("missing end-of-central-directory record");
  }

  private static int unsignedShort(byte[] bytes, int offset) {
    return (bytes[offset] & 0xFF) | ((bytes[offset + 1] & 0xFF) << 8);
  }

  private static int unsignedIntAsInt(byte[] bytes, int offset) throws IOException {
    long value = Integer.toUnsignedLong(intLittleEndian(bytes, offset));
    if (value > Integer.MAX_VALUE) {
      throw new IOException("central directory offset exceeds test parser range");
    }
    return (int) value;
  }

  private static int intLittleEndian(byte[] bytes, int offset) {
    return (bytes[offset] & 0xFF)
        | ((bytes[offset + 1] & 0xFF) << 8)
        | ((bytes[offset + 2] & 0xFF) << 16)
        | ((bytes[offset + 3] & 0xFF) << 24);
  }

  private static boolean canCreateSymlink(Path symlink) {
    try {
      Files.createSymbolicLink(symlink, Path.of("missing-target"));
      Files.deleteIfExists(symlink);
      return true;
    } catch (IOException | SecurityException | UnsupportedOperationException _) {
      return false;
    }
  }

  private static String sha256Hex(Path file) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    return AppDistributionSidecars.lowercaseHex(digest.digest(Files.readAllBytes(file)));
  }

  private static KeyPair generateEd25519KeyPair() throws Exception {
    return KeyPairGenerator.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM).generateKeyPair();
  }

  private static boolean isWindows() {
    return System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");
  }

  private record CentralDirectoryMode(int hostPlatform, int unixMode) {}
}
