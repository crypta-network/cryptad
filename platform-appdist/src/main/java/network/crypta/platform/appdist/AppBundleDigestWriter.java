package network.crypta.platform.appdist;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.jetbrains.annotations.NotNull;

/**
 * Creates and writes deterministic {@code cryptad-app.digests} sidecars.
 *
 * <p>The writer is the canonical producer for bundle digests used by signing, verification, and
 * local build tooling. It validates the bundle structure first, walks only the caller-supplied
 * bundle directory, rejects symbolic links and aliased directory entries, hashes regular files, and
 * serializes entries in lexicographic path order. The generated sidecar is UTF-8 text so operators
 * can inspect it, but callers should treat {@link AppBundleDigest} as the authoritative parsed
 * representation.
 *
 * <p>Distribution sidecars are excluded from the digest input. The app manifest remains included
 * because it controls app identity and launch behavior. File hashes are streamed through a fixed
 * buffer instead of materializing whole files in memory, which keeps signing and install-time
 * verification reliable for bundles with large local assets.
 */
public final class AppBundleDigestWriter {
  private static final int DIGEST_BUFFER_BYTES = 64 * 1024;
  private static final String FILE_PROPERTY_PREFIX = "file.";

  private AppBundleDigestWriter() {}

  /**
   * Computes a digest snapshot for the current bundle contents.
   *
   * <p>The method performs all structural validation needed before signing: the bundle root must be
   * a directory, the manifest must be valid, {@code app.exec} must resolve to a launchable file,
   * and every walked entry must remain inside the real bundle root. Sidecars such as {@code
   * cryptad-app.digests} and {@code cryptad-app.signature} are skipped so repeated signing produces
   * the same digest for the same payload.
   *
   * @param bundleRoot staged app bundle root directory to inspect without following unsafe links
   * @return deterministic digest snapshot for the current bundle payload
   * @throws IOException if the bundle cannot be read safely or the digest cannot be computed
   */
  public static AppBundleDigest create(Path bundleRoot) throws IOException {
    Path normalizedBundleRoot = AppDistributionSidecars.requireBundleRoot(bundleRoot);
    Path bundleRealRoot = normalizedBundleRoot.toRealPath();
    AppBundleStructureValidator.ValidatedBundle validatedBundle =
        AppBundleStructureValidator.validate(normalizedBundleRoot);
    DigestInventory inventory =
        collectDigestInventory(normalizedBundleRoot, bundleRealRoot, validatedBundle);
    return createDigest(inventory);
  }

  private static DigestInventory collectDigestInventory(
      Path normalizedBundleRoot,
      Path bundleRealRoot,
      AppBundleStructureValidator.ValidatedBundle validatedBundle)
      throws IOException {
    DigestInventory inventory = new DigestInventory();
    Files.walkFileTree(
        normalizedBundleRoot,
        new DigestFileVisitor(normalizedBundleRoot, bundleRealRoot, validatedBundle, inventory));
    return inventory;
  }

  private static AppBundleDigest createDigest(DigestInventory inventory)
      throws AppDistributionException {
    List<AppBundleDigestEntry> entries = new ArrayList<>(inventory.shaByPath().size());
    try {
      for (Map.Entry<String, String> entry : inventory.shaByPath().entrySet()) {
        entries.add(
            new AppBundleDigestEntry(
                entry.getKey(),
                entry.getValue(),
                inventory.executableByPath().get(entry.getKey())));
      }
      return new AppBundleDigest(
          AppBundleDigest.DIGEST_VERSION, AppBundleDigest.DIGEST_ALGORITHM, entries);
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException(exception.getMessage(), exception);
    }
  }

  /**
   * Writes a canonical digest sidecar for the bundle.
   *
   * <p>The sidecar is regenerated from the current bundle contents and atomically replaces the text
   * content of {@code cryptad-app.digests}. Callers that sign a bundle should use the returned
   * digest only as a snapshot; the signature itself is computed over the exact sidecar bytes
   * written by {@link AppBundleSigner}.
   *
   * @param bundleRoot staged app bundle root directory where the sidecar should be written
   * @return digest snapshot that was written to disk
   * @throws IOException if the bundle cannot be read safely or the sidecar cannot be written
   */
  public static AppBundleDigest write(Path bundleRoot) throws IOException {
    Path normalizedBundleRoot = AppDistributionSidecars.requireBundleRoot(bundleRoot);
    AppBundleDigest digest = create(normalizedBundleRoot);
    AppDistributionSidecars.writeUtf8File(
        normalizedBundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME), serialize(digest));
    return digest;
  }

  static String serialize(AppBundleDigest digest) {
    StringBuilder builder = new StringBuilder();
    builder
        .append("digest.version=")
        .append(digest.version())
        .append('\n')
        .append("digest.algorithm=")
        .append(digest.algorithm())
        .append('\n');
    List<AppBundleDigestEntry> entries =
        digest.entries().stream().sorted(Comparator.comparing(AppBundleDigestEntry::path)).toList();
    for (int index = 0; index < entries.size(); index++) {
      AppBundleDigestEntry entry = entries.get(index);
      builder
          .append(FILE_PROPERTY_PREFIX)
          .append(index)
          .append(".path=")
          .append(entry.path())
          .append('\n')
          .append(FILE_PROPERTY_PREFIX)
          .append(index)
          .append(".sha256=")
          .append(entry.sha256())
          .append('\n');
      if (entry.executable() != null) {
        builder
            .append(FILE_PROPERTY_PREFIX)
            .append(index)
            .append(".executable=")
            .append(entry.executable())
            .append('\n');
      }
    }
    return builder.toString();
  }

  private record DigestInventory(
      Map<String, String> shaByPath, Map<String, Boolean> executableByPath) {
    private DigestInventory() {
      this(new TreeMap<>(), new TreeMap<>());
    }
  }

  private static final class DigestFileVisitor extends SimpleFileVisitor<Path> {
    private final Path normalizedBundleRoot;
    private final Path bundleRealRoot;
    private final AppBundleStructureValidator.ValidatedBundle validatedBundle;
    private final DigestInventory inventory;
    private final Set<Path> visitedRealDirectories = new HashSet<>();

    private DigestFileVisitor(
        Path normalizedBundleRoot,
        Path bundleRealRoot,
        AppBundleStructureValidator.ValidatedBundle validatedBundle,
        DigestInventory inventory) {
      this.normalizedBundleRoot = normalizedBundleRoot;
      this.bundleRealRoot = bundleRealRoot;
      this.validatedBundle = validatedBundle;
      this.inventory = inventory;
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
      return FileVisitResult.CONTINUE;
    }

    @Override
    public @NotNull FileVisitResult visitFile(
        @NotNull Path file, @NotNull BasicFileAttributes attributes) throws IOException {
      AppDistributionSidecars.validateBundleEntry(normalizedBundleRoot, bundleRealRoot, file);
      if (!attributes.isRegularFile()) {
        throw new AppDistributionException("bundle must contain regular files only");
      }
      String relativePath = normalizeRelativePath(file);
      if (AppDistributionSidecars.isDistributionSidecar(relativePath)) {
        return FileVisitResult.CONTINUE;
      }
      inventory.shaByPath().put(relativePath, sha256Hex(file));
      recordExecutableMode(relativePath);
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

    private String normalizeRelativePath(Path file) throws AppDistributionException {
      try {
        return AppDistributionSidecars.normalizeBundleRelativePath(normalizedBundleRoot, file);
      } catch (IllegalArgumentException exception) {
        throw new AppDistributionException("bundle contains an invalid relative path", exception);
      }
    }

    private void recordExecutableMode(String relativePath) {
      if (relativePath.equals(validatedBundle.manifest().execPathText())) {
        inventory
            .executableByPath()
            .put(relativePath, validatedBundle.authenticatedExecutableBit());
      }
    }

    private static String sha256Hex(Path file) throws IOException {
      MessageDigest digest = AppDistributionSidecars.newSha256Digest();
      byte[] buffer = new byte[DIGEST_BUFFER_BYTES];
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

    private static boolean isLinkOrAliasedEntry(Path file) throws IOException {
      return Files.exists(file, LinkOption.NOFOLLOW_LINKS)
          && (Files.isSymbolicLink(file) || AppDistributionSidecars.isAliasedPathEntry(file));
    }
  }
}
