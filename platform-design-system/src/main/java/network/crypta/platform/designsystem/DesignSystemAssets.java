package network.crypta.platform.designsystem;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * Accessor for canonical Crypta app UI design-system assets.
 *
 * <p>Static app bundles vendor these files under {@code static/crypta-ui/}. Keeping the files local
 * lets the same bundle run from the legacy same-origin fallback and from isolated loopback app
 * origins without allowing remote scripts, remote stylesheets, or CDN dependencies.
 *
 * <p>This class is the single source of truth for the small platform UI asset set. Scaffolding,
 * first-party app staging, UI linting, and release evidence use the same metadata so a generated
 * bundle and a reviewed bundle agree on filenames, MIME types, sizes, and SHA-256 digests. That
 * agreement matters because third-party app authors copy these resources into their own immutable
 * bundles; tooling must be able to tell a canonical local asset from a modified or missing one
 * without depending on a live node.
 *
 * <p>The copy helper is deliberately conservative around filesystem boundaries. It normalizes
 * paths, refuses symbolic links at the bundle root and destination, creates only the expected
 * bundle-relative directory tree, and replaces existing regular files with canonical bytes. Callers
 * should prefer these helpers over hard-coded resource names whenever they stage, verify, or report
 * the canonical UI files. The class is stateless and thread-safe; each call reads the current
 * classpath resources and returns immutable metadata.
 */
public final class DesignSystemAssets {
  /**
   * Bundle-relative directory used by static app UIs.
   *
   * <p>The value is stable report and manifest-adjacent vocabulary, not a host filesystem path.
   * Resolve it under a validated app bundle root before reading or writing files. The slash form is
   * intentional because bundle manifests, CLI output, and JSON lint reports need the same value on
   * Linux, macOS, and Windows.
   */
  public static final String BUNDLE_DIRECTORY = "static/crypta-ui";

  private static final String RESOURCE_DIRECTORY = "/network/crypta/platform/designsystem/static/";
  private static final List<String> BUNDLE_DIRECTORY_SEGMENTS = List.of("static", "crypta-ui");
  private static final List<AssetDefinition> DEFINITIONS =
      List.of(
          new AssetDefinition("crypta-ui-tokens.css", "text/css"),
          new AssetDefinition("crypta-ui.css", "text/css"),
          new AssetDefinition("crypta-ui-components.js", "text/javascript"));

  private DesignSystemAssets() {}

  /**
   * Lists canonical assets in deterministic bundle load order.
   *
   * <p>The returned list is recomputed from classpath resources each time, so size and digest
   * values describe the bytes shipped in the current platform build. The order matches the expected
   * static app loading sequence: tokens first, component CSS second, optional
   * progressive-enhancement JavaScript last. The list is immutable and safe to use for CLI reports,
   * tests, and linter comparisons. Callers that need resource bytes should read from {@link
   * DesignSystemAsset#resourcePath()} rather than assuming files have already been staged.
   *
   * @return immutable list of asset metadata with size and SHA-256 digest computed from the current
   *     module classpath resources
   * @throws IOException if any canonical resource cannot be opened or read from the module
   *     classpath
   */
  public static List<DesignSystemAsset> list() throws IOException {
    List<DesignSystemAsset> assets = new ArrayList<>(DEFINITIONS.size());
    for (AssetDefinition definition : DEFINITIONS) {
      byte[] bytes = readResource(definition.resourcePath());
      assets.add(
          new DesignSystemAsset(
              definition.name(),
              definition.resourcePath(),
              BUNDLE_DIRECTORY + "/" + definition.name(),
              definition.mimeType(),
              bytes.length,
              sha256Hex(bytes)));
    }
    return List.copyOf(assets);
  }

  /**
   * Copies canonical assets under {@code static/crypta-ui/} in a staged app bundle.
   *
   * <p>The copy refuses symbolic-link bundle roots, symbolic-link destination directories, and
   * symbolic-link destination files. Destination paths are normalized and checked to remain below
   * the supplied bundle root before bytes are written. Existing regular files are replaced with the
   * canonical bytes; existing non-regular files fail before any attempt to stream resource content.
   *
   * <p>This method is intended for deterministic staging tasks, not for serving request paths. It
   * creates the {@code static/crypta-ui/} directory tree one segment at a time when needed and
   * returns the same metadata that {@link #list()} reports. It does not delete extra files an app
   * may have placed elsewhere in the bundle. Callers can persist or print the returned metadata as
   * evidence that a bundle contains the exact local assets expected by UI lint and release
   * certification.
   *
   * @param bundleRoot staged app bundle root that already exists as a real, non-symbolic-link
   *     directory
   * @return immutable metadata for the copied canonical assets in deterministic load order
   * @throws IOException if the bundle root is unsafe, a destination path is unsafe, or a canonical
   *     resource cannot be read or copied
   */
  public static List<DesignSystemAsset> copyIntoBundle(Path bundleRoot) throws IOException {
    Path root = Objects.requireNonNull(bundleRoot, "bundleRoot").toAbsolutePath().normalize();
    ensureRealDirectory(root, "bundle root");
    Path designSystemDirectory = root;
    for (String segment : BUNDLE_DIRECTORY_SEGMENTS) {
      designSystemDirectory = designSystemDirectory.resolve(segment);
      createRealDirectory(designSystemDirectory);
    }
    List<DesignSystemAsset> assets = list();
    for (DesignSystemAsset asset : assets) {
      Path target = root.resolve(asset.bundlePath()).normalize();
      if (!target.startsWith(root)) {
        throw new IOException(
            "design-system asset destination escapes bundle root: " + asset.bundlePath());
      }
      requireWritableRegularFile(target);
      try (InputStream input = DesignSystemAssets.class.getResourceAsStream(asset.resourcePath())) {
        if (input == null) {
          throw new IOException("missing design-system resource: " + asset.resourcePath());
        }
        try (OutputStream output =
            Files.newOutputStream(
                target,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS)) {
          input.transferTo(output);
        }
      }
    }
    return assets;
  }

  private static void createRealDirectory(Path directory) throws IOException {
    if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
      Files.createDirectory(directory);
    }
    ensureRealDirectory(directory, "design-system asset directory");
  }

  private static void ensureRealDirectory(Path directory, String description) throws IOException {
    if (Files.isSymbolicLink(directory)) {
      throw new IOException(description + " must not be a symbolic link: " + directory);
    }
    if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException(description + " must be a directory: " + directory);
    }
  }

  private static void requireWritableRegularFile(Path target) throws IOException {
    Path parent = target.getParent();
    if (parent == null) {
      throw new IOException("design-system asset destination must have a parent: " + target);
    }
    ensureRealDirectory(parent, "design-system asset parent");
    if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    if (Files.isSymbolicLink(target)) {
      throw new IOException(
          "design-system asset destination must not be a symbolic link: " + target);
    }
    if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("design-system asset destination must be a regular file: " + target);
    }
  }

  private static byte[] readResource(String resourcePath) throws IOException {
    try (InputStream input = DesignSystemAssets.class.getResourceAsStream(resourcePath)) {
      if (input == null) {
        throw new IOException("missing design-system resource: " + resourcePath);
      }
      return input.readAllBytes();
    }
  }

  private static String sha256Hex(byte[] bytes) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return HexFormat.of().formatHex(digest.digest(bytes));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is not available", exception);
    }
  }

  private record AssetDefinition(String name, String mimeType) {
    private String resourcePath() {
      return RESOURCE_DIRECTORY + name;
    }
  }
}
