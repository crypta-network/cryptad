package network.crypta.platform.appui;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.Optional;

/**
 * Resolves app-owned static UI paths beneath an installed bundle root.
 *
 * <p>The resolver is the final filesystem boundary before an HTTP adapter opens an installed app
 * asset. Manifest parsing proves that static UI entries are relative and syntactically safe, and
 * route parsing rejects traversal in request paths. This class checks the properties that only the
 * installed filesystem can answer: the normalized candidate must stay beneath the installed root,
 * each visited segment must avoid symbolic links and filesystem aliases, and the served target must
 * be a regular file.
 *
 * <p>Instances are stateless and safe to reuse. Each call reads metadata from the current
 * filesystem and returns a short-lived {@link AppStaticAsset} snapshot. Missing files and
 * directories are not exceptional because they map naturally to HTTP 404 responses. Escapes and
 * aliasing are exceptional because they indicate an unsafe request or a corrupted installed bundle.
 */
public final class AppStaticAssetResolver {
  /**
   * Creates a resolver with no retained filesystem state.
   *
   * <p>The resolver does not cache real paths, file attributes, or content-type decisions. Reusing
   * one instance across requests is equivalent to constructing a new instance for each request.
   */
  public AppStaticAssetResolver() {
    // This resolver is stateless; all filesystem metadata is read during each resolve call.
  }

  /**
   * Resolves one normalized bundle-relative static asset path.
   *
   * <p>The method accepts only paths that the manifest or route layer has already normalized to
   * bundle-relative text. It still normalizes the resolved candidate and checks every filesystem
   * segment with {@link LinkOption#NOFOLLOW_LINKS}. If the candidate is absent or resolves to a
   * directory, the method returns empty so adapters can report an ordinary not-found response.
   *
   * @param installedRoot immutable installed bundle root for the app being served
   * @param relativePath normalized bundle-relative path from the manifest or parsed request route
   * @return resolved asset metadata, or empty when the target is absent or not a regular file
   * @throws IOException if filesystem metadata or real-path checks cannot be read safely
   * @throws AppStaticAssetException if the path escapes the installed root or traverses a link
   */
  public Optional<AppStaticAsset> resolve(Path installedRoot, String relativePath)
      throws IOException, AppStaticAssetException {
    Path root = installedRoot.toAbsolutePath().normalize();
    Path candidate = root.resolve(relativePath).normalize();
    if (!candidate.startsWith(root)) {
      throw new AppStaticAssetException(400, "App UI asset path is unsafe.");
    }
    if (!Files.exists(candidate, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    validatePathDoesNotAlias(root, candidate);
    if (!Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    BasicFileAttributes attributes =
        Files.readAttributes(candidate, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    Instant lastModified = attributes.lastModifiedTime().toInstant();
    return Optional.of(
        new AppStaticAsset(
            candidate,
            relativePath,
            AppUiContentTypes.forPath(relativePath),
            attributes.size(),
            lastModified));
  }

  private static void validatePathDoesNotAlias(Path root, Path candidate)
      throws IOException, AppStaticAssetException {
    if (Files.isSymbolicLink(root)) {
      throw new AppStaticAssetException(400, "App UI asset path is unsafe.");
    }
    Path realRoot = root.toRealPath(LinkOption.NOFOLLOW_LINKS);
    Path current = root;
    Path relative = root.relativize(candidate);
    for (Path segment : relative) {
      current = current.resolve(segment);
      if (Files.isSymbolicLink(current)) {
        throw new AppStaticAssetException(400, "App UI asset path is unsafe.");
      }
      Path expectedRealPath = realRoot.resolve(root.relativize(current)).normalize();
      Path actualRealPath = current.toRealPath();
      if (!actualRealPath.equals(expectedRealPath)) {
        throw new AppStaticAssetException(400, "App UI asset path is unsafe.");
      }
    }
  }
}
