package network.crypta.platform.appdist;

import java.nio.file.Path;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Immutable result of packaging a staged app bundle as a ZIP artifact.
 *
 * <p>The result records both the validated source bundle and the artifact written by {@link
 * AppBundlePackager}. The digest is the appdist payload digest produced during pre-package
 * validation; it excludes distribution sidecars by design because signed-bundle metadata is not
 * part of the application payload digest. The artifact hash covers the exact ZIP bytes after
 * deterministic entry metadata and central-directory mode attributes have been written.
 *
 * <p>Catalog authoring should use {@link #artifact()}, {@link #sizeBytes()}, and {@link
 * #artifactSha256()} when publishing a bundle ZIP. Diagnostic output can also show {@link
 * #bundleDigest()} to explain which staged payload was packaged. The paths are normalized on
 * construction, and the result is safe to share between CLI layers without exposing mutable state.
 *
 * @param bundleRoot absolute normalized source bundle root that was packaged
 * @param artifact absolute normalized ZIP artifact path that was written
 * @param bundleDigest deterministic app payload digest observed before packaging
 * @param sizeBytes final artifact size in bytes, never negative
 * @param artifactSha256 lowercase SHA-256 hash of the final artifact bytes
 */
public record PackagedAppBundle(
    Path bundleRoot,
    Path artifact,
    AppBundleDigest bundleDigest,
    long sizeBytes,
    String artifactSha256) {
  private static final Pattern SHA_256_HEX_PATTERN = Pattern.compile("[0-9a-f]{64}");

  /**
   * Creates a validated packaging result.
   *
   * <p>The constructor normalizes both paths, rejects negative artifact sizes, and requires the
   * artifact digest to be exactly 64 lowercase hexadecimal characters. It does not check that the
   * paths still exist; callers should treat the result as a snapshot of the package operation that
   * just completed.
   *
   * @param bundleRoot source bundle root that was validated and packaged
   * @param artifact ZIP artifact path that was created or replaced
   * @param bundleDigest deterministic app payload digest observed before packaging
   * @param sizeBytes final artifact size in bytes, never negative
   * @param artifactSha256 lowercase SHA-256 hash of the final artifact bytes
   */
  public PackagedAppBundle {
    bundleRoot = Objects.requireNonNull(bundleRoot, "bundleRoot").toAbsolutePath().normalize();
    artifact = Objects.requireNonNull(artifact, "artifact").toAbsolutePath().normalize();
    Objects.requireNonNull(bundleDigest, "bundleDigest");
    if (sizeBytes < 0) {
      throw new IllegalArgumentException("sizeBytes must not be negative");
    }
    artifactSha256 =
        AppDistributionSidecars.requireNonBlankSingleLine(artifactSha256, "artifactSha256");
    if (!SHA_256_HEX_PATTERN.matcher(artifactSha256).matches()) {
      throw new IllegalArgumentException("artifactSha256 must be 64 lowercase hex characters");
    }
  }
}
