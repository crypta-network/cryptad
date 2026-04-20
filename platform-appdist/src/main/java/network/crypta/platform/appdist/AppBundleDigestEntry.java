package network.crypta.platform.appdist;

import java.util.regex.Pattern;

/**
 * One deterministic file digest entry inside {@code cryptad-app.digests}.
 *
 * <p>Entries use the same normalized path rules as the rest of the distribution sidecar format:
 * paths are relative to the bundle root, use {@code /} separators, and cannot contain traversal or
 * empty segments. The content hash is always lowercase hexadecimal SHA-256 of the exact file bytes
 * observed while generating or verifying the sidecar.
 *
 * <p>The optional {@code executable} field is deliberately nullable. A missing value means the file
 * has no authenticated executable-bit state, which keeps cross-platform signatures stable for
 * scripts and Windows launchers. A present value is used only when the declared {@code app.exec}
 * target is launchable because of POSIX executable permissions, so changing that permission after
 * signing invalidates the digest.
 *
 * @param path normalized relative bundle path using {@code /} separators
 * @param sha256 lowercase hexadecimal SHA-256 of the file bytes
 * @param executable authenticated POSIX executable-bit state for {@code app.exec}, or {@code null}
 *     when no permission metadata is part of the signed payload
 */
public record AppBundleDigestEntry(String path, String sha256, Boolean executable) {
  private static final Pattern SHA_256_HEX_PATTERN = Pattern.compile("[0-9a-f]{64}");

  /**
   * Creates a validated digest entry.
   *
   * <p>The constructor normalizes the supplied path and rejects malformed hash text. It does not
   * inspect the file system; callers are responsible for deciding whether executable-bit metadata
   * is applicable before constructing the entry.
   *
   * @param path normalized relative bundle path using {@code /} separators
   * @param sha256 lowercase hexadecimal SHA-256 of the file bytes
   * @param executable authenticated POSIX executable-bit state for {@code app.exec}, or {@code
   *     null} when no permission metadata is part of the signed payload
   * @throws IllegalArgumentException if the path or hash cannot be encoded in the sidecar format
   */
  public AppBundleDigestEntry {
    path = AppDistributionSidecars.normalizeBundleRelativePath(path, "digest path");
    sha256 = normalizeSha256(sha256);
  }

  /**
   * Creates a digest entry without authenticated executable metadata.
   *
   * <p>This overload is appropriate for ordinary payload files, manifest files, and launcher types
   * whose launchability does not depend on POSIX execute bits.
   *
   * @param path normalized relative bundle path using {@code /} separators
   * @param sha256 lowercase hexadecimal SHA-256 of the file bytes
   * @throws IllegalArgumentException if the path or hash cannot be encoded in the sidecar format
   */
  @SuppressWarnings("unused")
  public AppBundleDigestEntry(String path, String sha256) {
    this(path, sha256, null);
  }

  private static String normalizeSha256(String sha256) {
    String normalized = AppDistributionSidecars.requireNonBlankSingleLine(sha256, "sha256");
    if (!SHA_256_HEX_PATTERN.matcher(normalized).matches()) {
      throw new IllegalArgumentException("sha256 must be 64 lowercase hex characters");
    }
    return normalized;
  }
}
