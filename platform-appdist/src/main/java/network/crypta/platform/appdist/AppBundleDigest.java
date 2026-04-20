package network.crypta.platform.appdist;

import java.util.List;
import java.util.Objects;

/**
 * Immutable parsed or generated content of {@code cryptad-app.digests}.
 *
 * <p>The digest sidecar is the canonical inventory for a staged app bundle. Each entry names one
 * regular file by its normalized bundle-relative path and records the file's SHA-256 content hash,
 * plus any launchability metadata that must be authenticated for that file. The record enforces the
 * properties that make the sidecar reproducible: version {@code 1}, algorithm {@code SHA-256},
 * lexicographic path ordering, at least one entry, and mandatory coverage for {@code
 * cryptad-app.properties}.
 *
 * <p>Distribution control files are intentionally not allowed as digest entries. They are either
 * regenerated from the payload, such as {@code cryptad-app.digests}, or authenticate the generated
 * payload, such as {@code cryptad-app.signature}. Keeping that boundary explicit prevents callers
 * from accidentally signing mutable verification metadata as if it were app code or assets.
 *
 * @param version digest schema version, currently required to be {@code 1}
 * @param algorithm digest algorithm name, currently required to be {@code SHA-256}
 * @param entries deterministic bundle file digests sorted by normalized path
 */
public record AppBundleDigest(int version, String algorithm, List<AppBundleDigestEntry> entries) {
  /**
   * Canonical digest sidecar filename at the staged bundle root.
   *
   * <p>Writers replace this file when producing a fresh digest, and verifiers read this exact file
   * before comparing it with the current bundle contents.
   */
  public static final String DIGEST_FILE_NAME = "cryptad-app.digests";

  /**
   * Required app manifest filename that must be covered by every valid digest.
   *
   * <p>The manifest contains the app identity, version, and executable path, so omitting it would
   * allow launch-relevant metadata to change after signing.
   */
  public static final String MANIFEST_FILE_NAME = "cryptad-app.properties";

  /**
   * Current digest sidecar schema version.
   *
   * <p>Unsupported versions are rejected instead of interpreted leniently so future format changes
   * cannot be mistaken for this deterministic v1 layout.
   */
  public static final int DIGEST_VERSION = 1;

  /**
   * Supported content digest algorithm for bundle entries.
   *
   * <p>The text sidecar stores this algorithm name explicitly, but the implementation currently
   * accepts only SHA-256 to keep signing and verification behavior deterministic.
   */
  public static final String DIGEST_ALGORITHM = "SHA-256";

  /**
   * Creates a validated digest snapshot.
   *
   * <p>Construction performs format-level validation only. It checks ordering, required manifest
   * coverage, sidecar exclusion, and supported metadata values. It does not read files from disk or
   * verify the recorded hashes; use {@link AppBundleDigestVerifier#verify(java.nio.file.Path)} when
   * a bundle tree must be compared with an existing sidecar.
   *
   * @param version digest schema version, currently required to be {@code 1}
   * @param algorithm digest algorithm name, currently required to be {@code SHA-256}
   * @param entries deterministic bundle file digests sorted by normalized path
   * @throws IllegalArgumentException if the supplied values cannot represent a v1 digest sidecar
   */
  public AppBundleDigest {
    if (version != DIGEST_VERSION) {
      throw new IllegalArgumentException("unsupported digest.version: " + version);
    }
    if (!DIGEST_ALGORITHM.equals(Objects.requireNonNull(algorithm, "algorithm"))) {
      throw new IllegalArgumentException("unsupported digest.algorithm: " + algorithm);
    }
    entries = List.copyOf(Objects.requireNonNull(entries, "entries"));
    if (entries.isEmpty()) {
      throw new IllegalArgumentException("digest must contain at least one file entry");
    }
    validateEntries(entries);
  }

  private static void validateEntries(List<AppBundleDigestEntry> entries) {
    String previousPath = null;
    boolean manifestSeen = false;
    for (AppBundleDigestEntry entry : entries) {
      String path = entry.path();
      if (AppDistributionSidecars.isDistributionSidecar(path)) {
        throw new IllegalArgumentException("digest entries must not include distribution sidecars");
      }
      if (previousPath != null && previousPath.compareTo(path) >= 0) {
        throw new IllegalArgumentException("digest entries must be sorted lexicographically");
      }
      if (MANIFEST_FILE_NAME.equals(path)) {
        manifestSeen = true;
      }
      previousPath = path;
    }
    if (!manifestSeen) {
      throw new IllegalArgumentException(
          "digest entries must include " + AppBundleDigest.MANIFEST_FILE_NAME);
    }
  }
}
