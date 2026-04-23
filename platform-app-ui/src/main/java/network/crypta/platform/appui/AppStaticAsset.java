package network.crypta.platform.appui;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Objects;

/**
 * Resolved static file metadata for an installed app UI response.
 *
 * <p>The record is the handoff object between the reusable resolver and whichever HTTP adapter
 * streams the response. It carries only request-time metadata: the checked filesystem path, the
 * bundle-relative identity used for diagnostics and content-type lookup, the response MIME type,
 * and the size and modification time observed during resolution. It does not hold file contents or
 * an open stream.
 *
 * <p>The resolver creates instances only after installed-root confinement and link checks have
 * passed. Adapters should still treat the path as a file that can disappear or change before it is
 * opened; install and update operations can replace bundle contents between resolution and
 * streaming. For that reason, callers should use this record as a validated snapshot, not as a
 * cache entry with long-lived freshness guarantees.
 *
 * @param path filesystem path to the installed bundle file to stream
 * @param relativePath normalized bundle-relative asset path
 * @param contentType HTTP content type derived from the asset suffix
 * @param sizeBytes current file size in bytes
 * @param lastModified current file modification timestamp for cache headers
 */
public record AppStaticAsset(
    Path path, String relativePath, String contentType, long sizeBytes, Instant lastModified) {
  /**
   * Creates an immutable asset metadata snapshot.
   *
   * <p>The constructor enforces only value-level invariants that are independent of the filesystem.
   * It assumes the resolver has already checked whether {@code path} is a regular file beneath the
   * installed bundle root. Keeping those checks outside the record avoids stale filesystem state
   * and keeps construction deterministic in tests.
   *
   * @throws NullPointerException if any required value object is {@code null}
   * @throws IllegalArgumentException if {@code relativePath} is blank or {@code sizeBytes} is
   *     negative
   */
  public AppStaticAsset {
    Objects.requireNonNull(path, "path");
    Objects.requireNonNull(relativePath, "relativePath");
    Objects.requireNonNull(contentType, "contentType");
    Objects.requireNonNull(lastModified, "lastModified");
    if (relativePath.isBlank()) {
      throw new IllegalArgumentException("relativePath must not be blank");
    }
    if (sizeBytes < 0L) {
      throw new IllegalArgumentException("sizeBytes must be >= 0");
    }
  }
}
