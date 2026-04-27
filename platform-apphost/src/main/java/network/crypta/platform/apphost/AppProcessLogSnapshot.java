package network.crypta.platform.apphost;

import java.time.Instant;
import java.util.Objects;

/**
 * Bounded, token-redacted process-log tail for one app.
 *
 * <p>The snapshot contains log content and metadata only. It does not expose the underlying runtime
 * directory or process-log filesystem path. AppHost produces this model for operator-facing API and
 * Web Shell surfaces that need to inspect combined stdout/stderr without granting filesystem access
 * to the daemon's run directories.
 *
 * <p>The {@code text} value is display text, not trusted structured data. Runtime code redacts the
 * launch token and known AppHost paths before constructing this record, and UI callers must render
 * the text as escaped text rather than HTML. {@code maxBytes} describes the caller's requested
 * bound before implementation clamping; {@code sizeBytes} describes the full log file size when a
 * regular process log is available.
 *
 * <p>Unavailable logs are represented as stable empty snapshots with {@code available == false},
 * {@code sizeBytes == 0}, and empty text. This keeps missing files, stopped apps, and platforms
 * without a readable log from surfacing raw filesystem exceptions through the API boundary.
 *
 * @param appId stable application identifier normalized by {@link InstalledAppPaths#normalizeAppId}
 * @param available whether a process log was available as a readable regular file
 * @param truncated whether older bytes were omitted because of the requested bound
 * @param maxBytes requested maximum number of bytes before implementation clamping
 * @param sizeBytes full process-log size in bytes, or {@code 0} when unavailable
 * @param text redacted UTF-8 log tail text safe for escaped display
 * @param lastModifiedAt process-log modification time, if available from the filesystem
 */
public record AppProcessLogSnapshot(
    String appId,
    boolean available,
    boolean truncated,
    int maxBytes,
    long sizeBytes,
    String text,
    Instant lastModifiedAt) {
  /**
   * Creates a validated process-log snapshot.
   *
   * <p>The constructor performs value checks shared by AppHost runtime code and tests. It
   * normalizes the app id, requires a positive requested byte bound, rejects negative file sizes,
   * and requires a non-null text value. It does not perform redaction itself; callers must pass
   * text that has already gone through {@link AppHostTokenRedactor} when the snapshot leaves
   * internal runtime code.
   *
   * @param appId stable application identifier accepted by AppHost path normalization
   * @param available whether a process log was available as a readable regular file
   * @param truncated whether older bytes were omitted because of the requested bound
   * @param maxBytes requested maximum number of bytes before implementation clamping
   * @param sizeBytes full process-log size in bytes, or {@code 0} when unavailable
   * @param text redacted UTF-8 log tail text, never {@code null}
   * @param lastModifiedAt process-log modification time, if available from the filesystem
   */
  public AppProcessLogSnapshot {
    appId = InstalledAppPaths.normalizeAppId(appId);
    if (maxBytes <= 0) {
      throw new IllegalArgumentException("maxBytes must be positive");
    }
    if (sizeBytes < 0L) {
      throw new IllegalArgumentException("sizeBytes must be non-negative");
    }
    Objects.requireNonNull(text, "text");
  }
}
