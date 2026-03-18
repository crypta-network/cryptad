package network.crypta.runtime.spi;

import java.io.File;

/**
 * Detached request data for creating one new persistent queue download.
 *
 * <p>The record carries only the small set of values the legacy queue-download adapter needs to
 * recreate the existing persistent-download call. The HTTP layer owns all user-input parsings and
 * validation; this DTO simply preserves the chosen fetch URI string, filter flag, persistence mode,
 * return mode, and optional disk target directory.
 *
 * <p>The record is deliberately transport-like rather than behavior-rich. It does not normalize
 * legacy strings, create directories, or validate that a URI can be fetched. Callers should treat
 * instances as immutable request snapshots that are ready to hand to {@link QueueDownloadPort}
 * after the user-facing layer has finished all parsing and policy checks.
 *
 * @param fetchUri fetch URI string supplied by the caller; already validated by the HTTP layer in
 *     normal flows
 * @param filterData whether fetched data should be filtered before delivery
 * @param expectedMimeType optional MIME hint for download naming; may be {@code null}
 * @param persistenceType legacy persistence mode string such as {@code forever}
 * @param returnType legacy return mode string such as {@code disk} or {@code direct}
 * @param downloadsDir target directory for disk-backed downloads; {@code null} for direct-return
 *     requests
 */
public record QueueDownloadRequest(
    String fetchUri,
    boolean filterData,
    String expectedMimeType,
    String persistenceType,
    String returnType,
    File downloadsDir) {}
