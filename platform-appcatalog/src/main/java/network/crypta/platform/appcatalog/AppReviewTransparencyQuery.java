package network.crypta.platform.appcatalog;

import java.util.Objects;

/**
 * Bounded read query for the local review transparency log.
 *
 * <p>The query is the shared filtering contract for file-backed stores, in-memory stores, Platform
 * API handlers, and CLI verification helpers. It keeps reads conservative by normalizing blank
 * filters to {@code null}, clamping limits to {@link #MAX_LIMIT}, and treating invalid cursors as
 * the start of the log. Filtering is exact-match and local to the current host-owned log.
 *
 * <p>The cursor currently represents the last sequence number returned by a previous page, but
 * callers should treat it as an opaque token. Future stores may keep the same API shape while using
 * a different cursor encoding.
 *
 * @param limit requested page size before clamping to the local maximum
 * @param cursor opaque cursor from a previous page, or {@code null} for the first page
 * @param appId optional app id filter applied to record app ids
 * @param catalogId optional catalog id filter applied to record catalog ids
 * @param reviewerKeyId optional reviewer key id filter applied to record reviewer ids
 * @param kind optional event-kind filter applied to record kinds
 */
public record AppReviewTransparencyQuery(
    int limit,
    String cursor,
    String appId,
    String catalogId,
    String reviewerKeyId,
    AppReviewTransparencyEventKind kind) {
  /**
   * Default page size for operator-facing log reads.
   *
   * <p>The default keeps governance responses small enough for Web Shell and CLI display while
   * still returning enough context to explain recent review decisions.
   */
  public static final int DEFAULT_LIMIT = 25;

  /**
   * Maximum page size accepted by API and CLI callers.
   *
   * <p>Stores clamp larger values to this limit. The cap prevents a single governance request from
   * forcing an unbounded read of a local JSONL log.
   */
  public static final int MAX_LIMIT = 100;

  /**
   * Returns an unconstrained query with the default limit.
   *
   * <p>The query starts at the beginning of the local log and applies no app, catalog, reviewer, or
   * event-kind filters. Stores use this when callers pass {@code null} for a query object.
   *
   * @return default bounded query for operator-facing reads
   */
  public static AppReviewTransparencyQuery defaultQuery() {
    return new AppReviewTransparencyQuery(DEFAULT_LIMIT, null, null, null, null, null);
  }

  /**
   * Creates a normalized query.
   *
   * <p>Non-positive limits are replaced by {@link #DEFAULT_LIMIT}, larger limits are clamped to
   * {@link #MAX_LIMIT}, and blank text filters become {@code null}. Normalization happens once at
   * construction time so store implementations can apply a query without repeating validation.
   *
   * @param limit requested page size before defaulting and clamping
   * @param cursor opaque cursor token from the previous page
   * @param appId optional app id filter, blank values ignored
   * @param catalogId optional catalog id filter, blank values ignored
   * @param reviewerKeyId optional reviewer key id filter, blank values ignored
   * @param kind optional event-kind filter
   */
  public AppReviewTransparencyQuery {
    if (limit <= 0) {
      limit = DEFAULT_LIMIT;
    }
    limit = Math.min(limit, MAX_LIMIT);
    cursor = blankToNull(cursor);
    appId = blankToNull(appId);
    catalogId = blankToNull(catalogId);
    reviewerKeyId = blankToNull(reviewerKeyId);
  }

  boolean includes(AppReviewTransparencyRecord transparencyRecord) {
    Objects.requireNonNull(transparencyRecord, "transparencyRecord");
    return matchesFilter(appId, transparencyRecord.appId())
        && matchesFilter(catalogId, transparencyRecord.catalogId())
        && matchesFilter(reviewerKeyId, transparencyRecord.reviewerKeyId())
        && (kind == null || kind == transparencyRecord.kind());
  }

  long cursorSequence() {
    if (cursor == null) {
      return 0L;
    }
    try {
      return Long.parseLong(cursor);
    } catch (NumberFormatException _) {
      return 0L;
    }
  }

  private static boolean matchesFilter(String expected, String actual) {
    return expected == null || expected.equals(actual);
  }

  private static String blankToNull(String value) {
    return value == null || value.isBlank() ? null : value.trim();
  }
}
