package network.crypta.platform.appcatalog;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One bounded page of local review transparency records.
 *
 * <p>Pages are the read model returned by the transparency store and Platform API. They contain
 * already-redacted records and a cursor for continuing from the last record returned by a matching
 * query. The cursor is intentionally an opaque string to API callers even though the current store
 * uses record sequence numbers internally.
 *
 * <p>The record list is defensively copied on construction, so callers can safely retain a page
 * without being affected by later appends. A {@code null} cursor means there are no more matching
 * records known to this local store at the time of the read.
 *
 * @param records redacted records included in this bounded page
 * @param nextCursor cursor to pass to the next query, or {@code null} at the end
 */
public record AppReviewTransparencyPage(
    List<AppReviewTransparencyRecord> records, String nextCursor) {
  /**
   * Creates an immutable page.
   *
   * <p>The constructor copies the incoming records and preserves their order. Stores are expected
   * to supply records in ascending sequence order after applying cursor and filter constraints.
   *
   * @param records records selected by the bounded query
   * @param nextCursor cursor for the next page, or {@code null} when complete
   */
  public AppReviewTransparencyPage {
    records = List.copyOf(records);
  }

  /**
   * Converts this page to JSON-compatible values.
   *
   * <p>The returned map is safe for operator-facing API output. It delegates record conversion to
   * {@link AppReviewTransparencyRecord#toJsonValue()} and does not include store paths, raw key
   * material, private keys, or local process state.
   *
   * @return JSON-compatible page with {@code records} and {@code nextCursor}
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("records", records.stream().map(AppReviewTransparencyRecord::toJsonValue).toList());
    json.put("nextCursor", nextCursor);
    return json;
  }
}
