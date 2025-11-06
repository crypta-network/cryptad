package network.crypta.client.filter;

/**
 * Declares which side of the content-filtering pipeline should be applied.
 *
 * <p>This enumeration is carried through user interfaces and protocol messages to express the
 * caller's intent when running the content filter. In practice, {@code READ} triggers read-side
 * filtering that parses and sanitizes data so that it is safe to render or hand to a browser. The
 * {@code WRITE} option is reserved for write-time sanitization (for example, stripping metadata)
 * when inserting data, and {@code BOTH} indicates that both read- and write-side protections are
 * desired. Current call sites primarily execute read-side filtering; write-side handling may be
 * ignored by some components until full support is implemented.
 *
 * <p>Typical usage flows this value from a UI form or FCP message and selects the appropriate
 * filter behavior for a given MIME type. Library code should treat unknown or unsupported
 * operations conservatively by applying the strongest safe behavior available on the current code
 * path.
 *
 * <ul>
 *   <li><b>Read filtering</b>: parse, validate, and rewrite content to remove dangerous constructs
 *       before display.
 *   <li><b>Write filtering</b>: prepare data for publication by removing or normalizing potentially
 *       compromising information where supported.
 * </ul>
 *
 * @see network.crypta.client.filter.ContentFilter
 * @see network.crypta.client.filter.ContentDataFilter
 * @see network.crypta.clients.http.ContentFilterToadlet
 * @see network.crypta.clients.fcp.FilterMessage
 */
public enum FilterOperation {
  /**
   * Apply read-side filtering only.
   *
   * <p>Select this when the goal is to load and safely render content retrieved from the network or
   * disk. The filter parses input according to its MIME type and strips or rewrites constructs that
   * could cause external fetches, script execution, or other unsafe behavior. This is the most
   * commonly used operation in the codebase and is supported for a wide range of content types.
   */
  READ,

  /**
   * Apply write-side filtering only.
   *
   * <p>Intended for use during insertion or transformation of content prior to storage or
   * publication. Typical responsibilities include removing embedded metadata (for example EXIF in
   * images) or normalizing structures that may reveal environment details. Some call paths may not
   * implement write-side filtering yet and will treat this option as a no-op until support is
   * available.
   */
  WRITE,

  /**
   * Apply both read- and write-side filtering.
   *
   * <p>Use this when both ingestion-time and publication-time protections are desired. Systems that
   * only implement read-side filtering may effectively treat this as equivalent to {@link #READ}
   * for the time being. When full write-side support is present, this value ensures a comprehensive
   * pass on both sides of the content pipeline.
   */
  BOTH
}
