package network.crypta.client.filter;

import network.crypta.client.filter.HTMLFilter.ParsedTag;

/**
 * Callback interface used by the HTML filtering pipeline to inspect and optionally replace
 * individual tags during parsing.
 *
 * <p>Implementations are invoked by the HTML filter every time a tag is recognized in the input
 * stream. The callback receives a pre-parsed, immutable view of the tag and a {@link URIProcessor}
 * helper for performing safe, policy-aware transformations on attribute values that represent URIs.
 * Returning a non-{@code null} value replaces the original tag in the output with the provided
 * string; returning {@code null} keeps the tag as produced by the sanitizer.
 *
 * <p>Use this interface when you need to enforce site- or application-specific policies that go
 * beyond the default sanitizer (for example, rewriting links, whitelisting hosts, or adding
 * attributes). Implementations are typically stateless and inexpensive; they should avoid blocking
 * I/O and heavy computations because they are called for each tag as the document is streamed. The
 * filter may call a single instance from a single thread; however, implementations should be
 * written to be thread-safe or used in a thread-confined manner if shared across filtering
 * sessions.
 *
 * <ul>
 *   <li>Input is already parsed and normalized into a {@code ParsedTag}.
 *   <li>Return {@code null} to leave output unchanged for the current tag.
 *   <li>Return a string to emit a full replacement (must be syntactically valid HTML).
 * </ul>
 *
 * @see HTMLFilter
 * @see HTMLFilter.ParsedTag
 * @see URIProcessor
 */
public interface TagReplacerCallback {
  /**
   * Processes a single parsed tag and returns an optional replacement string.
   *
   * <p>The callback can examine the element name and attributes contained in {@code pt} and, when
   * necessary, consult {@code uriProcessor} to normalize, absolutize, or validate any attribute
   * values that represent URIs (for example, {@code href}, {@code src}, or {@code poster}). If the
   * method returns {@code null}, the original, sanitized tag output is preserved. If a non-null
   * string is returned, it is written verbatim to the output in place of the original tag. The
   * method should be side-effect-free and idempotent with respect to its inputs.
   *
   * <p>Edge cases: For unknown or unsupported elements, prefer returning {@code null} to defer to
   * the sanitizer. Avoid returning malformed markup; the caller does not post-process replacements.
   *
   * <pre>{@code
   * // Example: rewrite all <a> tags to use HTTPS
   * TagReplacerCallback cb = (pt, up) -> {
   *   if ("a".equalsIgnoreCase(pt.element)) {
   *     var attrs = pt.getAttributesAsMap();
   *     String href = attrs.get("href");
   *     if (href != null && href.startsWith("http://")) {
   *       return "<a href=\"" + href.replaceFirst("^http://", "https://") + "\">";
   *     }
   *   }
   *   return null; // keep original tag
   * };
   * }</pre>
   *
   * @param pt the parsed, immutable tag to inspect; contains the element name and raw attributes;
   *     never {@code null} and safe for repeated reads.
   * @param uriProcessor helper for URI-aware transformations and validation; may normalize or
   *     absolutize values; never {@code null}; do not retain references beyond the call.
   * @return a full tag replacement to emit verbatim, or {@code null} to keep the sanitizer’s
   *     original output for this tag; callers treat the returned text as final markup.
   */
  String processTag(ParsedTag pt, URIProcessor uriProcessor);
}
