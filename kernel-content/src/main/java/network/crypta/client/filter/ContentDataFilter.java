package network.crypta.client.filter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

/**
 * Contract for filtering bytes belonging to a specific MIME type.
 *
 * <p>This interface defines the read-side filtering operation that turns a potentially unsafe or
 * malformed data stream into a sanitized representation that is safe to forward to user agents (for
 * example, web browsers) and clients. Implementations are expected to validate structure and
 * content for the targeted media type and either emit a safe, possibly reduced, version of the
 * input or fail fast if the data cannot be made safe. A positive, parsing-based approach (often
 * called a whitelist strategy) is strongly preferred over attempting to strip known bad constructs.
 *
 * <p>The filtering operation is designed for streaming: the {@code InputStream} may be a {@code
 * java.io.PipedInputStream} or a network-backed stream. Implementations must not assume that {@code
 * input.available() == 0} implies the end of stream. They should also avoid unbounded buffering and
 * should propagate I/O failures promptly while keeping partially produced output in a consistent
 * state. Implementations are generally stateless and reusable; if the state is kept per invocation,
 * prefer creating a fresh instance and avoid sharing mutable state across threads.
 *
 * <ul>
 *   <li>Validates structure for the declared MIME type.
 *   <li>Removes or normalizes unsafe or ambiguous constructs.
 *   <li>May infer or adjust the character set when applicable.
 *   <li>Operates in a streaming fashion without relying on {@code available()}.
 * </ul>
 *
 * @see network.crypta.client.filter.ContentFilter
 * @see network.crypta.client.filter.FilterCallback
 */
public interface ContentDataFilter {

  /**
   * Filters a possibly untrusted stream for safe reading and type conformance.
   *
   * <p>The implementation must parse the input according to the target MIME type, write a safe
   * representation to {@code output}, and reject data that cannot be validated or sanitized. The
   * method is streaming-friendly: callers may provide a {@code PipedInputStream} or a network
   * stream, and implementations must not use {@code available()} as an end-of-stream signal. When
   * character encodings apply, the filter may honor the provided {@code charset}, infer a more
   * specific value, or leave it unchanged if the type is binary. Implementations may throw an
   * {@code IOException} for read/write failures; for validation failures, they typically use {@link
   * DataFilterException}, which is a subtype of {@link java.io.IOException}.
   *
   * <p>Typical usage writes the sanitized result to a buffer or a downstream response object while
   * providing a best-effort set of type parameters and the node's externally visible endpoint. A
   * {@link FilterCallback} can be supplied to influence how individual constructs are treated (for
   * example, when filtering HTML tags). The callback may be {@code null} for media types that do
   * not support such adjustments.
   *
   * <pre>{@code
   * // Example: invoke a filter with optional parameters and no callback
   * filter.readFilter(input, output, charset, Map.of(), schemeHostAndPort, null);
   * }</pre>
   *
   * @param input the source of potentially unsafe bytes to validate and sanitize; may be networking
   *     or pipe backed and must be read in a streaming manner without relying on {@code
   *     available()}.
   * @param output the destination for safe output; implementations should flush as appropriate and
   *     avoid writing malformed or partially validated constructs when rejection is certain.
   * @param charset the declared or inferred character set for text-based media; may be {@code null}
   *     or empty for binary types where character encoding is irrelevant to filtering.
   * @param otherParams additional parameters from the media type (for example, {@code boundary} for
   *     multipart) or an empty map when none are present; implementations must tolerate missing
   *     entries.
   * @param schemeHostAndPort the externally visible scheme, host, and port for the node (for
   *     example, {@code http://example:7777}); may be {@code null} when the information is unknown.
   *     Filters should use it only when embedding or validating absolute references.
   * @param cb optional callback for structure-specific decisions (such as HTML tag handling);
   *     implementations must check for {@code null} and proceed with default behavior when absent.
   * @throws IOException if an I/O failure occurs while reading the input or writing the output; the
   *     exception may be a {@link DataFilterException} when validation fails and no safe output can
   *     be produced.
   */
  void readFilter(
      InputStream input,
      OutputStream output,
      String charset,
      Map<String, String> otherParams,
      String schemeHostAndPort,
      FilterCallback cb)
      throws IOException;
}
