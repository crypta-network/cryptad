package network.crypta.clients.http;

import network.crypta.support.MultiValueTable;

/**
 * Immutable bundle of HTTP reply header metadata for toadlet responses.
 *
 * <p>This record consolidates status code, reason phrase, MIME type, and optional header overrides
 * into a single value object that can be passed through reply helpers without long parameter lists.
 * It is intended for use by {@link Toadlet} convenience methods and the {@link ToadletContext}
 * header-writing APIs, keeping each call site explicit about status metadata while avoiding
 * repetition. Instances are lightweight and carry no behavior beyond holding values.
 *
 * <p>All components are treated as request-scoped data; callers typically create a new instance per
 * response and discard it after the reply is written. The record is immutable and therefore
 * thread-safe, but any {@code headers} table supplied remains mutable and should not be shared
 * between concurrent responses. No validation is performed here, so callers remain responsible for
 * supplying valid HTTP status codes and MIME types.
 *
 * <ul>
 *   <li><strong>Typical use:</strong> construct via {@link #of(int, String, String)} or an overload
 *       and pass to a {@code writeReply} helper.
 *   <li><strong>JavaScript control:</strong> set {@link #forceDisableJavascript()} only when a
 *       stricter CSP is required than the container default.
 * </ul>
 *
 * @param code HTTP status code for the response line; must be a valid numeric status.
 * @param description Reason phrase paired with {@code code}; short, human-readable, non-null.
 * @param mimeType MIME type string for the body; {@code null} when no content type applies.
 * @param headers Optional header overrides; nullable and caller-owned if provided.
 * @param forceDisableJavascript {@code true} to force a restrictive CSP for the response.
 * @see Toadlet
 * @see ToadletContext
 */
public record ReplyHeaders(
    int code,
    String description,
    String mimeType,
    MultiValueTable<String, String> headers,
    boolean forceDisableJavascript) {
  /**
   * Creates header metadata with no custom headers and JavaScript allowed.
   *
   * <p>Use this overload for the common case where the response only needs a status code, reason
   * phrase, and MIME type. The returned instance has {@code headers} set to {@code null} and does
   * not force JavaScript suppression, so container defaults apply. It performs no validation and is
   * suitable for per-request allocation.
   *
   * @param code HTTP status code for the response line; must be a valid numeric status.
   * @param description Reason phrase paired with {@code code}; short, human-readable, non-null.
   * @param mimeType MIME type string for the body; {@code null} when no content type applies.
   * @return Immutable reply metadata with no extra headers and JavaScript allowed.
   */
  public static ReplyHeaders of(int code, String description, String mimeType) {
    return new ReplyHeaders(code, description, mimeType, null, false);
  }

  /**
   * Creates header metadata with caller-supplied extra headers and default JavaScript policy.
   *
   * <p>This overload is appropriate when the response needs additional headers such as {@code
   * Content-Disposition} or redirect locations but should still honor the container's default
   * JavaScript policy. The provided {@code headers} table is stored as-is and may be mutated by the
   * caller before the response is written, so avoid sharing it across threads.
   *
   * @param code HTTP status code for the response line; must be a valid numeric status.
   * @param description Reason phrase paired with {@code code}; short, human-readable, non-null.
   * @param mimeType MIME type string for the body; {@code null} when no content type applies.
   * @param headers Additional response headers to include; nullable and caller-owned.
   * @return Immutable reply metadata, including custom headers and JavaScript allowed.
   */
  public static ReplyHeaders of(
      int code, String description, String mimeType, MultiValueTable<String, String> headers) {
    return new ReplyHeaders(code, description, mimeType, headers, false);
  }

  /**
   * Creates header metadata with custom headers and an explicit JavaScript policy override.
   *
   * <p>Use this overload when a response must explicitly disable JavaScript or when a hardened CSP
   * is required regardless of the container default. The returned instance captures all supplied
   * values without validation; callers should ensure the status code and MIME type are appropriate
   * for the response body. The {@code headers} table remains caller-owned and may be {@code null}.
   *
   * @param code HTTP status code for the response line; must be a valid numeric status.
   * @param description Reason phrase paired with {@code code}; short, human-readable, non-null.
   * @param mimeType MIME type string for the body; {@code null} when no content type applies.
   * @param headers Additional response headers to include; nullable and caller-owned.
   * @param forceDisableJavascript {@code true} to disable scripts regardless of defaults.
   * @return Immutable reply metadata with custom headers and explicit JS policy.
   */
  public static ReplyHeaders of(
      int code,
      String description,
      String mimeType,
      MultiValueTable<String, String> headers,
      boolean forceDisableJavascript) {
    return new ReplyHeaders(code, description, mimeType, headers, forceDisableJavascript);
  }
}
