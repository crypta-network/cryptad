package network.crypta.client.filter;

import network.crypta.client.filter.HTMLFilter.ParsedTag;

/**
 * Callback interface used by content filters to report parsing events and to request decisions
 * about potentially unsafe constructs such as links, forms, and individual tags.
 *
 * <p>Implementations are invoked by filter pipelines while streaming input and are expected to make
 * quick, deterministic decisions about whether a value is acceptable as-is, requires rewriting, or
 * must be rejected. Most methods return either a sanitized representation or {@code null} to
 * indicate that the construct should be removed from the output. Methods that perform validation
 * may throw {@link CommentException} with a human-readable explanation when the input cannot be
 * accepted. Callers typically handle {@code null} by eliding the construct and handle exceptions by
 * aborting or substituting a placeholder.
 *
 * <p>Typical usage is to pass an implementation to an HTML/CSS tokenizer or a media/playlist
 * filter. The filter calls into this interface whenever it encounters items that may reference
 * external resources or affect navigation. Implementations may maintain context such as a base URI
 * and user policy. All methods must be thread-safe if the filter runs concurrently, but most
 * pipelines invoke a single instance on one thread per filtering operation. Implementations should
 * avoid retaining large intermediate strings to keep memory usage bounded for large inputs.
 *
 * <ul>
 *   <li>URI processing: normalize, canonicalize, optionally absolutize, and enforce policy.
 *   <li>Form handling: decide whether a form may be emitted and where it submits.
 *   <li>Tag replacement: rewrite or drop specific HTML tags as needed.
 *   <li>Notifications: receive non-modifying events such as text runs and completion signals.
 * </ul>
 *
 * @see HTMLFilter
 */
public interface FilterCallback {

  /**
   * Processes a URI and returns a sanitized representation suitable for filtered output.
   *
   * <p>The implementation may normalize encoding, strip disallowed query parameters, or convert to
   * a relative form according to policy. If the URI cannot be made sufficiently safe for inclusion,
   * the method returns {@code null}. Implementations may also throw an exception to signal a hard
   * validation failure.
   *
   * @param uri The original URI string to evaluate and possibly rewrite. It is treated as opaque
   *     input and may be relative or absolute; never {@code null}.
   * @param overrideType Optional MIME type override to attach to the result, for example {@code
   *     "text/html; charset=UTF-8"}; {@code null} means no override.
   * @return A rewritten, policy-compliant URI string ready to emit, or {@code null} when the input
   *     must be removed from the document.
   * @throws CommentException When the URI is syntactically invalid or violates policy in a way that
   *     should abort the operation rather than eliding it.
   */
  String processURI(String uri, String overrideType) throws CommentException;

  /**
   * Processes a URI with additional controls for absolutization and prefetch intent.
   *
   * <p>In addition to the behavior of {@link #processURI(String, String)}, this variant can force
   * relative references to be converted to absolute ones and can mark a URI as inline, which allows
   * an implementation to treat it as a candidate for prefetching or more permissive policies.
   * Returning {@code null} indicates the URI should be removed.
   *
   * @param uri The URI string to evaluate. May be absolute or relative; normalization is
   *     implementation-defined and the value is not modified in-place.
   * @param overrideType Optional MIME type override to attach to the result; pass {@code null} to
   *     keep the detected or default type unchanged.
   * @param noRelative When {@code true}, convert relative references to an absolute URI using the
   *     current base; when {@code false}, a relative form may be preserved if policy allows.
   * @param inline When {@code true}, indicates the URI is referenced inline and may be prefetched
   *     or relaxed subject to policy; {@code false} applies normal handling.
   * @return A sanitized, possibly absolutized URI string safe to emit, or {@code null} if it must
   *     be removed from the output.
   * @throws CommentException If the URI is invalid or unacceptable under the current policy and
   *     filtering cannot continue safely.
   */
  String processURI(String uri, String overrideType, boolean noRelative, boolean inline)
      throws CommentException;

  /**
   * Processes a URI and enforces a specific scheme/host/port when the input is relative.
   *
   * <p>When the parsed URI does not carry an authority component, the provided {@code
   * forceSchemeHostAndPort} prefix is applied to construct an absolute reference. Implementations
   * may still reject, rewrite, or return {@code null} if the resulting URI fails validation. Inline
   * hints are treated as in the other overload.
   *
   * @param uri The candidate URI to process; may be relative and is interpreted against the given
   *     forced authority if needed; never {@code null}.
   * @param overrideType Optional MIME type override to carry into the result, or {@code null} to
   *     leave unspecified.
   * @param forceSchemeHostAndPort Authority prefix (for example, {@code "https://example.com:443"})
   *     applied only when {@code uri} lacks a host; must include scheme and, optionally, port.
   * @param inline When {@code true}, marks the URI as inline which may permit prefetch or relaxed
   *     treatment; otherwise normal policy applies.
   * @return The sanitized absolute or relative URI string, or {@code null} if the value must be
   *     dropped from the output.
   * @throws CommentException If parsing fails or the constructed URI violates policy in a
   *     non-recoverable manner.
   */
  String processURI(String uri, String overrideType, String forceSchemeHostAndPort, boolean inline)
      throws CommentException;

  /**
   * Processes a {@code <base href>} value and returns the sanitized base URI to adopt for
   * subsequent relative resolution.
   *
   * <p>Implementations typically validate the value and, if acceptable, update internal context for
   * later calls to {@link #processURI(String, String)} and related methods. Returning {@code null}
   * indicates the base is rejected and should not be emitted, leaving the previously effective base
   * unchanged.
   *
   * @param baseHref The candidate base URI string taken from the document; it may be absolute or
   *     relative and is validated according to policy.
   * @return The sanitized base URI to apply to further processing, or {@code null} if the value is
   *     unsafe and must be ignored.
   */
  String onBaseHref(String baseHref);

  /**
   * Notifies the callback of a plain-text segment encountered during filtering; this is a
   * non-modifying event.
   *
   * <p>The provided {@code s} has already been decoded by the appropriate decoder for the host
   * format (for example, the HTML entity decoder). If the text is forwarded to a browser, it must
   * be re-encoded as required for the destination context. The {@code type} parameter may identify
   * the enclosing element, such as {@code "title"}; it can be {@code null} when no specific element
   * applies.
   *
   * @param s The decoded text content as a Java string; the implementation must not assume any
   *     particular size and should avoid keeping long-lived references for large inputs.
   * @param type Optional contextual type hint such as the enclosing tag name; may be {@code null}
   *     when the source element is not known.
   */
  void onText(String s, String type);

  /**
   * Processes a form declaration and decides whether the form may be emitted and where it should
   * submit.
   *
   * <p>Implementations may restrict methods, rewrite the {@code action} destination, or block the
   * form entirely. Returning {@code null} indicates the form must be removed. The method name
   * comparison is case-insensitive in most implementations and values other than {@code GET} or
   * {@code POST} are commonly rejected.
   *
   * @param method The HTTP method specified by the form, typically {@code GET} or {@code POST};
   *     other values may be disallowed depending on policy.
   * @param action The target URI to which the form submits; may be relative and is validated and
   *     possibly rewritten.
   * @return A sanitized submit URI string to place back in the {@code action} attribute, or {@code
   *     null} to suppress the form entirely.
   * @throws CommentException If the form is invalid or violates policy in a way that should abort
   *     processing rather than silently dropping it.
   */
  String processForm(String method, String action) throws CommentException;

  /**
   * Processes an individual HTML tag and optionally returns a replacement serialization.
   *
   * <p>The callback may rewrite attributes, drop the tag entirely, or leave it unchanged. Returning
   * {@code null} signals that the tag can pass through untouched; otherwise the returned string is
   * emitted verbatim. The provided {@link ParsedTag} exposes the tag name and attributes as parsed
   * by {@link HTMLFilter}.
   *
   * @param pt The parsed tag object describing the element and attributes to evaluate; never {@code
   *     null} while filtering.
   * @return Replacement HTML to emit for the tag, or {@code null} to retain the original
   *     representation unchanged.
   */
  String processTag(ParsedTag pt);

  /**
   * Signals that the filtering run has completed and no more callbacks will be issued for the
   * current input.
   *
   * <p>Implementations may use this hook to flush per-document state, release resources, or
   * finalize metrics. The method must return quickly and must not throw.
   */
  void onFinished();
}
