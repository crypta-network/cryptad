package network.crypta.client.filter;

import java.net.URISyntaxException;

/**
 * Strategy interface for safe, policy-aware URI processing used by the filtering pipeline.
 *
 * <p>Implementations take raw URI strings found in user-supplied or untrusted documents and
 * transform them into forms that are safe to emit in filtered output. Typical operations include
 * normalization, canonicalization, optional absolutization against a base, and enforcement of
 * policy (for example, allowed schemes or host restrictions). When a value cannot be made
 * sufficiently safe, methods return {@code null} to indicate that the reference should be removed
 * from the resulting document. Some operations may signal unrecoverable validation problems via a
 * {@link CommentException} with a human-readable explanation.
 *
 * <p>This interface is used by higher-level callbacks such as {@link TagReplacerCallback} and
 * {@link FilterCallback} during streaming sanitization. Implementations are generally stateless or
 * hold only small amounts of context (for example, a base URI). Concurrency requirements are
 * caller-defined; most filters invoke a single instance from one thread per document, but
 * implementations should avoid global mutable state and be safe to reuse across runs.
 *
 * <ul>
 *   <li>Normalize and sanitize URI strings prior to emission.
 *   <li>Optionally absolutize relative references using an implementation-defined base.
 *   <li>Enforce policy; return {@code null} when a value must be elided.
 * </ul>
 *
 * @see FilterCallback
 * @see TagReplacerCallback
 */
public interface URIProcessor {

  /**
   * Processes a URI string and returns a sanitized representation suitable for filtered output.
   *
   * <p>The implementation may normalize encoding, strip or rewrite disallowed components, and, when
   * requested, convert relative references to absolute ones. The {@code inline} flag allows
   * implementations to apply context-specific handling (for example, when the URI is referenced
   * from an inline attribute). Returning {@code null} indicates that the value is unsafe and should
   * be removed rather than emitted.
   *
   * <pre>{@code
   * // Example: evaluate a candidate URI for inclusion
   * String safe = uriProcessor.processURI(raw, null, /* noRelative= * / false, /* inline= * / true);
   * if (safe != null) {
   *   // emit or store the sanitized value
   * }
   * }</pre>
   *
   * @param u the original URI string to evaluate; may be absolute or relative and is treated as
   *     opaque input; never modified in place.
   * @param overrideType optional MIME type hint to associate with the processed value; may be
   *     {@code null}; implementations may ignore it when not applicable.
   * @param noRelative when {@code true}, convert relative references to absolute form using the
   *     current base; when {@code false}, a relative form may be preserved if policy allows.
   * @param inline when {@code true}, indicates the URI appears in an inline context and may be
   *     handled with context-specific rules; {@code false} applies normal processing.
   * @return a sanitized URI string that is safe to emit, possibly rewritten and/or absolutized; or
   *     {@code null} if the input cannot be made acceptable under policy and must be removed.
   * @throws CommentException if parsing fails, policy validation cannot be satisfied, or the value
   *     must cause the operation to abort instead of eliding it silently.
   */
  String processURI(String u, String overrideType, boolean noRelative, boolean inline)
      throws CommentException;

  /**
   * Makes a URI absolute with respect to the implementation's notion of base resolution.
   *
   * <p>The provided {@code uri} may be absolute already or may be a relative reference. The
   * returned value is an ASCII string form suitable for use in serialized output. Implementations
   * apply the same pre-encoding and normalization rules they use for general processing. This
   * method does not perform policy checks and does not alter behavior beyond resolution; callers
   * should still invoke {@link #processURI(String, String, boolean, boolean)} when validation is
   * required.
   *
   * @param uri the input URI string to resolve; may be absolute or relative; must be syntactically
   *     valid according to {@link java.net.URI} when combined with the base.
   * @return the absolute, normalized ASCII URI string computed from {@code uri} and the base
   *     context held by the implementation; never {@code null}.
   * @throws URISyntaxException if the URI is malformed or cannot be resolved against the current
   *     base due to invalid syntax.
   */
  String makeURIAbsolute(String uri) throws URISyntaxException;
}
