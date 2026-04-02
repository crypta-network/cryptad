/**
 * Client content filtering for safely rendering data fetched through Crypta.
 *
 * <p>This package provides filtering utilities that can be invoked during a download pipeline
 * (commonly by the HTTP gateway) to classify and transform fetched data into a browser‑safe form.
 * The filters aim to identify "safe" content and either remove, neutralize, or warn about parts we
 * do not understand or cannot be made safe at the time of processing. The core approach is
 * whitelisting: parse the input, permit only recognized constructs, and drop or sanitize the rest.
 * This is more robust than attempting to detect specific exploits or blocking by pattern.
 *
 * <p>"Dangerous" here primarily refers to content (for example, HTML) that could trigger requests
 * to the non‑anonymous web (so‑called web bugs), or enable browser behaviors such as active
 * scripting that deanonymize users or leak information. The filters therefore focus on HTML and CSS
 * sanitization, but the same principles apply to other MIME types that can carry active content or
 * metadata with privacy impact.
 *
 * <p>A registry maps known MIME types to dedicated filters or to user‑visible warnings when the
 * content type is recognized but cannot be safely processed. The filtering pipeline is intended to
 * be used in a streaming fashion to keep memory usage predictable for large files; callers should
 * prefer passing streams rather than fully buffering responses. When no filter is available, a
 * conservative pass‑through may be used and a warning surfaced to the client.
 *
 * <p>Write filtering is also supported: potentially identifying data such as image EXIF metadata
 * can be stripped at insert time to reduce the risk of accidental disclosure. In addition, the HTML
 * path supports transformation hooks (for example, a tag‑replacement callback used to inject
 * placeholders while content is still loading). Such callbacks are implementation details and must
 * not assume browser‑specific behaviors; they should operate on already‑parsed elements rather than
 * raw text.
 *
 * <p>Concurrency and threading: Implementations are typically stateless or only keep per‑request
 * state; they should be reusable across requests when documented as thread‑safe. Callers should
 * confine any mutable filter instance to a single request context and avoid sharing it across
 * threads unless explicitly safe to do so.
 *
 * <ul>
 *   <li><b>Responsibilities</b>: identify safe constructs, sanitize or drop unsafe parts, surface
 *       clear warnings for partially filtered content.
 *   <li><b>Typical use</b>: select a filter by MIME type, stream the response through it, and
 *       forward the result to the browser or storage.
 *   <li><b>Design</b>: default‑deny (whitelist) parsing; favor deterministic, streaming
 *       transformations over best‑effort pattern matching.
 * </ul>
 *
 * <p>Example (conceptual):
 *
 * <pre>{@code
 * // Pseudocode: choose a filter and stream data through it
 * var mime = response.contentType();
 * var filter = Filters.forMimeType(mime); // returns a no-op filter if none exists
 * try (InputStream in = response.openStream(); OutputStream out = browserSink()) {
 *   filter.filter(in, out);
 * }
 * }</pre>
 */
package network.crypta.client.filter;
