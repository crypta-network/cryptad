package network.crypta.clients.http;

import java.util.Set;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertException;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;

/**
 * Browse-local content client seam for legacy HTTP toadlets.
 *
 * <p>This interface isolates browse-owned code from the runtime-owned high-level client APIs. The
 * browse leaf still needs a small set of content operations: creating fetch contexts, performing
 * synchronous fetches for HTTP responses, inserting generated content, scheduling best-effort
 * prefetches, and tuning size limits before a request starts. Keeping that surface here lets the
 * browse module stay leaf-safe while the concrete runtime binding remains in {@code
 * :bridge-http-runtime}.
 *
 * <p>Typical callers are browse and FProxy toadlets that construct a per-request {@link
 * FetchContext}, adjust it for the current request, then invoke {@link #fetch(FreenetURI,
 * RequestClient, FetchContext)} or {@link #prefetch(FreenetURI, long, long, Set)} as needed.
 * Implementations may be stateful with respect to default size caps, so callers should treat those
 * setters as configuration for further operations rather than as metadata on a single request.
 *
 * <ul>
 *   <li>Use {@link #getFetchContext()} or {@link #getFetchContext(long, String)} to get a fresh,
 *       mutable request context.
 *   <li>Use {@link #fetch(FreenetURI, RequestClient, FetchContext)} for blocking content retrieval
 *       on behalf of an HTTP request.
 *   <li>Use {@link #prefetch(FreenetURI, long, long, Set)} for best-effort warming of likely inline
 *       or follow-up content.
 * </ul>
 */
public interface BrowseContentClient {

  /**
   * Sets the default maximum payload length for later browse-side fetches.
   *
   * <p>This updates the client's default cap for final payload bytes returned by later fetches. It
   * is primarily used by browse routes that need to tighten or relax limits before they create a
   * new {@link FetchContext}. The value is expressed in bytes and applies to further operations
   * that consult the client defaults; it does not retroactively modify contexts that were already
   * created.
   *
   * @param maxLength maximum payload length, in bytes, that future browse-side fetch contexts
   *     should inherit
   */
  void setMaxLength(long maxLength);

  /**
   * Sets the default maximum intermediate-data length for later browse-side fetches.
   *
   * <p>This controls the default cap for temporary or intermediate data produced while executing a
   * fetch, such as decompression or filtering buffers. Browse code uses it when large pages or
   * media might require more temporary working space than the final output size alone suggests.
   * Like {@link #setMaxLength(long)}, this setting affects future contexts and requests rather than
   * mutating an existing in-flight fetch.
   *
   * @param maxIntermediateLength maximum intermediate-data length, in bytes, that newly created
   *     browse-side fetch contexts should inherit
   */
  void setMaxIntermediateLength(long maxIntermediateLength);

  /**
   * Creates a default fetch context using the current client defaults.
   *
   * <p>The returned context is intended to be caller-owned and mutable. Typical browse call paths
   * request a fresh context, adjust filtering or size options for the current request, and then
   * pass that context into {@link #fetch(FreenetURI, RequestClient, FetchContext)}. Callers should
   * not assume the context is safe to share across concurrent requests unless they add their own
   * synchronization and immutability guarantees.
   *
   * @return fresh mutable fetch context initialized from the client's current default settings
   */
  FetchContext getFetchContext();

  /**
   * Creates a fetch context with browse-specific size and origin hints applied.
   *
   * <p>This overload exists for browse and FProxy flows that already know the maximum response size
   * they are willing to serve and the absolute origin that should be used when rewriting filtered
   * links. Implementations typically seed the returned context from the client's defaults and then
   * apply the provided output-size and scheme/host/port hints before the caller performs any
   * request-specific adjustments.
   *
   * @param maxSize requested maximum output size, in bytes, for the context being created
   * @param schemeHostAndPort absolute scheme, host, and port hint used by filtering and link
   *     rewriting code, such as {@code https://example.invalid:8443}
   * @return fresh mutable fetch context prepared with the supplied size and origin hints
   */
  FetchContext getFetchContext(long maxSize, String schemeHostAndPort);

  /**
   * Performs a blocking fetch using the supplied fetch context and request identity.
   *
   * <p>This method is the browse seam for synchronous retrieval. Callers generally invoke it from a
   * toadlet request handler after constructing a per-request {@link FetchContext}. The supplied
   * {@link RequestClient} identifies the request for accounting and scheduling purposes, while the
   * context carries the filtering, size, and retry policy for this fetch. On success the method
   * returns only when the result is complete. On failure, it throws a {@link FetchException} whose
   * mode and attached metadata describe the reason.
   *
   * @param uri target content URI to fetch for the current HTTP request; implementations expect an
   *     exact request target rather than a loosely normalized alias
   * @param requestClient request identity used for scheduling, accounting, and cancellation
   *     ownership within the client/runtime layer
   * @param fetchContext mutable fetch context that defines limits and filtering behavior for this
   *     request only
   * @return completed fetch result containing the fetched data and associated metadata
   * @throws FetchException if the content cannot be fetched or filtered according to the supplied
   *     request context
   */
  FetchResult fetch(FreenetURI uri, RequestClient requestClient, FetchContext fetchContext)
      throws FetchException;

  /**
   * Performs a blocking insert using the supplied payload.
   *
   * <p>This is used by browse-owned routes that generate or upload content and need the resulting
   * URI before they can respond. The {@code insert} block carries both the payload and the desired
   * insert target. When {@code getChkOnly} is {@code true}, implementations may stop after
   * computing the CHK instead of performing a full network insert. The optional filename hint is
   * passed through for cases where downstream code records or exposes a suggested name.
   *
   * @param insert insert payload, metadata, and requested target URI for the operation
   * @param getChkOnly {@code true} to compute only the CHK and skip a full insert where supported;
   *     {@code false} to perform normal insert behavior
   * @param filenameHint optional filename hint associated with the inserted payload, or {@code
   *     null} when no hint is available
   * @return resulting URI reported by the underlying insert operation
   * @throws InsertException if the insert cannot be completed, or the requested URI is invalid for
   *     the chosen insert mode
   */
  FreenetURI insert(InsertBlock insert, boolean getChkOnly, String filenameHint)
      throws InsertException;

  /**
   * Schedules a best-effort prefetch for inline browse content discovered during filtering.
   *
   * <p>Prefetching is advisory rather than required. Browse code uses it when filtering discovers
   * inline resources or likely follow-up targets that may improve responsiveness if cached early.
   * Implementations may schedule the work asynchronously, skip it under load, or abandon it once
   * the timeout expires. A {@code null} MIME allowlist means any MIME type is acceptable, while a
   * non-null set limits the prefetch to matching MIME types.
   *
   * @param uri target URI to prefetch as a best-effort cache warm-up candidate
   * @param timeoutMillis maximum prefetch lifetime, in milliseconds, before the work should be
   *     abandoned if still incomplete
   * @param maxSize maximum number of bytes the prefetch should attempt to retrieve
   * @param allowedMimeTypes optional MIME allowlist; {@code null} permits prefetch regardless of
   *     MIME type, while a non-null set restricts prefetching to matching types
   */
  void prefetch(FreenetURI uri, long timeoutMillis, long maxSize, Set<String> allowedMimeTypes);
}
