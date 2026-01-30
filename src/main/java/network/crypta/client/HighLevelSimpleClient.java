package network.crypta.client;

import java.util.Map;
import java.util.Set;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.client.async.ClientPutter;
import network.crypta.client.events.ClientEventListener;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;

/**
 * High-level client facade for common fetch and insert operations.
 *
 * <p>This interface defines a cohesive set of blocking and non-blocking APIs used by applications
 * to retrieve and publish content. It focuses on practical ergonomics: a small number of entry
 * points supported by per-request contexts for detailed control. Typical usage is:
 *
 * <pre>{@code
 * // 1) Configure general limits on the client
 * client.setMaxLength(10 * 1024 * 1024L); // 10 MiB
 *
 * // 2) Create a per-request context and start a fetch
 * FetchContext ctx = client.getFetchContext();
 * FetchResult res = client.fetch(uri);
 * }</pre>
 *
 * <p>Design notes:
 *
 * <ul>
 *   <li>Blocking methods return a result or throw; non-blocking methods return a handle and deliver
 *       progress via callbacks.
 *   <li>Contexts are cheap to create and are expected to be one-per-request.
 *   <li>Implementations may maintain mutable configuration; prefer copying a client when you need
 *       isolated event streams or short-lived adjustments.
 * </ul>
 */
public interface HighLevelSimpleClient {

  /**
   * Set the maximum length (in bytes) of fetched data.
   *
   * <p>The value acts as a guardrail for subsequent requests created through this client. It may be
   * used to reject responses or intermediate processing that would exceed the configured limit.
   *
   * @param maxLength Maximum allowed size in bytes for fetched output; applies to future requests
   *     created via this client instance and may be interpreted as an upper bound.
   */
  void setMaxLength(long maxLength);

  /**
   * Set the maximum length (in bytes) of intermediate data.
   *
   * <p>This limit applies to intermediary artifacts processed while obtaining the final result (for
   * example, container manifests). It does not directly cap the final output size unless the
   * concrete implementation ties the two together.
   *
   * @param maxIntermediateLength Maximum allowed size in bytes for intermediate processing
   *     artifacts; applies to future requests created via this client instance.
   */
  void setMaxIntermediateLength(long maxIntermediateLength);

  /**
   * Fetch a URI and block until completion.
   *
   * <p>This call resolves the provided {@code uri}, performs all network and verification steps as
   * configured by the current client settings, and returns the result on success.
   *
   * @param uri The content identifier to retrieve; must not be {@code null}.
   * @return A completed fetch result containing data and metadata when available; never {@code
   *     null} on success.
   * @throws FetchException If the request fails, times out, is rejected by limits, or otherwise
   *     cannot complete successfully.
   */
  FetchResult fetch(FreenetURI uri) throws FetchException;

  /**
   * Fetch from already-available metadata and block until completion.
   *
   * <p>Some workflows begin with a metadata block rather than a URI. This method treats the given
   * metadata as the starting point for resolution.
   *
   * @param initialMetadata The initial metadata source used to resolve the final content; must not
   *     be {@code null}.
   * @return A completed fetch result derived from the supplied metadata; never {@code null} on
   *     success.
   * @throws FetchException If resolution from the provided metadata fails or violates configured
   *     constraints.
   */
  @SuppressWarnings("unused")
  FetchResult fetchFromMetadata(Bucket initialMetadata) throws FetchException;

  /**
   * Fetch a URI with a maximum-size override and block until completion.
   *
   * <p>The {@code maxSize} parameter can constrain output and intermediate processing sizes for the
   * lifetime of this specific request. Implementations may interpret non-positive values as no
   * override to the current client defaults.
   *
   * @param uri The content identifier to retrieve; must not be {@code null}.
   * @param maxSize Per-request maximum size in bytes for both output and related intermediate data;
   *     interpretation of non-positive values is implementation-defined.
   * @return A completed fetch result containing data and metadata when available; never {@code
   *     null} on success.
   * @throws FetchException If the request cannot be completed successfully.
   */
  FetchResult fetch(FreenetURI uri, long maxSize) throws FetchException;

  /**
   * Fetch a URI with size override and an explicit request context, then block.
   *
   * <p>The {@code context} influences scheduling and persistence characteristics of the request
   * (for example, priority and persistence flags).
   *
   * @param uri The content identifier to retrieve; must not be {@code null}.
   * @param maxSize Per-request maximum size in bytes for both output and related intermediate data;
   *     interpretation of non-positive values is implementation-defined.
   * @param context A request client used for scheduling and lifecycle coordination; must not be
   *     {@code null} when context-specific routing or persistence is required.
   * @return A completed fetch result containing data and metadata when available; never {@code
   *     null} on success.
   * @throws FetchException If the request cannot be completed successfully.
   */
  FetchResult fetch(FreenetURI uri, long maxSize, RequestClient context) throws FetchException;

  /**
   * Start a non-blocking fetch with an explicit callback and priority.
   *
   * <p>The returned handle represents an active request that will notify the supplied callback as
   * progress occurs and when the request completes or fails.
   *
   * @param uri The content identifier to retrieve; must not be {@code null}.
   * @param callback Callback invoked for completion and progress notifications; must not be {@code
   *     null}.
   * @param fctx Per-request fetch context controlling limits and behavior; must not be {@code
   *     null}.
   * @param prio Initial priority class for scheduling; valid range depends on the scheduler
   *     configuration.
   * @return A started {@code ClientGetter} representing the asynchronous fetch operation.
   * @throws FetchException If the request cannot be started due to invalid parameters or current
   *     constraints.
   */
  ClientGetter fetch(FreenetURI uri, ClientGetCallback callback, FetchContext fctx, short prio)
      throws FetchException;

  /**
   * Start a non-blocking fetch using an initial metadata block.
   *
   * <p>This variant is analogous to {@code fetchFromMetadata(...)} but returns immediately with an
   * active request handle; results are delivered via the provided callback.
   *
   * @param initialMetadata The initial metadata source used to resolve the final content; must not
   *     be {@code null}.
   * @param callback Callback invoked for completion and progress notifications; must not be {@code
   *     null}.
   * @param fctx Per-request fetch context controlling limits and behavior; must not be {@code
   *     null}.
   * @param prio Initial priority class for scheduling; valid range depends on the scheduler
   *     configuration.
   * @return A started {@code ClientGetter} representing the asynchronous fetch operation.
   * @throws FetchException If the request cannot be started due to invalid parameters or current
   *     constraints.
   */
  @SuppressWarnings("unused")
  ClientGetter fetchFromMetadata(
      Bucket initialMetadata, ClientGetCallback callback, FetchContext fctx, short prio)
      throws FetchException;

  /**
   * Start a non-blocking fetch with an explicit callback and context.
   *
   * <p>Returns immediately with a handle; progress and completion are delivered to the callback.
   * For priority control, use {@link #fetch(FreenetURI, ClientGetCallback, FetchContext, short)}.
   *
   * @param uri The content identifier to retrieve; must not be {@code null}.
   * @param callback Callback invoked for completion and progress notifications; must not be {@code
   *     null}.
   * @param fctx Per-request fetch context controlling limits and behavior; must not be {@code
   *     null}.
   * @return A started {@code ClientGetter} representing the asynchronous fetch operation.
   * @throws FetchException If the request cannot be started due to invalid parameters or current
   *     constraints.
   */
  ClientGetter fetch(FreenetURI uri, ClientGetCallback callback, FetchContext fctx)
      throws FetchException;

  /**
   * Start a non-blocking fetch with a maximum-size parameter and explicit priority.
   *
   * <p>Returns immediately with a handle; progress and completion are delivered to the callback.
   *
   * @param uri The content identifier to retrieve; must not be {@code null}.
   * @param maxSize Per-request maximum size in bytes for both output and related intermediate data;
   *     interpretation of non-positive values is implementation-defined.
   * @param callback Callback invoked for completion and progress notifications; must not be {@code
   *     null}.
   * @param fctx Per-request fetch context controlling limits and behavior; must not be {@code
   *     null}.
   * @param priorityClass Initial priority class for scheduling; valid range depends on the
   *     scheduler configuration.
   * @return A started {@code ClientGetter} representing the asynchronous fetch operation.
   * @throws FetchException If the request cannot be started due to invalid parameters or current
   *     constraints.
   */
  ClientGetter fetch(
      FreenetURI uri,
      long maxSize,
      ClientGetCallback callback,
      FetchContext fctx,
      short priorityClass)
      throws FetchException;

  /**
   * Insert a single block or small object and block until completion.
   *
   * <p>Depending on flags, this may compute and return the final insert URI or only the CHK.
   *
   * @param insert The data and metadata bundle to insert; must not be {@code null}.
   * @param getCHKOnly When {@code true}, compute the CHK without publishing full content.
   * @param filenameHint Optional filename hint used to build a single-file manifest; may be {@code
   *     null} when not desired.
   * @return The resulting URI that identifies the inserted content; never {@code null} on success.
   * @throws InsertException If the insert fails or constraints prevent completion.
   */
  FreenetURI insert(InsertBlock insert, boolean getCHKOnly, String filenameHint)
      throws InsertException;

  /**
   * Insert a single block or small object at a specific priority and block until completion.
   *
   * @param insert The data and metadata bundle to insert; must not be {@code null}.
   * @param getCHKOnly When {@code true}, compute the CHK without publishing full content.
   * @param filenameHint Optional filename hint used to build a single-file manifest; may be {@code
   *     null} when not desired.
   * @param priority Priority class used for scheduling; valid range depends on the scheduler
   *     configuration.
   * @return The resulting URI that identifies the inserted content; never {@code null} on success.
   * @throws InsertException If the insert fails or constraints prevent completion.
   */
  FreenetURI insert(InsertBlock insert, boolean getCHKOnly, String filenameHint, short priority)
      throws InsertException;

  /**
   * Insert content using an explicit insert context and block until completion.
   *
   * @param insert The data and metadata bundle to insert; must not be {@code null}.
   * @param filenameHint Optional filename hint used to build a single-file manifest; may be {@code
   *     null} when not desired.
   * @param priority Priority class used for scheduling; valid range depends on the scheduler
   *     configuration.
   * @param ctx Per-request insert context controlling limits and behavior; must not be {@code
   *     null}.
   * @return The resulting URI that identifies the inserted content; never {@code null} on success.
   * @throws InsertException If the insert fails or constraints prevent completion.
   */
  FreenetURI insert(InsertBlock insert, String filenameHint, short priority, InsertContext ctx)
      throws InsertException;

  /**
   * Start a non-blocking insert and return immediately.
   *
   * <p>Completion and progress are reported to the supplied callback.
   *
   * @param insert The data and metadata bundle to insert; must not be {@code null}.
   * @param filenameHint Optional filename hint used to build a single-file manifest; may be {@code
   *     null} when not desired.
   * @param isMetadata When {@code true}, treat the data as metadata rather than user content.
   * @param ctx Per-request insert context controlling limits and behavior; must not be {@code
   *     null}.
   * @param cb Callback invoked for completion and progress notifications; must not be {@code null}.
   * @return A started {@code ClientPutter} representing the asynchronous insert operation.
   * @throws InsertException If the insert cannot be started due to invalid parameters or current
   *     constraints.
   */
  ClientPutter insert(
      InsertBlock insert,
      String filenameHint,
      boolean isMetadata,
      InsertContext ctx,
      ClientPutCallback cb)
      throws InsertException;

  /**
   * Start a non-blocking insert at a specific priority and return immediately.
   *
   * <p>Completion and progress are reported to the supplied callback.
   *
   * @param insert The data and metadata bundle to insert; must not be {@code null}.
   * @param filenameHint Optional filename hint used to build a single-file manifest; may be {@code
   *     null} when not desired.
   * @param isMetadata When {@code true}, treat the data as metadata rather than user content.
   * @param ctx Per-request insert context controlling limits and behavior; must not be {@code
   *     null}.
   * @param cb Callback invoked for completion and progress notifications; must not be {@code null}.
   * @param priority Priority class used for scheduling; valid range depends on the scheduler
   *     configuration.
   * @return A started {@code ClientPutter} representing the asynchronous insert operation.
   * @throws InsertException If the insert cannot be started due to invalid parameters or current
   *     constraints.
   */
  ClientPutter insert(
      InsertBlock insert,
      String filenameHint,
      boolean isMetadata,
      InsertContext ctx,
      ClientPutCallback cb,
      short priority)
      throws InsertException;

  /**
   * Insert a redirect that points one URI to another.
   *
   * <p>This operation publishes a small object instructing clients to resolve {@code insertURI} to
   * {@code target}.
   *
   * @param insertURI The URI under which the redirect object is published; must not be {@code
   *     null}.
   * @param target The final target URI clients should follow to; must not be {@code null}.
   * @return The URI that identifies the stored redirect object; never {@code null} on success.
   * @throws InsertException If the redirect object cannot be created or published.
   */
  FreenetURI insertRedirect(FreenetURI insertURI, FreenetURI target) throws InsertException;

  /**
   * Insert multiple files as a manifest (for example, a directory-like structure) and block.
   *
   * <p>The {@code bucketsByName} map represents a tree of entries where values are either data
   * buckets, nested manifests, or manifest items. Implementations define the accepted value types.
   *
   * @param insertURI Base URI under which the manifest is inserted; must not be {@code null}.
   * @param bucketsByName Mapping of logical names to entries (data or sub-structures); must not be
   *     {@code null}.
   * @param defaultName Optional default item name to use when a consumer needs a single entry; may
   *     be {@code null}.
   * @return The URI that identifies the stored manifest; never {@code null} on success.
   * @throws InsertException If manifest assembly or publishing fails.
   */
  FreenetURI insertManifest(
      FreenetURI insertURI, Map<String, Object> bucketsByName, String defaultName)
      throws InsertException;

  /**
   * Insert multiple files as a manifest with an explicit priority and block.
   *
   * @param insertURI Base URI under which the manifest is inserted; must not be {@code null}.
   * @param bucketsByName Mapping of logical names to entries (data or sub-structures); must not be
   *     {@code null}.
   * @param defaultName Optional default item name to use when a consumer needs a single entry; may
   *     be {@code null}.
   * @param priorityClass Priority class used for scheduling; valid range depends on the scheduler
   *     configuration.
   * @return The URI that identifies the stored manifest; never {@code null} on success.
   * @throws InsertException If manifest assembly or publishing fails.
   */
  FreenetURI insertManifest(
      FreenetURI insertURI,
      Map<String, Object> bucketsByName,
      String defaultName,
      short priorityClass)
      throws InsertException;

  /**
   * Insert multiple files as a manifest with an explicit priority and optional crypto key override.
   *
   * @param insertURI Base URI under which the manifest is inserted; must not be {@code null}.
   * @param bucketsByName Mapping of logical names to entries (data or sub-structures); must not be
   *     {@code null}.
   * @param defaultName Optional default item name to use when a consumer needs a single entry; may
   *     be {@code null}.
   * @param priorityClass Priority class used for scheduling; valid range depends on the scheduler
   *     configuration.
   * @param forceCryptoKey Optional raw key material used to override the manifest crypto key; may
   *     be {@code null}.
   * @return The URI that identifies the stored manifest; never {@code null} on success.
   * @throws InsertException If manifest assembly or publishing fails.
   */
  FreenetURI insertManifest(
      FreenetURI insertURI,
      Map<String, Object> bucketsByName,
      String defaultName,
      short priorityClass,
      byte[] forceCryptoKey)
      throws InsertException;

  /**
   * Create a new {@code FetchContext} configured from current client settings.
   *
   * <p>A fresh context is typically created per request so per-request modifications do not affect
   * other operations; passing a modified context to a {@code fetch(...)} call applies those changes
   * to that request only.
   *
   * @return A new fetch context initialized from the current client configuration.
   */
  FetchContext getFetchContext();

  /**
   * Create a new {@code FetchContext} with a suggested size parameter.
   *
   * <p>The effect of {@code size} is implementation-defined; typical implementations use it to
   * initialize output and intermediate size limits for the returned context.
   *
   * @param size Suggested maximum size in bytes used to initialize limits of the returned context;
   *     interpretation of non-positive values is implementation-defined.
   * @return A new fetch context initialized from the current client configuration.
   */
  FetchContext getFetchContext(long size);

  /**
   * Create a new {@code FetchContext} with a suggested size and network endpoint hint.
   *
   * <p>The {@code schemeHostAndPort} string may guide how relative references are resolved during
   * fetches that require an origin-like hint.
   *
   * @param size Suggested maximum size in bytes used to initialize limits of the returned context;
   *     interpretation of non-positive values is implementation-defined.
   * @param schemeHostAndPort Optional hint in the form {@code scheme://host:port} used to influence
   *     resolution behavior; may be {@code null}.
   * @return A new fetch context initialized from the current client configuration.
   */
  FetchContext getFetchContext(long size, String schemeHostAndPort);

  /**
   * Create a new {@code InsertContext} configured from current client settings.
   *
   * <p>The {@code forceNonPersistent} flag directs the implementation to use the non-persistent
   * bucket pool for any temporary allocations required by the insert operation.
   *
   * @param forceNonPersistent When {@code true}, prefer the non-persistent bucket pool for
   *     temporary data structures during insertion.
   * @return A new insert context initialized from the current client configuration.
   */
  InsertContext getInsertContext(boolean forceNonPersistent);

  /**
   * Register an event listener to receive client request events.
   *
   * <p>Listeners may observe progress and completion notifications for requests initiated through
   * this client after registration.
   *
   * @param listener The listener to add; must not be {@code null}. Duplicate registrations may be
   *     ignored by implementations.
   */
  void addEventHook(ClientEventListener listener);

  /**
   * Generate a new key pair for document publishing.
   *
   * <p>The returned array contains two URIs: index {@code 0} is the insert URI and index {@code 1}
   * is the corresponding request URI.
   *
   * @param docName Optional document name associated with the key material; may be {@code null}.
   * @return An array containing the insert and request URIs in that order; never {@code null} on
   *     success.
   */
  @SuppressWarnings("unused")
  FreenetURI[] generateKeyPair(String docName);

  /**
   * Prefetch a key at a low priority and cancel if not ready by a deadline.
   *
   * <p>This is a best-effort warm-up: the request is cancelled automatically if it has not
   * completed before {@code timeout} elapses.
   *
   * @param uri The content identifier to warm up in the cache; must not be {@code null}.
   * @param timeout Timeout in milliseconds after which the request is cancelled.
   * @param maxSize Maximum size in bytes allowed for the prefetch; interpretation of non-positive
   *     values is implementation-defined.
   * @param allowedTypes Optional set of accepted MIME types; when non-{@code null}, the prefetch is
   *     cancelled if the resolved type is not included.
   */
  void prefetch(FreenetURI uri, long timeout, long maxSize, Set<String> allowedTypes);

  /**
   * Prefetch a key at the given priority and cancel if not ready by a deadline.
   *
   * <p>This is a best-effort warm-up: the request is cancelled automatically if it has not
   * completed before {@code timeout} elapses.
   *
   * @param uri The content identifier to warm up in the cache; must not be {@code null}.
   * @param timeout Timeout in milliseconds after which the request is cancelled.
   * @param maxSize Maximum size in bytes allowed for the prefetch; interpretation of non-positive
   *     values is implementation-defined.
   * @param allowedTypes Optional set of accepted MIME types; when non-{@code null}, the prefetch is
   *     cancelled if the resolved type is not included.
   * @param prio Initial priority class for scheduling; valid range depends on the scheduler
   *     configuration.
   */
  void prefetch(FreenetURI uri, long timeout, long maxSize, Set<String> allowedTypes, short prio);

  /**
   * Create a copy of this client with the same configuration/state.
   *
   * <p>The copy is intended for issuing additional requests that should not share per-request
   * listeners or transient execution state with the original while keeping the same configuration
   * baselines.
   *
   * @return A new client instance initialized from this client's configuration.
   */
  HighLevelSimpleClient copy();
}
