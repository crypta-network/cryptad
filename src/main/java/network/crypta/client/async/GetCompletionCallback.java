package network.crypta.client.async;

import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.crypt.HashResult;
import network.crypta.support.compress.Compressor;

/**
 * Callback interface for asynchronous client {@code get} requests.
 *
 * <p>Implementations receive lifecycle notifications while a client download progresses, including
 * early metadata signals, size and compatibility information, and a final outcome that delivers a
 * {@link StreamGenerator} on success or a {@link FetchException} on failure. The callback is
 * intended for higher-level client code that needs to drive UI updates, persistence, or follow-up
 * processing without blocking the networking and decoding pipelines.
 *
 * <p>Invocation ordering is defined by the client state machine ({@link ClientGetState}) and may
 * vary depending on the data set and available metadata. Callbacks can be invoked from internal
 * worker threads; implementations should avoid long blocking operations and prefer offloading heavy
 * work to their own executor when necessary. Unless explicitly documented by the caller, no
 * guarantees are made about reentrancy; treat each method as potentially called on arbitrary
 * client-managed threads.
 *
 * <ul>
 *   <li>Progress: size, MIME type, compatibility mode, and splitfile characteristics may arrive
 *       before the actual data stream becomes available.
 *   <li>Outcome: exactly one terminal outcome is expected for a request — success or failure —
 *       after which no further progress callbacks should be relied upon.
 *   <li>Context: {@link ClientContext} provides helper services and utilities that are valid for
 *       the duration of the callback invocation.
 * </ul>
 *
 * @see ClientGetState
 * @see ClientContext
 * @see StreamGenerator
 * @see FetchException
 */
public interface GetCompletionCallback {

  /**
   * Signals successful completion of the request and provides access to the fetched content.
   *
   * <p>The supplied {@code streamGenerator} yields the decoded payload, while {@code
   * clientMetadata} and {@code decompressors} describe how the data should be interpreted and which
   * decompression steps (if any) are applicable. The provided {@code state} reflects the final
   * client state at the time of completion. Implementations should read or hand off the stream
   * promptly; delaying may hold internal resources longer than necessary.
   *
   * @param streamGenerator generator that produces the final decoded data stream; reading it may
   *     allocate buffers and I/O resources and should be done in a controlled manner
   * @param clientMetadata metadata describing the content, such as MIME type and related headers or
   *     parameters made available by the client layer during retrieval
   * @param decompressors ordered list of decompressors that were selected for this fetch; callers
   *     may inspect to understand the applied or applicable transformations
   * @param state final {@link ClientGetState} snapshot associated with this request at completion;
   *     useful for logging or correlating follow-up actions
   * @param context utilities and helpers for the duration of the callback; valid only within the
   *     calling thread and not intended for cross-thread retention
   */
  void onSuccess(
      StreamGenerator streamGenerator,
      ClientMetadata clientMetadata,
      List<? extends Compressor> decompressors,
      ClientGetState state,
      ClientContext context);

  /**
   * Reports a terminal failure for the request.
   *
   * <p>The {@code FetchException} conveys the reason category and any available detail. The
   * associated {@code state} reflects the most recent client state, which may include partial
   * progress information helpful for diagnostics or retries. Implementations should perform any
   * cleanup and user-visible error reporting needed for the failed operation.
   *
   * @param e exception describing the failure condition and context-specific details suitable for
   *     logging or presenting a user-readable message
   * @param state last known {@link ClientGetState} for this request; may indicate where the failure
   *     occurred within the pipeline or which component raised the error
   * @param context utilities and helpers for the duration of the callback; do not retain beyond the
   *     scope of the invocation unless explicitly supported by the caller
   */
  void onFailure(FetchException e, ClientGetState state, ClientContext context);

  /**
   * Called when the ClientGetState knows that it knows about all the blocks it will need to fetch.
   *
   * <p>This is typically the moment when the client can present more accurate progress indicators
   * because the total work is now bounded. It does not imply that any specific block has been
   * downloaded; rather, the dependency set is fully enumerated based on metadata and discovered
   * references.
   *
   * @param state current {@link ClientGetState} representing the request at the time of block-set
   *     finalization; callers may snapshot relevant counters for progress UIs
   * @param context utilities and helpers for the duration of the callback; valid for use only while
   *     handling this notification and not intended for cross-thread sharing
   */
  void onBlockSetFinished(ClientGetState state, ClientContext context);

  /**
   * Called when the ClientGetState handling the request yields control to another ClientGetState.
   *
   * <p>State transitions occur when the internal download pipeline advances between phases (for
   * example, moving from metadata processing to payload assembly) or when an alternate strategy is
   * selected. This notification allows implementers to discard state tied to the outgoing handler
   * and initialize any bookkeeping for the new one. The transition itself is controlled by the
   * client; callback recipients should treat both arguments as snapshots and must not attempt to
   * manipulate internal state objects directly.
   *
   * @param oldState The old ClientGetState.
   * @param newState The new ClientGetState.
   * @param context The database handle. Must not be used by other threads.
   */
  void onTransition(ClientGetState oldState, ClientGetState newState, ClientContext context);

  /**
   * Called when we know the size of the final data. Not the same as onExpectedTopSize(), which is
   * called for new metadata and gives more information. This might be called much later on for
   * older content.
   *
   * <p>Applications may use this information to provision storage, pre-allocate buffers, or compute
   * user-visible progress bars. The value is an estimate provided by upstream metadata; it may be
   * refined later if improved information becomes available.
   *
   * @param size The expected size of the final data expressed in bytes; callers should treat the
   *     value as advisory and be prepared for minor deviations in rare cases
   * @param context Utility object containing helpers, mostly not persistent, such as the Ticker,
   *     temporary storage factories etc.
   */
  void onExpectedSize(long size, ClientContext context);

  /**
   * Called when we know the MIME type of the final data. Useful for e.g. determining whether it is
   * safe to handle etc., although the client can ask for the client layer to handle filtering.
   *
   * <p>For example, a UI may enable a preview, select the appropriate viewer, or prompt before
   * handling executable or otherwise sensitive content types. The metadata may include parameters
   * such as character set or encoding hints depending on the source data.
   *
   * @param metadata The MIME type, possibly including parameters, as a String. For example, {@code
   *     "text/html; charset=ISO-8859-1"} when provided by the upstream metadata
   * @param context Utility object containing helpers, mostly not persistent, such as the Ticker,
   *     temporary storage factories etc.
   * @throws FetchException The callee can throw a FetchException to terminate the download e.g. if
   *     they can't handle the MIME type.
   */
  void onExpectedMIME(ClientMetadata metadata, ClientContext context) throws FetchException;

  /**
   * Indicates that metadata for the request has been finalized and will not change further.
   *
   * <p>After this notification, implementations may commit decisions that rely on stable metadata
   * (for example, selecting a renderer or allocating fixed-size structures). This signal does not
   * imply that content is available; it only states that the descriptive information is now
   * complete.
   */
  void onFinalizedMetadata();

  /**
   * Called when we know the size of the final file, and the number of blocks needed etc. For recent
   * metadata, this is known at the time of handling the top block.
   *
   * <p>This provides a complete picture necessary to drive progress indicators, capacity planning,
   * and user feedback for splitfile downloads. The values derive from top-level metadata and should
   * be considered authoritative for the current request.
   *
   * @param size The final size of the data in bytes as determined by the metadata layer.
   * @param compressed The size in bytes after compression and prior to decompression steps applied
   *     during decode; helpful for estimating network usage and disk staging
   * @param blocksReq The number of blocks required to successfully decode the file without error;
   *     progress can be measured against this target
   * @param blocksTotal The total number of blocks present and available to the client, including
   *     any redundancy beyond the minimum required count
   * @param context Utility object containing helpers, mostly not persistent, such as the Ticker,
   *     temporary storage factories etc.
   */
  void onExpectedTopSize(
      long size, long compressed, int blocksReq, int blocksTotal, ClientContext context);

  /**
   * Called when we know the settings for the splitfile.
   *
   * <p>Large files are represented as splitfiles; this callback communicates the observed
   * compatibility range and whether compression and keying behaviors apply. Depending on the insert
   * mode, a custom splitfile key may have been used. For modern metadata, definitive information
   * may be available at the top layer.
   *
   * @param min The lowest CompatibilityMode that appears to be valid based on what we've fetched so
   *     far; informs the minimum reader capability assumed for decode
   * @param max The highest CompatibilityMode that appears to be valid based on what we've fetched
   *     so far; informs the highest feature level observed for this content
   * @param customSplitfileKey The fixed byte[] encryption key used on insert. On anything recent, a
   *     single key is generated and reused; this reduces metadata size and improves SSK security
   * @param compressed Whether the content is compressed. If {@code false}, the {@code dontCompress}
   *     option was selected during insert and no decompression is necessary
   * @param bottomLayer Whether this report originates at the bottom layer of the splitfile pyramid
   *     (the actual file) rather than a metadata layer referencing additional content
   * @param definitiveAnyway Whether this report is definitive even though it is not from the bottom
   *     layer; recent splitfiles may embed complete data in the top key
   * @param context Utility object containing helpers, mostly not persistent, such as the Ticker,
   *     temporary storage factories etc.
   */
  void onSplitfileCompatibilityMode(
      CompatibilityMode min,
      CompatibilityMode max,
      byte[] customSplitfileKey,
      boolean compressed,
      boolean bottomLayer,
      boolean definitiveAnyway,
      ClientContext context);

  /**
   * Called when we know the HashResult of the final file. This will be checked when we actually
   * fetch it, so is guaranteed to be correct. For recent metadata this is known at the top
   * layer/block.
   *
   * <p>Providing the hash values early allows clients to verify integrity of cached or mirrored
   * copies and to display stable identifiers to users. Final verification occurs when the content
   * is assembled.
   *
   * @param hashes A set of hashes for the final file content; algorithms and layout are defined by
   *     {@link HashResult} and should be treated as immutable once reported
   * @param context Utility object containing helpers, mostly not persistent, such as the Ticker,
   *     temporary storage factories etc.
   */
  void onHashes(HashResult[] hashes, ClientContext context);
}
