package network.crypta.client.async;

import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.USK;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates completion callbacks and retained data handling for USK fetchers.
 *
 * <p>This helper wraps a {@link USKCompletionHandler} to decode data, retain the most recent
 * payload, and deliver completion callbacks when a polling cycle finishes. It owns references to
 * the manager, original USK, and requester so it can unregister and emit callbacks consistently.
 * Callers typically invoke it when a fetcher is finished or canceled, and the coordinator handles
 * cleanup of scheduler state and subscriber notification.
 *
 * <p>The class is mutable but relies on the caller for synchronization; it performs no internal
 * locking beyond the underlying collaborators. It also keeps track of real-time scheduling bias to
 * interact with the correct scheduler queue when cleaning up pending keys.
 *
 * <ul>
 *   <li>Decodes and applies data based on completion decisions.
 *   <li>Exposes retained-data accessors for completion logic.
 *   <li>Handles unsubscribe and callback delivery on completion.
 * </ul>
 */
final class USKCompletionCoordinator {
  /** Logger for callback completion errors. */
  private static final Logger LOG = LoggerFactory.getLogger(USKCompletionCoordinator.class);

  /** Completion handler that performs decoding and retained-data management. */
  private final USKCompletionHandler completionHandler;

  /** Manager used to unsubscribe and record completion. */
  private final USKManager uskManager;

  /** Base USK used for slot lookups and found-edition callbacks. */
  private final USK origUSK;

  /** Requester used for decoding and scheduling context. */
  private final ClientRequester parent;

  /** Whether cleanup should use real-time scheduling queues. */
  private final boolean realTimeFlag;

  /**
   * Creates a completion coordinator for a USK fetcher.
   *
   * <p>The coordinator depends on collaborators that are expected to remain valid for the life of
   * the fetcher. The {@code parent} and {@code realTimeFlag} are used to align cleanup operations
   * with the same scheduling bias as the fetcher itself.
   *
   * @param completionHandler handler that decodes and stores retained data; must be non-null
   * @param uskManager manager used to unsubscribe and track completion; must be non-null
   * @param origUSK base USK used for lookups and callback payloads; must be non-null
   * @param parent requester used for decode context and scheduling; must be non-null
   * @param realTimeFlag whether cleanup should use real-time scheduling queues
   */
  USKCompletionCoordinator(
      USKCompletionHandler completionHandler,
      USKManager uskManager,
      USK origUSK,
      ClientRequester parent,
      boolean realTimeFlag) {
    this.completionHandler = completionHandler;
    this.uskManager = uskManager;
    this.origUSK = origUSK;
    this.parent = parent;
    this.realTimeFlag = realTimeFlag;
  }

  /**
   * Decodes and applies a data block when decoding is requested.
   *
   * <p>If {@code decode} is {@code false}, the method returns immediately. Otherwise, it delegates
   * to {@link USKCompletionHandler#decodeBlockIfNeeded(boolean, ClientSSKBlock, ClientContext,
   * ClientRequester)} to produce a decoded bucket and then applies the decoded data to the
   * completion handler.
   *
   * @param decode whether decoding should be performed
   * @param block block to decode; may be null when only metadata is available
   * @param context client context used for decoding; must not be null
   */
  void applyDecodedData(boolean decode, ClientSSKBlock block, ClientContext context) {
    if (!decode) return;
    Bucket decoded = completionHandler.decodeBlockIfNeeded(true, block, context, parent);
    completionHandler.applyDecodedData(true, block, decoded);
  }

  /**
   * Applies decoded data for a discovered edition.
   *
   * <p>This delegates to the completion handler to parse or store the supplied data payload and
   * metadata flags.
   *
   * @param decode whether the payload should be decoded
   * @param metadata whether the payload represents metadata rather than raw content
   * @param codec compression codec identifier associated with the payload
   * @param data raw payload bytes; may be null when data is unavailable
   * @param context client context used for decoding; must not be null
   */
  void applyFoundDecodedData(
      boolean decode, boolean metadata, short codec, byte[] data, ClientContext context) {
    completionHandler.applyFoundDecodedData(decode, metadata, codec, data, context);
  }

  /**
   * Releases retained data bytes, if any.
   *
   * @return retained data bytes, or {@code null} when none are stored
   */
  @SuppressWarnings("unused")
  byte[] releaseLastDataBytes() {
    return completionHandler.releaseLastDataBytes();
  }

  /**
   * Returns the compression codec used by the retained data.
   *
   * @return codec identifier for the last retained data
   */
  @SuppressWarnings("unused")
  short lastCompressionCodec() {
    return completionHandler.lastCompressionCodec();
  }

  /**
   * Returns whether the retained data represents metadata.
   *
   * @return {@code true} if the retained data is metadata
   */
  @SuppressWarnings("unused")
  boolean lastWasMetadata() {
    return completionHandler.lastWasMetadata();
  }

  /**
   * Returns whether retained data from the last request is available.
   *
   * @return {@code true} if retained data is present
   */
  boolean hasLastRequestData() {
    return completionHandler.hasLastRequestData();
  }

  /** Clears any retained data from the last request. */
  void clearLastRequestData() {
    completionHandler.clearLastRequestData();
  }

  /**
   * Completes callbacks and cleans up fetcher state.
   *
   * <p>The method unsubscribes the fetcher, removes pending keys from the scheduler, and delivers
   * completion callbacks with the latest known edition and retained data. Exceptions thrown by
   * callbacks are caught and logged so that remaining callbacks still receive notifications.
   *
   * @param context client context used for scheduling and callback payloads
   * @param fetcher fetcher instance being completed; must not be null
   * @param callbacks callback array to notify; may be empty but not null
   */
  void completeCallbacks(
      ClientContext context, USKFetcher fetcher, USKFetcherCallback[] callbacks) {
    uskManager.unsubscribe(origUSK, fetcher);
    uskManager.onFinished(fetcher);
    context
        .getSskFetchScheduler(realTimeFlag)
        .schedTransient
        .removePendingKeys((KeyListener) fetcher);
    long ed = uskManager.lookupLatestSlot(origUSK);
    byte[] data = completionHandler.releaseLastDataBytes();
    short codec = completionHandler.lastCompressionCodec();
    boolean metadata = completionHandler.lastWasMetadata();
    for (USKFetcherCallback c : callbacks) {
      try {
        if (ed == -1) c.onFailure(context);
        else
          c.onFoundEdition(
              new USKFoundEdition(
                  new USKFoundEditionPayload(ed, origUSK.copy(ed), metadata, codec, data),
                  context,
                  new USKFoundEditionProgress(false, false)));
      } catch (Exception e) {
        LOG.error(
            "An exception occurred while dealing with a callback:{}\n{}", c, e.getMessage(), e);
      }
    }
  }

  /**
   * Notifies callbacks that the fetcher was canceled.
   *
   * @param context client context supplied to cancellation callbacks
   * @param callbacks callback array to notify; may be empty but not null
   */
  void finishCancelled(ClientContext context, USKFetcherCallback[] callbacks) {
    for (USKFetcherCallback c : callbacks) c.onCancelled(context);
  }
}
