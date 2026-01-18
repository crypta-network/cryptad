package network.crypta.client.async;

import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.USK;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Handles completion and retained data handling for a USK fetcher. */
final class USKCompletionCoordinator {
  private static final Logger LOG = LoggerFactory.getLogger(USKCompletionCoordinator.class);

  private final USKCompletionHandler completionHandler;
  private final USKManager uskManager;
  private final USK origUSK;
  private final ClientRequester parent;
  private final boolean realTimeFlag;

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

  void applyDecodedData(boolean decode, ClientSSKBlock block, ClientContext context) {
    if (!decode) return;
    Bucket decoded = completionHandler.decodeBlockIfNeeded(decode, block, context, parent);
    completionHandler.applyDecodedData(decode, block, decoded);
  }

  void applyFoundDecodedData(
      boolean decode, boolean metadata, short codec, byte[] data, ClientContext context) {
    completionHandler.applyFoundDecodedData(decode, metadata, codec, data, context);
  }

  byte[] releaseLastDataBytes() {
    return completionHandler.releaseLastDataBytes();
  }

  short lastCompressionCodec() {
    return completionHandler.lastCompressionCodec();
  }

  boolean lastWasMetadata() {
    return completionHandler.lastWasMetadata();
  }

  Bucket lastRequestData() {
    return completionHandler.lastRequestData();
  }

  void clearLastRequestData() {
    completionHandler.clearLastRequestData();
  }

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
                  ed, origUSK.copy(ed), context, metadata, codec, data, false, false));
      } catch (Exception e) {
        LOG.error(
            "An exception occured while dealing with a callback:{}\n{}", c, e.getMessage(), e);
      }
    }
  }

  void finishCancelled(ClientContext context, USKFetcherCallback[] callbacks) {
    for (USKFetcherCallback c : callbacks) c.onCancelled(context);
  }
}
