package network.crypta.node;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import network.crypta.client.FetchResult;
import network.crypta.client.async.USKRetriever;
import network.crypta.client.async.USKRetrieverCallback;
import network.crypta.keys.USK;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles ARK/USK retrieval lifecycle for a peer.
 *
 * <p>Encapsulates ARK state, fetcher lifecycle, and noderef updates triggered by ARK fetches.
 */
final class PeerNodeArkManager implements USKRetrieverCallback {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeArkManager.class);

  private final PeerNode peer;
  private final Object arkFetcherSync = new Object();
  private USKRetriever arkFetcher;
  private USK myARK;

  PeerNodeArkManager(PeerNode peer) {
    this.peer = peer;
  }

  boolean parseArk(SimpleFieldSet fs, boolean onStartup, boolean forDiffNodeRef) {
    USK ark =
        PeerNodeReferenceSupport.computeArk(
            peer.selfPeerNode(), fs, onStartup, forDiffNodeRef, myARK);
    if (ark == null) return false;
    synchronized (peer) {
      if ((myARK == null) || ((myARK != ark) && !myARK.equals(ark))) {
        myARK = ark;
        return true;
      }
    }
    return false;
  }

  void appendArkFields(SimpleFieldSet fs) {
    USK ark;
    synchronized (peer) {
      ark = myARK;
    }
    if (ark == null) return;
    // Decrement it because we keep the number we would like to fetch, not the last one fetched.
    fs.put(PeerNode.SFS_KEY_ARK_NUMBER, ark.suggestedEdition - 1);
    fs.putSingle(PeerNode.SFS_KEY_ARK_PUBURI, ark.getBaseSSK().toString(false, false));
  }

  boolean isFetching() {
    return arkFetcher != null;
  }

  void startFetcher() {
    // Note: keep locking minimal; avoid holding locks across callbacks
    if (!peer.node.isEnableARKs()) return;
    synchronized (arkFetcherSync) {
      if (myARK == null) {
        LOG.debug("No ARK for {} !!!!", peer);
        return;
      }
      if (arkFetcher == null) {
        LOG.debug("Starting ARK fetcher for {} : {}", peer, myARK);
        arkFetcher =
            peer.node
                .getClientCore()
                .getUskManager()
                .subscribeContent(
                    myARK,
                    this,
                    true,
                    peer.node.getArkFetcherContext(),
                    RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
                    peer.node.getNonPersistentClientRT());
      }
    }
  }

  void stopFetcher() {
    if (!peer.node.isEnableARKs()) return;
    LOG.debug("Stopping ARK fetcher for {} : {}", peer, myARK);
    // Note: keep locking minimal; avoid holding locks across callbacks
    USKRetriever ret;
    synchronized (arkFetcherSync) {
      if (arkFetcher == null) {
        if (LOG.isDebugEnabled()) LOG.debug("ARK fetcher not running for {}", peer);
        return;
      }
      ret = arkFetcher;
      arkFetcher = null;
    }
    final USKRetriever unsub = ret;
    peer.node
        .getExecutor()
        .execute(
            () -> peer.node.getClientCore().getUskManager().unsubscribeContent(myARK, unsub, true));
  }

  void handleArkUpdate(SimpleFieldSet fs, long fetchedEdition) {
    try {
      synchronized (peer) {
        peer.resetHandshakeCountAfterArkFetch();
        if (myARK != null && myARK.suggestedEdition < fetchedEdition + 1) {
          myARK = myARK.copy(fetchedEdition + 1);
        }
      }
      peer.processNewNoderef(fs, true, false, false);
    } catch (FSParseException e) {
      LOG.error("Invalid ARK update: {}", e, e);
      // This is ok as ARKs are limited to 4K anyway.
      LOG.error("Data was: \n{}", fs);
      peer.markHandshakeCountAfterArkFailure();
    }
  }

  @Override
  public short getPollingPriorityNormal() {
    return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
  }

  @Override
  public short getPollingPriorityProgress() {
    return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
  }

  @Override
  public void onFound(USK origUSK, long edition, FetchResult result) {
    USK arkSnapshot;
    synchronized (peer) {
      arkSnapshot = myARK;
    }
    try (var _ = result.asBucket()) {
      if (arkSnapshot == null || peer.isConnected() || arkSnapshot.suggestedEdition > edition) {
        return;
      }

      byte[] data;
      try {
        data = result.asByteArray();
      } catch (IOException e) {
        LOG.error("I/O error reading fetched ARK: {}", e, e);
        return;
      }

      String ref = new String(data, StandardCharsets.UTF_8);

      try {
        SimpleFieldSet fs = new SimpleFieldSet(ref, false, true, false);
        if (LOG.isDebugEnabled()) LOG.debug("Got ARK for {}", peer);
        handleArkUpdate(fs, edition);
      } catch (IOException e) {
        // Corrupt ref.
        LOG.error(
            "Corrupt ARK reference? Fetched {} got while parsing: {} from:\n{}",
            arkSnapshot.copy(edition),
            e,
            ref,
            e);
      }
    }
  }
}
