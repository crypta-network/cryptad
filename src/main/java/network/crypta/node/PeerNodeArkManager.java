package network.crypta.node;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.FetchResult;
import network.crypta.client.async.USKRetriever;
import network.crypta.client.async.USKRetrieverCallback;
import network.crypta.keys.USK;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates ARK/USK retrieval state for a single peer connection.
 *
 * <p>This manager owns the current ARK {@link USK}, subscribes to updates through the USK manager,
 * and translates successful fetches into noderef updates on the owning {@link PeerNode}. Callers
 * typically seed state via {@link #parseArk(SimpleFieldSet, boolean, boolean)}, then invoke {@link
 * #startFetcher()} or {@link #stopFetcher()} as connection status and configuration change. The
 * manager is intentionally small and focused: it does not perform transport or routing logic, only
 * state tracking and callback wiring.
 *
 * <p>State is guarded by two mechanisms: {@link #myARK} uses an atomic reference for cross-thread
 * ARK snapshots, while {@code arkFetcherSync} protects fetcher subscription transitions. This
 * avoids holding the peer lock while invoking callbacks or scheduling unsubscribe work.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Deriving and persisting the peer's ARK edition and public URI.
 *   <li>Starting and stopping the USK subscription that polls ARK updates.
 *   <li>Applying fetched noderefs and refreshing handshake counters.
 * </ul>
 *
 * @see PeerNode
 * @see PeerNodeReferenceSupport
 * @see USKRetrieverCallback
 */
final class PeerNodeArkManager implements USKRetrieverCallback {
  /** Logger for ARK state changes, fetch lifecycle events, and parse failures. */
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeArkManager.class);

  /** Owning peer used for synchronization, noderef updates, and executor access. */
  private final PeerNode peer;

  /** Dedicated lock guarding subscription start/stop and {@link #arkFetcher} updates. */
  private final Object arkFetcherSync = new Object();

  /** Active USK subscription fetcher, or {@code null} when no fetch is running. */
  private USKRetriever arkFetcher;

  /** ARK currently used by {@link #arkFetcher}, guarded by {@link #arkFetcherSync}. */
  private USK subscribedArk;

  /** Current ARK USK for this peer, updated when fresher editions are learned. */
  private final AtomicReference<USK> myARK = new AtomicReference<>();

  /**
   * Creates a manager bound to a single peer instance.
   *
   * <p>The manager starts with no ARK and no subscription. Callers are expected to parse an ARK
   * from the peer's noderef and then explicitly start fetching when ARK retrievals are enabled.
   *
   * @param peer owning peer whose ARK lifecycle is managed; must be non-null.
   */
  PeerNodeArkManager(PeerNode peer) {
    this.peer = peer;
  }

  /**
   * Parses and stores an ARK USK from a peer noderef field set.
   *
   * <p>This method delegates ARK computation to {@link PeerNodeReferenceSupport}, then updates the
   * cached {@link #myARK} only when the computed value differs from the existing one. It is safe to
   * call repeatedly; unchanged input is treated as a no-op. The peer monitor protects ARK updates.
   *
   * @param fs noderef fields that may contain ARK data to compute.
   * @param onStartup hint indicating whether parsing occurs during startup.
   * @param forDiffNodeRef hint indicating noderef fields come from a diff.
   * @return {@code true} when a new ARK is stored; {@code false} otherwise.
   */
  boolean parseArk(SimpleFieldSet fs, boolean onStartup, boolean forDiffNodeRef) {
    USK currentArk = myARK.get();
    USK ark =
        PeerNodeReferenceSupport.computeArk(
            peer.selfPeerNode(), fs, onStartup, forDiffNodeRef, currentArk);
    if (ark == null) return false;
    synchronized (peer) {
      USK previousArk = myARK.get();
      if (previousArk == null || !previousArk.equals(ark)) {
        myARK.set(ark);
        return true;
      }
    }
    return false;
  }

  /**
   * Appends the current ARK fields to the provided field set.
   *
   * <p>If no ARK is available yet, the method returns without modifying the set. When present, it
   * writes the public URI and a suggested edition value adjusted by one to match the expected on-
   * wire encoding.
   *
   * @param fs destination field set that receives ARK fields when present.
   */
  void appendArkFields(SimpleFieldSet fs) {
    USK ark = myARK.get();
    if (ark == null) return;
    // Decrement it because we keep the number we would like to fetch, not the last one fetched.
    fs.put(PeerNode.SFS_KEY_ARK_NUMBER, ark.suggestedEdition - 1);
    fs.putSingle(PeerNode.SFS_KEY_ARK_PUBURI, ark.getBaseSSK().toString(false, false));
  }

  /**
   * Reports whether an ARK fetch subscription is currently active.
   *
   * <p>The return value reflects the presence of a cached retriever reference and is therefore a
   * fast, non-blocking check. Because it does not acquire {@link #arkFetcherSync}, callers should
   * treat the result as a snapshot that may change immediately after returning.
   *
   * @return {@code true} if a fetcher is recorded; {@code false} otherwise.
   */
  boolean isFetching() {
    return arkFetcher != null;
  }

  /**
   * Starts the ARK fetcher subscription when configuration and state allow it.
   *
   * <p>The method returns quickly if ARK fetching is disabled or no ARK is known. If a subscription
   * is already active for a different ARK, it re-subscribes to the newer ARK and unsubscribes the
   * previous retriever asynchronously. On success, it registers this instance as the callback and
   * stores the resulting {@link USKRetriever} under {@link #arkFetcherSync}. Locks are kept minimal
   * to avoid holding them across callback or network activity.
   */
  void startFetcher() {
    // Note: keep locking minimal; avoid holding locks across callbacks
    if (!peer.node.isEnableARKs()) return;
    USKRetriever oldFetcher = null;
    USK oldArk = null;
    synchronized (arkFetcherSync) {
      USK ark = myARK.get();
      if (ark == null) {
        LOG.debug("No ARK for {} !!!!", peer);
        return;
      }

      if (arkFetcher != null && Objects.equals(subscribedArk, ark)) {
        return;
      }

      if (arkFetcher == null) {
        LOG.debug("Starting ARK fetcher for {} : {}", peer, ark);
      } else {
        LOG.debug("Restarting ARK fetcher for {} : {} -> {}", peer, subscribedArk, ark);
        oldFetcher = arkFetcher;
        oldArk = subscribedArk;
      }

      arkFetcher =
          peer.node
              .services()
              .clientCore()
              .getUskManager()
              .subscribeContent(
                  ark,
                  this,
                  true,
                  peer.node.network().arkFetcherContext(),
                  RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
                  peer.node.getNonPersistentClientRT());
      subscribedArk = ark;
    }

    scheduleUnsubscribe(oldArk, oldFetcher);
  }

  /**
   * Stops the ARK fetcher subscription if one is active.
   *
   * <p>The method clears the cached retriever under {@link #arkFetcherSync}, then performs to
   * unsubscribe asynchronously on the node executor. This avoids invoking external callbacks while
   * holding locks and keeps stop operations safe during shutdown or disconnect sequences.
   */
  void stopFetcher() {
    if (!peer.node.isEnableARKs()) return;
    // Note: keep locking minimal; avoid holding locks across callbacks
    USK ark;
    USKRetriever ret;
    synchronized (arkFetcherSync) {
      if (arkFetcher == null) {
        if (LOG.isDebugEnabled()) LOG.debug("ARK fetcher not running for {}", peer);
        return;
      }
      ark = subscribedArk;
      ret = arkFetcher;
      arkFetcher = null;
      subscribedArk = null;
    }

    LOG.debug("Stopping ARK fetcher for {} : {}", peer, ark);
    scheduleUnsubscribe(ark, ret);
  }

  private void scheduleUnsubscribe(USK ark, USKRetriever retriever) {
    if (ark == null || retriever == null) {
      return;
    }
    peer.node
        .network()
        .executor()
        .execute(
            () ->
                peer.node
                    .services()
                    .clientCore()
                    .getUskManager()
                    .unsubscribeContent(ark, retriever, true));
  }

  /**
   * Applies a fetched ARK noderef update and refreshes peer handshake state.
   *
   * <p>The method records a successful ARK fetch, advances the stored edition when the fetched
   * edition is newer, and then delegates noderef processing to the peer. Parsing failures are
   * logged and treated as an ARK failure, leaving the previous ARK value intact.
   *
   * @param fs parsed noderef fields from the fetched ARK reference.
   * @param fetchedEdition edition number that was successfully fetched.
   */
  void handleArkUpdate(SimpleFieldSet fs, long fetchedEdition) {
    try {
      synchronized (peer) {
        peer.resetHandshakeCountAfterArkFetch();
        USK currentArk = myARK.get();
        if (currentArk != null && currentArk.suggestedEdition < fetchedEdition + 1) {
          myARK.set(currentArk.copy(fetchedEdition + 1));
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

  /**
   * Returns the polling priority used for normal ARK fetch cycles.
   *
   * <p>ARK retrievals are scheduled at the immediate splitfile priority to keep peer metadata
   * current without waiting for lower-priority queues. The returned value is constant and has no
   * side effects, so repeated calls are inexpensive and idempotent.
   *
   * @return the immediate splitfile priority class used by the ARK fetcher.
   */
  @Override
  public short getPollingPriorityNormal() {
    return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
  }

  /**
   * Returns the polling priority used while ARK fetch progress is tracked.
   *
   * <p>This mirrors {@link #getPollingPriorityNormal()} so that progress polling does not drop in
   * priority relative to normal ARK fetches. The value is constant and safe to call from any
   * thread.
   *
   * @return the immediate splitfile priority class used for progress polling.
   */
  @Override
  public short getPollingPriorityProgress() {
    return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
  }

  /**
   * Handles a successfully fetched ARK edition and applies it to the peer state.
   *
   * <p>The callback verifies that the fetched edition is not stale relative to the current ARK and
   * that the peer is not yet connected. It then reads the UTF-8 noderef payload from the {@link
   * FetchResult}, parses it into a {@link SimpleFieldSet}, and delegates to {@link
   * #handleArkUpdate(SimpleFieldSet, long)}. I/O or parse failures are logged and do not update the
   * ARK.
   *
   * @param origUSK original USK request key that initiated the retrieval.
   * @param edition edition number that was found by the fetcher.
   * @param result fetch result containing the ARK payload and metadata.
   */
  @Override
  public void onFound(USK origUSK, long edition, FetchResult result) {
    USK arkSnapshot = myARK.get();
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
