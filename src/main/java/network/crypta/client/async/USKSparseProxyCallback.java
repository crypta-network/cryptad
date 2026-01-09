package network.crypta.client.async;

import network.crypta.keys.USK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A filtering {@link USKProgressCallback} that forwards only sparse, significant updates from an
 * underlying USK subscription.
 *
 * <p>This proxy coalesces noisy progress into a compact signal suitable for user interfaces or
 * higher-level coordination. During an active polling round it records the latest observed edition
 * and associated metadata but suppresses intermediate callbacks. Once the round transitions between
 * phases, it emits at most one consolidated update reflecting the current best knowledge of the
 * latest slot. Older or regressive signals are ignored unless they contribute new "known-good"
 * information. This reduces redundant work and log volume while preserving the key state
 * transitions library clients typically care about.
 *
 * <p>Thread-safety: instances synchronize internally to track the last observed/sent edition and to
 * ensure that at most one coalesced update is forwarded per phase. The wrapped callback is invoked
 * outside the monitor. Callers may reuse a single instance across polling lifecycles, but should
 * avoid sharing a single instance across different subscriptions.
 *
 * <ul>
 *   <li>Coalesces updates within a round; forwards on phase boundaries.
 *   <li>Prefers the newest observed edition; remembers "known-good" advancement.
 *   <li>Falls back to the latest recorded slot when no in-round update exists.
 * </ul>
 *
 * @author toad
 * @see USKCallback
 * @see USKProgressCallback
 * @see USKManager
 * @see USK
 */
public class USKSparseProxyCallback implements USKProgressCallback {
  private static final Logger LOG = LoggerFactory.getLogger(USKSparseProxyCallback.class);

  final USKCallback target;
  final USK key;

  private long lastEdition;
  private long lastSent;
  private boolean lastMetadata;
  private short lastCodec;
  private byte[] lastData;
  private boolean lastWasKnownGoodToo;
  private boolean roundFinished;

  /**
   * Creates a new sparse proxy around a target {@link USKCallback} for the given key.
   *
   * <p>The proxy captures detailed progress during a polling round and forwards at most one
   * coalesced update per phase transition to the wrapped callback. Use this when consumers prefer a
   * compact signal of the latest edition over a high-frequency stream of intermediate updates.
   *
   * <pre>{@code
   * // Example: wrap a verbose callback to reduce update volume
   * USKSparseProxyCallback proxy = new USKSparseProxyCallback(target, usk);
   * }</pre>
   *
   * @param cb The non-null callback to receive coalesced, phase-aligned notifications. It is
   *     invoked on internal threads; callers must ensure it is thread-safe.
   * @param key The non-null USK whose editions are being tracked by this proxy. Used for fallback
   *     lookups when no in-round update has been observed yet.
   */
  public USKSparseProxyCallback(USKCallback cb, USK key) {
    target = cb;
    lastEdition = -1; // So we see the first one even if it's 0
    lastSent = -1;
    this.key = key;
    if (LOG.isDebugEnabled())
      LOG.debug("Creating sparse proxy callback {} for {} for {}", this, cb, key);
  }

  /**
   * Receives an update about a discovered or advanced USK edition and applies sparse-forwarding
   * rules.
   *
   * <p>Within a polling round the proxy remembers only the newest observed edition and whether it
   * also advanced the highest known-good value. Updates for older editions are dropped unless they
   * contribute a known-good advance. The wrapped callback is invoked immediately only after a phase
   * boundary has been signalled; otherwise the information is retained and may be forwarded later
   * from {@link #onSendingToNetwork(ClientContext)} or {@link #onRoundFinished(ClientContext)}.
   *
   * @param foundEdition The payload describing the discovered edition and its metadata.
   */
  @Override
  public void onFoundEdition(USKFoundEdition foundEdition) {
    long l = foundEdition.edition();
    boolean metadata = foundEdition.metadata();
    short codec = foundEdition.codec();
    byte[] data = foundEdition.data();
    boolean newKnownGood = foundEdition.newKnownGood();
    synchronized (this) {
      if (l < lastEdition) {
        if (!roundFinished) return;
        if (!newKnownGood) return;
      } else if (l == lastEdition) {
        if (newKnownGood) lastWasKnownGoodToo = true;
      } else {
        lastEdition = l;
        lastMetadata = metadata;
        lastCodec = codec;
        lastData = data;
        lastWasKnownGoodToo = newKnownGood;
      }
      if (!roundFinished) return;
    }
    target.onFoundEdition(foundEdition);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation delegates directly to the wrapped target callback.
   */
  @Override
  public short getPollingPriorityNormal() {
    return target.getPollingPriorityNormal();
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation delegates directly to the wrapped target callback.
   */
  @Override
  public short getPollingPriorityProgress() {
    return target.getPollingPriorityProgress();
  }

  /**
   * Signals that the subscription is transitioning from local checks to network activity.
   *
   * <p>If no edition was forwarded during the current round, the proxy attempts a best-effort
   * fallback to the latest recorded slot for the configured key and emits a single consolidated
   * update to the wrapped callback. If an edition was already sent for the round, no further
   * forwarding occurs here.
   *
   * @param context Execution context for the current request; non-null and suitable for lightweight
   *     diagnostics associated with this transition.
   */
  @Override
  public void onSendingToNetwork(ClientContext context) {
    innerRoundFinished(context, false);
  }

  /**
   * Signals that a polling round has finished and forwards at most one coalesced update.
   *
   * <p>When the round completes, any retained "newest edition" observation is forwarded once to the
   * wrapped callback. Subsequent invocations within the same round are suppressed. This keeps the
   * consumer view aligned with natural scheduler milestones while avoiding redundant notifications.
   *
   * @param context Execution context for the current request; non-null and scoped to this round.
   */
  @Override
  public void onRoundFinished(ClientContext context) {
    innerRoundFinished(context, true);
  }

  private void innerRoundFinished(ClientContext context, boolean finishedRound) {
    long ed;
    boolean meta;
    short codec;
    byte[] data;
    boolean wasKnownGood;
    synchronized (this) {
      if (finishedRound) roundFinished = true;
      if (lastSent == lastEdition) return;
      lastSent = ed = lastEdition;
      meta = lastMetadata;
      codec = lastCodec;
      data = lastData;
      wasKnownGood = lastWasKnownGoodToo;
    }
    if (ed == -1) {
      ed = context.uskManager.lookupLatestSlot(key);
      if (ed == -1) return;
      meta = false;
      codec = -1;
      data = null;
      wasKnownGood = false;
    }
    // At this point, either we returned above or ed is guaranteed != -1
    target.onFoundEdition(
        new USKFoundEdition(ed, key, context, meta, codec, data, wasKnownGood, wasKnownGood));
  }
}
