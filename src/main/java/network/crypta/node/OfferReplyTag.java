package network.crypta.node;

import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tag that tracks the lifecycle of a single reply to an offer.
 *
 * <p>An {@code OfferReplyTag} extends {@link UIDTag} for the short window in which we process a
 * reply to an offered key. It records whether the reply concerns an SSK key and participates in the
 * standard UID bookkeeping so the identifier can be safely reused once outbound processing
 * completes.
 *
 * <p>Concurrency: inherits the synchronization discipline from {@link UIDTag}. Instances are
 * mutable and not thread‑safe without external synchronization.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class OfferReplyTag extends UIDTag {
  private static final Logger LOG = LoggerFactory.getLogger(OfferReplyTag.class);

  /** {@code true} when the reply concerns an SSK key; {@code false} for CHK. */
  final boolean ssk;

  /**
   * Create a tag for an offer reply.
   *
   * @param isSSK {@code true} if the reply is for an SSK key; {@code false} for CHK.
   * @param source Original source peer or {@code null} when originated locally.
   * @param realTimeFlag Whether this request uses the real‑time routing budget.
   * @param uid Unique identifier associated with this in‑flight operation.
   * @param node Owning node; used to obtain the {@link RequestTracker} via {@code
   *     node.routing().tracker()}.
   */
  public OfferReplyTag(boolean isSSK, PeerNode source, boolean realTimeFlag, long uid, Node node) {
    super(source, realTimeFlag, uid, node);
    ssk = isSSK;
  }

  @Override
  public void logStillPresent(Long uid) {
    // Log a concise, one‑line diagnostic including age, uid, and key type.
    String sb =
        "OfferReplyTag still present after "
            + TimeUtil.formatTime(age())
            + " (uid="
            + uid
            + ", ssk="
            + ssk
            + ")";
    LOG.error(sb);
  }

  @Override
  public int expectedTransfersIn(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
    // Offer replies do not account for inbound transfers.
    return 0;
  }

  @Override
  public int expectedTransfersOut(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
    // We expect exactly one outbound transfer for an offer reply.
    return 1;
  }

  /**
   * @return {@code true} if the reply concerns an SSK key.
   */
  @Override
  public boolean isSSK() {
    return ssk;
  }

  /**
   * @return {@code false}; this tag type is not an insert.
   */
  @Override
  public boolean isInsert() {
    return false;
  }

  /**
   * @return {@code true}; this tag type represents an offer reply.
   */
  @Override
  public boolean isOfferReply() {
    return true;
  }
}
