package network.crypta.node;

import network.crypta.support.Logger;
import network.crypta.support.TimeUtil;

/**
 * Tag tracking an offer reply.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class OfferReplyTag extends UIDTag {

  final boolean ssk;

  public OfferReplyTag(boolean isSSK, PeerNode source, boolean realTimeFlag, long uid, Node node) {
    super(source, realTimeFlag, uid, node);
    ssk = isSSK;
  }

  @Override
  public void logStillPresent(Long uid) {
    String sb = "Still present after " + TimeUtil.formatTime(age()) + " : ssk=" + ssk;
    Logger.error(this, sb);
  }

  @Override
  public int expectedTransfersIn(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
    return 0;
  }

  @Override
  public int expectedTransfersOut(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
    return 1;
  }

  @Override
  public boolean isSSK() {
    return ssk;
  }

  @Override
  public boolean isInsert() {
    return false;
  }

  @Override
  public boolean isOfferReply() {
    return true;
  }
}
