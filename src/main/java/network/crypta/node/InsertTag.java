package network.crypta.node;

import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tag that tracks the lifecycle of a single insert request.
 *
 * <p>An {@code InsertTag} extends {@link UIDTag} with insert‑specific state: whether the request
 * targets an SSK key ({@link #ssk}) and where the request originated ({@link START}). It also
 * coordinates unlocking of the underlying UID with the lifetime of a corresponding sender: the UID
 * is not released while the sender has started but not yet finished.
 *
 * <p>Concurrency: several methods are {@code synchronized} on {@code this}. Callers must follow the
 * same locking discipline used by {@link UIDTag}. Instances are mutable and not thread‑safe without
 * external synchronization.
 *
 * <p>Logging: when a tag exceeds the request timeout, {@link #logStillPresent(Long)} emits a
 * concise one‑line diagnostic that includes the age, UID (if provided), origin, key type, and any
 * recorded handler exception.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class InsertTag extends UIDTag {
  private static final Logger LOG = LoggerFactory.getLogger(InsertTag.class);

  private final boolean ssk;

  /** Where the insert originates from. */
  enum START {
    LOCAL,
    REMOTE,
  }

  private final START start;
  private Throwable handlerThrew;
  private boolean senderStarted;
  private boolean senderFinished;

  InsertTag(boolean ssk, START start, PeerNode source, boolean realTimeFlag, long uid, Node node) {
    super(source, realTimeFlag, uid, node);
    this.start = start;
    this.ssk = ssk;
  }

  /**
   * Mark that the outbound sender has started.
   *
   * <p>While the sender is active (started but not finished), {@link #mustUnlock()} returns {@code
   * false} to prevent premature UID release.
   */
  public synchronized void startedSender() {
    senderStarted = true;
    UIDTraceLogger.log("insertSenderStart", this);
  }

  /**
   * Mark that the outbound sender has finished and attempt to release the UID if eligible.
   *
   * <p>If {@link #mustUnlock()} evaluates to {@code true} after updating state, this method invokes
   * the standard unlocking path to allow the UID to be reused.
   */
  public void finishedSender() {
    boolean unlockNow;
    boolean localNoRecordUnlock = false;
    synchronized (this) {
      senderFinished = true;
      unlockNow = mustUnlock();
      if (unlockNow) {
        localNoRecordUnlock = this.noRecordUnlock;
      }
    }
    UIDTraceLogger.log("insertSenderFinish", this, () -> "unlock=" + unlockNow);
    if (!unlockNow) return;
    innerUnlock(localNoRecordUnlock);
  }

  /**
   * Defer unlocking while the sender is mid‑flight; otherwise delegate to the base decision.
   *
   * <p>Returns {@code false} when {@link #startedSender()} has been called but {@link
   * #finishedSender()} has not, even if the handler has already unlocked.
   */
  @Override
  protected synchronized boolean mustUnlock() {
    if (senderStarted && !senderFinished) return false;
    return super.mustUnlock();
  }

  /**
   * Record an exception thrown by the request handler for later diagnostics.
   *
   * @param t Throwable thrown by the handler; may be {@code null} to clear.
   */
  public synchronized void handlerThrew(Throwable t) {
    handlerThrew = t;
    if (t != null) {
      UIDTraceLogger.log("handlerThrew", this, () -> "error=" + t.getClass().getSimpleName());
    }
  }

  /**
   * Emit a single‑line diagnostic that the tag remains after the timeout threshold.
   *
   * <p>Includes the age (human‑readable), UID when provided, origin, key type, whether a handler
   * exception was recorded, and the base tag state from {@link UIDTag#toString()}.
   *
   * @param uid Optional UID to include in the message; may be {@code null}.
   */
  @Override
  public void logStillPresent(Long uid) {
    if (LOG.isErrorEnabled()) {
      StringBuilder sb = new StringBuilder();
      sb.append("Still present after ").append(TimeUtil.formatTime(age()));
      sb.append(" : ").append(uid);
      sb.append(" : start=").append(start);
      sb.append(" ssk=").append(ssk);
      sb.append(" : ");
      sb.append(super.toString());
      if (handlerThrew != null) LOG.error(sb.toString(), handlerThrew);
      else LOG.error(sb.toString());
    }
  }

  /**
   * Estimate inbound transfers attributed to this insert.
   *
   * <p>Returns {@code 1} when the request is treated as remote (or when {@code ignoreLocalVsRemote}
   * is {@code true}) and has been accepted; otherwise {@code 0}.
   *
   * @param ignoreLocalVsRemote When {@code true}, treat as remote regardless of origin.
   * @param outwardTransfersPerInsert Ignored for inbound estimates.
   * @param forAccept Indicator for admission vs. sending decisions; does not change this logic.
   * @return Expected inbound transfers (0 or 1).
   */
  @Override
  public synchronized int expectedTransfersIn(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
    if (!accepted) return 0;
    return ((!isLocal()) || ignoreLocalVsRemote) ? 1 : 0;
  }

  /**
   * Estimate outbound transfers attributed to this insert.
   *
   * <p>Returns {@code outwardTransfersPerInsert} when the request is accepted and has not been
   * flagged as {@code notRoutedOnwards}; otherwise {@code 0}.
   *
   * @param ignoreLocalVsRemote When {@code true}, has no effect for outbound estimates.
   * @param outwardTransfersPerInsert Expected number of outbound transfers per insert operation.
   * @param forAccept Indicator for admission vs. sending decisions; does not change this logic.
   * @return Expected outbound transfers.
   */
  @Override
  public synchronized int expectedTransfersOut(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
    if (!accepted) return 0;
    if (notRoutedOnwards) return 0;
    return outwardTransfersPerInsert;
  }

  /**
   * @return {@code true} if this tag represents an SSK insert; {@code false} for CHK.
   */
  @Override
  public boolean isSSK() {
    return ssk;
  }

  /**
   * @return {@code true}; this tag type always represents an insert.
   */
  @Override
  public boolean isInsert() {
    return true;
  }

  /**
   * @return {@code false}; insert tags are not offer replies.
   */
  @Override
  public boolean isOfferReply() {
    return false;
  }
}
