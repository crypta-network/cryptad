package network.crypta.io.comm;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;
import network.crypta.io.comm.MessageFilter.MATCHED;
import network.crypta.node.PeerNode;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates matching of inbound messages against waiting filters and, when no filter matches,
 * hands messages to an optional {@link Dispatcher}. Keeps a bounded FIFO of unclaimed messages so
 * late-registered filters can still match recently received messages. Also schedules periodic
 * cleanup to remove expired filters.
 *
 * <p>Thread-safety: the {@code filters} list is used as the monitor protecting both the filter list
 * itself and the {@code unclaimed} queue. All mutations of either structure synchronize on {@code
 * filters}. Public methods are safe to call from concurrent threads.
 */
public class MessageCore {
  private static final Logger LOG = LoggerFactory.getLogger(MessageCore.class);
  private static final String UNCLAIMED_FIFO_MSG_PREFIX = "ms with unclaimedFIFOSize of ";
  private static final String DROP_UNCLAIMED_OVERFLOW_FROM =
      "Dropping unclaimed (fifo overflow) from ";
  private static final String DROP_UNCLAIMED_OVERFLOW_LIVED =
      "Dropping unclaimed (fifo overflow), lived ";
  private static final String DROP_UNCLAIMED_EXPIRED_ASYNC_FROM =
      "Dropping expired unclaimed (async scan) from ";
  private static final String DROP_UNCLAIMED_EXPIRED_ASYNC_LIVED =
      "Dropping expired unclaimed (async scan), lived ";
  private static final String DROP_UNCLAIMED_EXPIRED_WAITFOR_FROM =
      "Dropping expired unclaimed (waitFor scan) from ";
  private static final String DROP_UNCLAIMED_EXPIRED_WAITFOR_LIVED =
      "Dropping expired unclaimed (waitFor scan), lived ";
  private static final String LIVED = ", lived ";
  private static final String AGE_SUFFIX = "{} (age): {}";

  /** Legacy revision identifier retained for compatibility with external tools. */
  public static final String VERSION =
      "$Id: MessageCore.java,v 1.22 2005/08/25 17:28:19 amphibian Exp $";

  // No static initialization required.

  private Dispatcher dispatcher;
  private final PriorityAwareExecutor executor;

  /**
   * Serves both as the filter list and the lock protecting itself and {@link #unclaimed}. Acquire
   * this monitor before mutating either structure.
   */
  private final LinkedList<MessageFilter> filters = new LinkedList<>();

  private final LinkedList<Message> unclaimed = new LinkedList<>();
  private static final int MAX_UNMATCHED_FIFO_SIZE = 50000;
  private static final long MAX_UNCLAIMED_FIFO_ITEM_LIFETIME =
      MINUTES.toMillis(10); // Applied uniformly to all message types.
  // MIN_FILTER_REMOVE_TIME avoids overly tight rescheduling; near-minimum timeouts may be rounded.
  private static final long MAX_FILTER_REMOVE_TIME = SECONDS.toMillis(10);
  private static final long MIN_FILTER_REMOVE_TIME = SECONDS.toMillis(1);
  private long startedTime;

  /**
   * Returns the epoch time in milliseconds when {@link #start(Ticker)} was invoked.
   *
   * @return start time in epoch milliseconds, or {@code 0} if not started
   */
  public synchronized long getStartedTime() {
    return startedTime;
  }

  /**
   * Creates a new core bound to the given executor for running callbacks.
   *
   * @param executor executor used for the filter callbacks and related tasks
   */
  public MessageCore(PriorityAwareExecutor executor) {
    this.executor = executor;
  }

  /**
   * Decodes a single message from the provided packet segment.
   *
   * <p>On failure, this method logs the error and returns {@code null}.
   *
   * @param data backing array containing packet bytes
   * @param offset starting offset into {@code data}
   * @param length number of bytes to decode
   * @param peer sending peer context
   * @param overhead decoder-specific parameter forwarded to {@link
   *     Message#decodeMessageFromPacket(byte[], int, int, PeerContext, int)}
   * @return decoded message, or {@code null} if decoding fails
   */
  public Message decodeSingleMessage(
      byte[] data, int offset, int length, PeerContext peer, int overhead) {
    try {
      return Message.decodeMessageFromPacket(data, offset, length, peer, overhead);
    } catch (Exception t) {
      LOG.error("Could not decode packet: {}", t, t);
      return null;
    }
  }

  /**
   * Starts periodic maintenance and records the start time.
   *
   * <p>Schedules recurring removal of timed-out filters using the supplied {@link Ticker}. Intended
   * to be called once during initialization.
   *
   * @param ticker scheduler used for maintenance tasks
   */
  public void start(final Ticker ticker) {
    synchronized (this) {
      startedTime = System.currentTimeMillis();
    }
    ticker.queueTimedJob(
        new Runnable() {

          @Override
          public void run() {
            long now = System.currentTimeMillis();
            long nextRun = now + MAX_FILTER_REMOVE_TIME;
            try {
              nextRun = removeTimedOutFilters(nextRun);
            } catch (Exception t) {
              LOG.error("Failed to remove timed out filters: {}", t, t);
            } finally {
              ticker.queueTimedJob(
                  this, Math.max(MIN_FILTER_REMOVE_TIME, nextRun - System.currentTimeMillis()));
            }
          }
        },
        MIN_FILTER_REMOVE_TIME);
  }

  /** Removes timed-out filters and returns the next timeout to schedule against. */
  long removeTimedOutFilters(long nextTimeout) {
    long tStart = System.currentTimeMillis() + 1;
    // Add 1 ms so a waitFor() that just observed the timeout has a chance to remove the filter,
    // reducing redundant scanning.
    if (LOG.isDebugEnabled()) LOG.debug("Removing timed out filters");

    Set<MessageFilter> timedOutFilters = new HashSet<>();
    nextTimeout = scanAndCollectTimedOutFilters(nextTimeout, tStart, timedOutFilters);

    if (!timedOutFilters.isEmpty()) {
      notifyTimedOutFilters(timedOutFilters);
    }

    logRemoveTimedDuration(tStart);
    return nextTimeout;
  }

  private long scanAndCollectTimedOutFilters(
      long nextTimeout, long tStart, Set<MessageFilter> timedOutFilters) {
    synchronized (filters) {
      for (ListIterator<MessageFilter> i = filters.listIterator(); i.hasNext(); ) {
        MessageFilter f = i.next();
        if (f.timedOut(tStart)) {
          i.remove();
          handleTimedOutFilter(f, timedOutFilters, tStart);
        } else {
          nextTimeout = updateNextTimeoutIfCallback(nextTimeout, f);
        }
        // Do not stop at the first non-expired filter. Callback logic can independently mark
        // filters as timed out, so scan all entries. See the end of waitFor() for a related race.
      }
    }
    return nextTimeout;
  }

  private void handleTimedOutFilter(
      MessageFilter f, Set<MessageFilter> timedOutFilters, long tStart) {
    if (LOG.isDebugEnabled()) LOG.debug("Removing {}", f);
    if (!timedOutFilters.add(f)) {
      LOG.error("Filter {} is in filter list twice!", f);
    }
    if (LOG.isDebugEnabled()) {
      logIfUnclaimedWouldMatch(f, tStart);
    }
  }

  private long updateNextTimeoutIfCallback(long nextTimeout, MessageFilter f) {
    if (f.hasCallback() && nextTimeout > f.getTimeout()) {
      return f.getTimeout();
    }
    return nextTimeout;
  }

  private void logIfUnclaimedWouldMatch(MessageFilter f, long tStart) {
    for (Message m : unclaimed) {
      MATCHED status = f.match(m, true, tStart);
      if (status == MATCHED.MATCHED) {
        // Don't match it, we timed out; two-level timeouts etc. may want it for the next filter.
        LOG.error("Timed out but should have matched in _unclaimed: {} for {}", m, f);
        break;
      }
    }
  }

  private void notifyTimedOutFilters(Set<MessageFilter> timedOutFilters) {
    for (MessageFilter f : timedOutFilters) {
      f.setMessage(null);
      f.onTimedOut(executor);
    }
  }

  private void logRemoveTimedDuration(long tStart) {
    long tEnd = System.currentTimeMillis();
    if (tEnd - tStart > 50) {
      if (tEnd - tStart > 3000) {
        LOG.error("removeTimedOutFilters took {}ms", tEnd - tStart);
      } else if (LOG.isDebugEnabled()) {
        LOG.debug("removeTimedOutFilters took {}ms", tEnd - tStart);
      }
    }
  }

  /**
   * Attempts to deliver an inbound message to a waiting filter; if none match, optionally hands it
   * to the {@link Dispatcher}. If still unmatched, queues the message in the unclaimed FIFO so a
   * later filter can pick it up.
   *
   * @param m inbound message
   * @param from socket handler (used for debug logging)
   */
  public void checkFilters(Message m, PacketSocketHandler from) {
    long tStart = System.currentTimeMillis();
    logInbound(m, from);

    FilterScanResult initial = scanFiltersForMatch(m, tStart);
    boolean matched = initial.matched;
    MessageFilter match = initial.match;
    if (initial.timedOut != null) notifyTimedOutList(initial.timedOut);
    if (match != null) match.onMatched(executor);

    matched = dispatchIfUnmatched(m, matched);

    // Keep a small window of unclaimed messages so late-registered filters can still match them.
    if (!matched) {
      if (LOG.isDebugEnabled()) LOG.debug("Unclaimed: {}", m);
      RecheckResult recheck = recheckFiltersAndMaybeQueue(m, tStart);
      if (recheck.match != null) recheck.match.onMatched(executor);
      if (recheck.timedOut != null) notifyTimedOutList(recheck.timedOut);
      matched = recheck.matched;
    }

    logCheckFiltersDuration(tStart, matched);
  }

  private void logInbound(Message m, PacketSocketHandler from) {
    if (LOG.isDebugEnabled()) LOG.debug("checkFilters: {} from {}", m, m.getSource());
    if (m.getSource() instanceof PeerNode peerNode) {
      peerNode.incrementReceivedMessageType(m.getSpec().getName());
    }
    if (LOG.isDebugEnabled() && !m.getSpec().equals(DMT.packetTransmit)) {
      LOG.debug("{} {} <- {} : {}", System.currentTimeMillis() % 60000, from, m.getSource(), m);
    }
  }

  @SuppressWarnings("java:S1181") // We really do want to catch Throwable here
  private boolean dispatchIfUnmatched(Message m, boolean matched) {
    if (!matched && dispatcher != null) {
      try {
        if (LOG.isDebugEnabled()) LOG.debug("Feeding to dispatcher: {}", m);
        return dispatcher.handleMessage(m);
      } catch (Throwable t) {
        LOG.error("Dispatcher threw {}", t, t);
      }
    }
    return matched;
  }

  private void notifyTimedOutList(List<MessageFilter> timedOut) {
    for (MessageFilter f : timedOut) {
      if (LOG.isDebugEnabled()) LOG.debug("Timed out {}", f);
      f.setMessage(null);
      f.onTimedOut(executor);
    }
  }

  private void logCheckFiltersDuration(long tStart, boolean matched) {
    long tEnd = System.currentTimeMillis();
    long dT = tEnd - tStart;
    if (dT > 50) {
      if (dT > 3000) {
        LOG.error(
            "checkFilters took {}" + UNCLAIMED_FIFO_MSG_PREFIX + "{} for matched: {}",
            dT,
            unclaimed.size(),
            matched);
      } else if (LOG.isDebugEnabled()) {
        LOG.debug(
            "checkFilters took {}" + UNCLAIMED_FIFO_MSG_PREFIX + "{} for matched: {}",
            dT,
            unclaimed.size(),
            matched);
      }
    }
  }

  private record FilterScanResult(
      boolean matched, MessageFilter match, List<MessageFilter> timedOut) {}

  private FilterScanResult scanFiltersForMatch(Message m, long tStart) {
    boolean matched = false;
    MessageFilter match = null;
    List<MessageFilter> timedOut = new ArrayList<>();
    synchronized (filters) {
      for (ListIterator<MessageFilter> i = filters.listIterator(); i.hasNext(); ) {
        MessageFilter f = i.next();
        if (f.matched()) {
          LOG.error("removed pre-matched message filter found in filters: {}", f);
          i.remove();
        } else {
          MessageFilter matchedFilter = evaluateFilterForMatch(m, tStart, i, f, timedOut);
          if (matchedFilter != null) {
            matched = true;
            match = matchedFilter;
            break; // Only one match permitted per message
          }
        }
      }
    }
    return new FilterScanResult(matched, match, timedOut.isEmpty() ? null : timedOut);
  }

  private MessageFilter evaluateFilterForMatch(
      Message m,
      long tStart,
      ListIterator<MessageFilter> i,
      MessageFilter f,
      List<MessageFilter> timedOut) {
    MATCHED status = f.match(m, false, tStart);
    switch (status) {
      case TIMED_OUT, TIMED_OUT_AND_MATCHED -> {
        timedOut.add(f);
        i.remove();
        return null;
      }
      case MATCHED -> {
        i.remove();
        // Set the message while holding the monitor so a concurrent waitFor() that is about to
        // time out can still observe the match.
        f.setMessage(m);
        if (LOG.isDebugEnabled()) LOG.debug("scanFilters: matched filter {}", f);
        return f;
      }
      case NONE -> {
        if (LOG.isDebugEnabled()) LOG.debug("Did not match {}", f);
        return null;
      }
      case null, default -> {
        if (LOG.isDebugEnabled()) LOG.debug("Did not match {}", f);
        return null;
      }
    }
  }

  private record RecheckResult(
      boolean matched, MessageFilter match, List<MessageFilter> timedOut) {}

  private RecheckResult recheckFiltersAndMaybeQueue(Message m, long tStart) {
    synchronized (filters) {
      if (LOG.isDebugEnabled()) LOG.debug("Rechecking filters and adding message");
      FilterScanResult scan = scanRecheckFilters(m, tStart);
      if (!scan.matched) {
        queueUnclaimed(m);
      }
      return new RecheckResult(scan.matched, scan.match, scan.timedOut);
    }
  }

  private FilterScanResult scanRecheckFilters(Message m, long tStart) {
    boolean matched = false;
    MessageFilter match = null;
    List<MessageFilter> timedOut = null;
    for (ListIterator<MessageFilter> i = filters.listIterator(); i.hasNext(); ) {
      MessageFilter f = i.next();
      MATCHED status = f.match(m, false, tStart);
      if (status == MATCHED.MATCHED) {
        matched = true;
        match = f;
        i.remove();
        if (LOG.isDebugEnabled()) LOG.debug("recheckFilters: matched filter {}", f);
        match.setMessage(m);
        break; // Only one match permitted per message
      } else if (status == MATCHED.TIMED_OUT || status == MATCHED.TIMED_OUT_AND_MATCHED) {
        if (timedOut == null) timedOut = new ArrayList<>();
        timedOut.add(f);
        i.remove();
      }
    }
    return new FilterScanResult(matched, match, timedOut);
  }

  private void queueUnclaimed(Message m) {
    while (unclaimed.size() > MAX_UNMATCHED_FIFO_SIZE) {
      Message removed = unclaimed.removeFirst();
      long messageLifeTime = System.currentTimeMillis() - removed.localInstantiationTime;
      if (LOG.isInfoEnabled()) {
        String lived = TimeUtil.formatTime(messageLifeTime, 2, true);
        if (removed.getSource() instanceof PeerNode) {
          LOG.info(
              DROP_UNCLAIMED_OVERFLOW_FROM + "{}" + LIVED + "{} (quantity): {}",
              removed.getSource().getPeer(),
              lived,
              removed);
        } else {
          LOG.info(DROP_UNCLAIMED_OVERFLOW_LIVED + "{} (quantity): {}", lived, removed);
        }
      }
    }
    unclaimed.addLast(m);
    if (LOG.isDebugEnabled()) LOG.debug("Done");
  }

  /**
   * Notifies the core that a peer disconnected.
   *
   * <p>Removes any waiting filters bound to {@code ctx} that report a dropped connection and
   * invokes their {@code onDroppedConnection} callbacks on the executor.
   *
   * @param ctx context for the disconnected peer
   */
  public void onDisconnect(PeerContext ctx) {
    ArrayList<MessageFilter> droppedFilters =
        null; // A rare operation, we can waste objects for better locking
    synchronized (filters) {
      ListIterator<MessageFilter> i = filters.listIterator();
      while (i.hasNext()) {
        MessageFilter f = i.next();
        if (f.matchesDroppedConnection(ctx)) {
          if (droppedFilters == null) droppedFilters = new ArrayList<>();
          droppedFilters.add(f);
          i.remove();
        }
      }
    }
    if (droppedFilters != null) {
      for (MessageFilter mf : droppedFilters) {
        mf.onDroppedConnection(ctx, executor);
      }
    }
  }

  /**
   * Notifies the core that a peer reconnected with a new boot ID.
   *
   * <p>Removes filters associated with {@code ctx} that consider a restart a terminal condition and
   * invokes their {@code onRestartedConnection} callbacks on the executor.
   *
   * @param ctx context for the restarted peer
   */
  public void onRestart(PeerContext ctx) {
    ArrayList<MessageFilter> droppedFilters =
        null; // A rare operation, we can waste objects for better locking
    synchronized (filters) {
      ListIterator<MessageFilter> i = filters.listIterator();
      while (i.hasNext()) {
        MessageFilter f = i.next();
        if (f.matchesRestartedConnection(ctx)) {
          if (droppedFilters == null) droppedFilters = new ArrayList<>();
          droppedFilters.add(f);
          i.remove();
        }
      }
    }
    if (droppedFilters != null) {
      for (MessageFilter mf : droppedFilters) {
        mf.onRestartedConnection(ctx, executor);
      }
    }
  }

  /**
   * Registers a filter with an asynchronous callback.
   *
   * <p>First scans the {@code unclaimed} queue for an immediate match; otherwise inserts the filter
   * ordered by timeout. If the relevant connection has already dropped, the filter is not added and
   * a {@link DisconnectedException} is thrown.
   *
   * @param filter filter to register
   * @param callback callback invoked on match or timeout
   * @param ctr byte counter updated with received payload sizes
   * @throws DisconnectedException if the connection tracked by the filter is already dropped
   */
  public void addAsyncFilter(
      MessageFilter filter, AsyncMessageFilterCallback callback, ByteCounter ctr)
      throws DisconnectedException {
    filter.setAsyncCallback(callback, ctr);
    if (filter.matched()) {
      LOG.error(
          "addAsyncFilter() on a filter which is already matched: {}",
          filter,
          new Exception("error"));
      filter.clearMatched();
    }
    filter.onStartWaiting(false);
    if (LOG.isDebugEnabled()) LOG.debug("Adding async filter {} for {}", filter, callback);
    Message ret;
    if (filter.anyConnectionsDropped()) {
      throw new DisconnectedException();
    }
    // Scan recently received but unclaimed messages first. Drop unclaimed entries older than
    // MAX_UNCLAIMED_FIFO_ITEM_LIFETIME.
    long now = System.currentTimeMillis();
    long messageDropTime = now - MAX_UNCLAIMED_FIFO_ITEM_LIFETIME;
    long timeout = filter.getTimeout();
    synchronized (filters) {
      // Once in the list, it is up to the callback system to trigger the disconnection; however,
      // we may have disconnected between check above and locking, so we must check again.
      if (filter.anyConnectionsDropped()) {
        throw new DisconnectedException();
      }
      if (LOG.isDebugEnabled()) LOG.debug("addAsyncFilter: checking unclaimed queue");
      ret = tryMatchUnclaimedForAsync(filter, now, messageDropTime);
      if (ret == null && timeout >= System.currentTimeMillis()) {
        if (LOG.isDebugEnabled()) LOG.debug("addAsyncFilter: no match in unclaimed queue");
        insertFilterOrdered(filter, timeout);
        return;
      }
    }
    if (ret != null) {
      filter.setMessage(ret);
      filter.onMatched(executor);
      filter.clearMatched();
    } else {
      filter.onTimedOut(executor);
    }
  }

  private Message tryMatchUnclaimedForAsync(MessageFilter filter, long now, long messageDropTime) {
    for (ListIterator<Message> i = unclaimed.listIterator(); i.hasNext(); ) {
      Message m = i.next();
      // These messages have already arrived, so we can match against them even if we are timed out.
      MATCHED status = filter.match(m, true, now);
      if (status == MATCHED.MATCHED) {
        i.remove();
        if (LOG.isDebugEnabled()) LOG.debug("addAsyncFilter: matched in unclaimed queue");
        return m;
      } else if (m.localInstantiationTime < messageDropTime) {
        i.remove();
        long messageLifeTime = now - m.localInstantiationTime;
        if (LOG.isInfoEnabled()) {
          String lived = TimeUtil.formatTime(messageLifeTime, 2, true);
          if (m.getSource() instanceof PeerNode) {
            LOG.info(
                DROP_UNCLAIMED_EXPIRED_ASYNC_FROM + "{}" + LIVED + AGE_SUFFIX,
                m.getSource().getPeer(),
                lived,
                m);
          } else {
            LOG.info(DROP_UNCLAIMED_EXPIRED_ASYNC_LIVED + AGE_SUFFIX, lived, m);
          }
        }
      }
    }
    return null;
  }

  private void insertFilterOrdered(MessageFilter filter, long timeout) {
    ListIterator<MessageFilter> i = filters.listIterator();
    boolean inserted = false;
    while (i.hasNext()) {
      MessageFilter mf = i.next();
      if (mf.getTimeout() > timeout) {
        i.previous();
        i.add(filter);
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Added in middle - mf timeout={} - my timeout={}",
              mf.getTimeout(),
              filter.getTimeout());
        inserted = true;
        break;
      }
    }
    if (!inserted) {
      i.add(filter);
      if (LOG.isDebugEnabled()) LOG.debug("Added at end");
    }
  }

  /**
   * Waits synchronously for a filter to match, time out, or be invalidated by a disconnect.
   *
   * <p>If a matching message is already present in the {@code unclaimed} queue, it is returned
   * immediately. Otherwise, this call blocks until one of the following occurs: a message matches
   * the filter, the filter's timeout elapses (returns {@code null}), or a relevant connection is
   * dropped (throws {@link DisconnectedException}).
   *
   * @param filter filter to wait on; must not have a callback
   * @param ctr byte counter updated with the size of the received message
   * @return the matching message, or {@code null} if the wait timed out
   * @throws DisconnectedException if the peer associated with the filter disconnects
   * @throws IllegalArgumentException if {@code filter} has a callback
   */
  public Message waitFor(MessageFilter filter, ByteCounter ctr) throws DisconnectedException {
    if (LOG.isTraceEnabled()) LOG.trace("Waiting for {}", filter);

    if (filter.hasCallback()) {
      throw new IllegalArgumentException("waitFor called with a filter that has a callback");
    }

    long startTime = System.currentTimeMillis();
    if (filter.matched()) {
      LOG.error(
          "waitFor() on a filter which is already matched: {}", filter, new Exception("error"));
      filter.clearMatched();
    }
    filter.onStartWaiting(true);
    Message ret;
    if (filter.anyConnectionsDropped()) {
      filter.onDroppedConnection(filter.droppedConnection(), executor);
      throw new DisconnectedException();
    }
    long scanStart = System.currentTimeMillis();
    ret = scanUnclaimedAndMaybeInsert(filter, startTime);
    long scanEnd = System.currentTimeMillis();
    logWaitForUnclaimedDuration(scanStart, scanEnd, ret);
    // Release the outer monitor before blocking on the filter; waiting on the filter does not
    // release this class's lock.
    if (ret == null) {
      ret = waitOnFilter(filter);
      if (LOG.isDebugEnabled()) LOG.debug("Returning {} from {}", ret, filter);
    }

    // Post-wait cleanup while holding the monitor again.

    ret = finalizeWaitAndRemoveFilter(filter, ret);

    // Accounting and return value.
    long endTime = System.currentTimeMillis();
    if (LOG.isTraceEnabled()) LOG.trace("Returning in {}ms", endTime - startTime);
    if ((ctr != null) && (ret != null)) ctr.receivedBytes(ret.receivedByteCount());
    return ret;
  }

  private Message scanUnclaimedAndMaybeInsert(MessageFilter filter, long startTime) {
    Message ret = null;
    synchronized (filters) {
      if (LOG.isDebugEnabled()) LOG.debug("waitFor: checking unclaimed queue");
      long now = System.currentTimeMillis();
      long messageDropTime = now - MAX_UNCLAIMED_FIFO_ITEM_LIFETIME;
      for (ListIterator<Message> i = unclaimed.listIterator(); i.hasNext(); ) {
        Message m = i.next();
        ret = handleUnclaimedCandidate(filter, startTime, now, messageDropTime, i, m);
        if (ret != null) break;
      }
      if (ret == null) {
        if (LOG.isDebugEnabled()) LOG.debug("waitFor: no match in unclaimed queue");
        insertFilterOrdered(filter, filter.getTimeout());
      }
    }
    return ret;
  }

  private Message handleUnclaimedCandidate(
      MessageFilter filter,
      long startTime,
      long now,
      long messageDropTime,
      ListIterator<Message> iterator,
      Message message) {
    MATCHED status = filter.match(message, true, startTime);
    if (status == MATCHED.MATCHED) {
      iterator.remove();
      if (LOG.isDebugEnabled()) LOG.debug("waitFor: matched in unclaimed queue");
      return message;
    }
    if (isExpired(message, messageDropTime)) {
      iterator.remove();
      logDroppedUnclaimed(message, now);
    }
    return null;
  }

  private static boolean isExpired(Message m, long messageDropTime) {
    return m.localInstantiationTime < messageDropTime;
  }

  private void logDroppedUnclaimed(Message m, long now) {
    long messageLifeTime = now - m.localInstantiationTime;
    if (LOG.isInfoEnabled()) {
      String lived = TimeUtil.formatTime(messageLifeTime, 2, true);
      if (m.getSource() instanceof PeerNode) {
        LOG.info(
            DROP_UNCLAIMED_EXPIRED_WAITFOR_FROM + "{}" + LIVED + AGE_SUFFIX,
            m.getSource().getPeer(),
            lived,
            m);
      } else {
        LOG.info(DROP_UNCLAIMED_EXPIRED_WAITFOR_LIVED + AGE_SUFFIX, lived, m);
      }
    }
  }

  private void logWaitForUnclaimedDuration(long start, long end, Message ret) {
    if (end - start > 50) {
      if (end - start > 3000)
        LOG.error(
            "waitFor _unclaimed iteration took {}" + UNCLAIMED_FIFO_MSG_PREFIX + "{} for ret of {}",
            end - start,
            unclaimed.size(),
            ret);
      else if (LOG.isDebugEnabled())
        LOG.debug(
            "waitFor _unclaimed iteration took {}" + UNCLAIMED_FIFO_MSG_PREFIX + "{} for ret of {}",
            end - start,
            unclaimed.size(),
            ret);
    }
  }

  private Message waitOnFilter(MessageFilter filter) throws DisconnectedException {
    if (LOG.isDebugEnabled()) LOG.debug("Waiting...");
    return filter.waitForSignalOrTimeout();
  }

  private Message finalizeWaitAndRemoveFilter(MessageFilter filter, Message ret) {
    synchronized (filters) {
      // Some nasty race conditions can happen here.
      // E.g., the filter can be matched, and yet we time out at the same time.
      // Hence, we need to be sure that when we remove it, it hasn't been matched.
      // Note also that the locking does work here - the filter lock is taken last, and
      // filters protect both the unwanted messages, the filter list, and are taken when a match is
      // found too.
      if (ret == null && filter.matched()) {
        ret = filter.getMessage();
      }
      filter.clearMatched();
      // We must remove it from filters before we return, or when it is re-added,
      // it will be in the list twice, and potentially many more times than twice!
      // Fortunately, it will be close to the beginning of the filters list, having just timed out.
      // That is assuming it hasn't already been removed; in that case, this will be slower.
      filters.remove(filter);
      // A filter being waitFor()'ed cannot have any callbacks, so we don't need to call
      // onMatched().
    }
    return ret;
  }

  /**
   * Sends a message to a peer asynchronously.
   *
   * <p>Internal-only messages (as indicated by the {@code MessageSpec}) are not sent and are logged
   * at error level.
   *
   * @param destination target peer context
   * @param m message to send
   * @param ctr byte counter for sent payload accounting
   * @throws NotConnectedException if the destination is not currently connected
   */
  public void send(PeerContext destination, Message m, ByteCounter ctr)
      throws NotConnectedException {
    if (m.getSpec().isInternalOnly()) {
      LOG.error(
          "Trying to send internal-only message {} of spec {}",
          m,
          m.getSpec(),
          new Exception("debug"));
      return;
    }
    destination.transport().sendAsync(m, null, ctr);
  }

  /**
   * Sets the dispatcher that receives messages not claimed by any filter. Configure during
   * initialization before concurrent calls to {@link #checkFilters(Message, PacketSocketHandler)}.
   *
   * @param d dispatcher to receive unmatched messages; {@code null} disables dispatching
   */
  public void setDispatcher(Dispatcher d) {
    dispatcher = d;
  }

  /** Returns the current number of messages held in the unclaimed FIFO. */
  public int getUnclaimedFIFOSize() {
    synchronized (filters) {
      return unclaimed.size();
    }
  }

  /**
   * Returns a snapshot of unclaimed message counts grouped by message name.
   *
   * @return a new map keyed by message spec name with counts of unclaimed entries
   */
  public Map<String, Integer> getUnclaimedFIFOMessageCounts() {
    Map<String, Integer> messageCounts = new HashMap<>();
    synchronized (filters) {
      for (Message m : unclaimed) {
        String messageName = m.getSpec().getName();
        Integer messageCount = messageCounts.get(messageName);
        if (messageCount == null) {
          messageCounts.put(messageName, 1);
        } else {
          messageCount = messageCount + 1;
          messageCounts.put(messageName, messageCount);
        }
      }
    }
    return messageCounts;
  }

  /** Returns the executor used for running filter callbacks. */
  public PriorityAwareExecutor getExecutor() {
    return executor;
  }
}
