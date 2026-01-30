package network.crypta.io.comm;

import java.util.ArrayList;
import java.util.List;
import network.crypta.node.PrioRunnable;
import network.crypta.support.PriorityAwareExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Matches inbound {@link Message} instances against a set of criteria.
 *
 * <p>A filter can constrain the expected {@link MessageType}, originating {@link PeerContext}, and
 * one or more named payload fields. It supports timeouts and can be chained with another filter via
 * {@link #or(MessageFilter)}. Callers may either block until a match/timeout using {@link
 * #waitForSignalOrTimeout()} or register an asynchronous {@link AsyncMessageFilterCallback} via
 * {@link #setAsyncCallback(AsyncMessageFilterCallback, ByteCounter)}.
 *
 * <p>Thread safety: instances synchronize on {@code this}. Waiting and signaling use the same
 * monitor so waiters are reliably woken when a match, disconnect, or restart occurs.
 */
public final class MessageFilter {
  private static final Logger LOG = LoggerFactory.getLogger(MessageFilter.class);

  /** Historical CVS Id retained for diagnostics. */
  public static final String VERSION =
      "$Id: MessageFilter.java,v 1.7 2005/08/25 17:28:19 amphibian Exp $";

  private boolean matchedFlag;
  private PeerContext droppedConnection;
  private MessageType type;
  private final List<Object> fields = new ArrayList<>();
  private final List<String> fieldNames = new ArrayList<>();
  private PeerContext source;
  private long timeout;

  /**
   * When {@code true}, the effective timeout is measured from the start of waiting; when {@code
   * false}, it is measured from the time {@link #setTimeout(long)} (or {@link #setNoTimeout()}) was
   * called.
   */
  private boolean timeoutFromWait;

  private long initialTimeout;
  private MessageFilter orFilter;
  private Message message;
  private long oldBootId;
  private AsyncMessageFilterCallback callback;
  private ByteCounter byteCounter;
  private boolean timeoutSet = false;

  private MessageFilter() {
    timeoutFromWait = true;
  }

  /**
   * Creates a new filter with no type, source, or field constraints. The default behavior measures
   * timeouts from the start of waiting.
   *
   * @return a new {@link MessageFilter} instance
   */
  public static MessageFilter create() {
    return new MessageFilter();
  }

  void onStartWaiting(boolean waitFor) {
    synchronized (this) {
      /* Waiting with a callback would race, because onMatched() clears the matched
       * state when a callback is present. A robust design would:
       *  - Mark that the filter is being waited on here.
       *  - Invoke the callback immediately upon match when not waiting.
       *  - Otherwise, defer invoking the callback until waitFor() completes. */
      if (waitFor && callback != null)
        throw new IllegalStateException("Cannot wait on a MessageFilter with a callback!");
      if (!timeoutSet)
        throw new IllegalStateException("No timeout set on filter " + this + "; cannot wait.");
      if (initialTimeout > 0 && timeoutFromWait)
        timeout = System.currentTimeMillis() + initialTimeout;
    }
    if (orFilter != null) orFilter.onStartWaiting(waitFor);
  }

  /**
   * Set whether the timeout is relative to the creation of the filter, or the start of waitFor().
   *
   * @param b If true, the timeout is relative to the time at which setTimeout() was called, if
   *     false, it's relative to the start of waitFor().
   */
  @SuppressWarnings("UnusedReturnValue")
  public MessageFilter setTimeoutRelativeToCreation(boolean b) {
    timeoutFromWait = !b;
    return this;
  }

  /**
   * Sets an absolute expiry relative to now.
   *
   * <p>When multiple filters match the same message, the filter with the earlier expiry is favored.
   *
   * @param timeout time in milliseconds before the filter expires
   * @return this filter instance (for chaining)
   */
  public MessageFilter setTimeout(long timeout) {
    timeoutSet = true;
    initialTimeout = timeout;
    this.timeout = System.currentTimeMillis() + timeout;
    return this;
  }

  /**
   * Disables expiry for this filter. Internally sets the timeout to {@link Long#MAX_VALUE}.
   *
   * @return this filter instance (for chaining)
   */
  public MessageFilter setNoTimeout() {
    timeoutSet = true;
    timeout = Long.MAX_VALUE;
    initialTimeout = 0;
    return this;
  }

  /**
   * Constrains matches to the given message type.
   *
   * @param type expected {@link MessageType}; {@code null} means any type
   * @return this filter instance (for chaining)
   */
  public MessageFilter setType(MessageType type) {
    this.type = type;
    return this;
  }

  /**
   * Constrains matches to messages originating from the given peer. The peer's boot id is captured
   * at the time of setting and used to detect restarts.
   *
   * @param source expected {@link PeerContext}; {@code null} means any source
   * @return this filter instance (for chaining)
   */
  public MessageFilter setSource(PeerContext source) {
    this.source = source;
    if (source != null) oldBootId = source.getBootID();
    return this;
  }

  /**
   * Returns the peer this filter (or chain) is constrained to, if any.
   *
   * @return the constrained source peer, or {@code null}
   */
  public PeerContext getSource() {
    return source;
  }

  /** Convenience overload of {@link #setField(String, Object)} for boolean values. */
  public MessageFilter setField(String fieldName, boolean value) {
    return setField(fieldName, Boolean.valueOf(value));
  }

  /** Convenience overload of {@link #setField(String, Object)} for byte values. */
  public MessageFilter setField(String fieldName, byte value) {
    return setField(fieldName, Byte.valueOf(value));
  }

  /** Convenience overload of {@link #setField(String, Object)} for short values. */
  public MessageFilter setField(String fieldName, short value) {
    return setField(fieldName, Short.valueOf(value));
  }

  /** Convenience overload of {@link #setField(String, Object)} for int values. */
  public MessageFilter setField(String fieldName, int value) {
    return setField(fieldName, Integer.valueOf(value));
  }

  /** Convenience overload of {@link #setField(String, Object)} for long values. */
  public MessageFilter setField(String fieldName, long value) {
    return setField(fieldName, Long.valueOf(value));
  }

  /**
   * Constrains a payload field to an expected value.
   *
   * <p>If a {@link #setType(MessageType) type} has been set, the {@code fieldValue} is validated
   * against the type's declared field type.
   *
   * @param fieldName payload field name
   * @param fieldValue expected value (must be non-null)
   * @return this filter instance (for chaining)
   * @throws IncorrectTypeException if the value type does not match the message specification
   */
  public MessageFilter setField(String fieldName, Object fieldValue) {
    if (type != null && !type.checkType(fieldName, fieldValue)) {
      throw new IncorrectTypeException(
          "Got "
              + fieldValue.getClass()
              + ", expected "
              + type.typeOf(fieldName)
              + " for "
              + type.getName());
    }
    synchronized (fields) {
      final int i = fieldNames.indexOf(fieldName);
      if (i >= 0) {
        fields.set(i, fieldValue);
      } else {
        fieldNames.add(fieldName);
        fields.add(fieldValue);
      }
    }
    return this;
  }

  /**
   * Adds an alternative filter that is evaluated before this one.
   *
   * <p>The resulting chain matches if either the alternate filter or this filter matches. Nest
   * multiple alternates: {@code f1.or(f2.or(f3))}. The right-most filter is tested first; place the
   * most likely match last.
   *
   * @param or the alternate filter; may be {@code null}
   * @return this filter instance (for chaining)
   * @throws IllegalStateException if a different alternate filter was already set
   */
  public MessageFilter or(MessageFilter or) {
    if ((or != null) && (orFilter != null) && or != orFilter) {
      throw new IllegalStateException(
          "Setting a second .or() on the same filter will replace the "
              + "existing one, not add another. "
              + orFilter
              + " would be replaced by "
              + or
              + ".");
    }
    if (or != null && or.initialTimeout != initialTimeout) {
      LOG.error(
          "Message filters being or()ed have different timeouts! This is very dangerous! This is {}"
              + " or is {}",
          this,
          or);
    }
    orFilter = or;
    return this;
  }

  /**
   * Registers an asynchronous callback to be invoked on match, timeout, disconnect, or restart
   * events. When the callback implements {@link SlowAsyncMessageFilterCallback}, the invocation is
   * scheduled on the provided {@link PriorityAwareExecutor} with the priority returned by {@link
   * SlowAsyncMessageFilterCallback#getPriority()}.
   *
   * @param cb callback instance; may be {@code null} to clear
   * @param ctr optional byte counter to receive {@link ByteCounter#receivedBytes(int)} updates on
   *     match
   * @return this filter instance (for chaining)
   */
  @SuppressWarnings("UnusedReturnValue")
  public MessageFilter setAsyncCallback(AsyncMessageFilterCallback cb, ByteCounter ctr) {
    callback = cb;
    byteCounter = ctr;
    return this;
  }

  /** Outcome of {@link #match(Message, long)}. */
  public enum MATCHED {
    /** The message matches all constraints and is within the timeout window. */
    MATCHED,
    /** The filter has expired without a match. */
    TIMED_OUT,
    /** The message matches but the filter expired by the time it was checked. */
    TIMED_OUT_AND_MATCHED,
    /** No match; the filter remains active. */
    NONE
  }

  /**
   * Tests the message against this filter (and any chained {@link #or(MessageFilter)}).
   *
   * @param m message to evaluate
   * @param now current time in milliseconds
   * @return the match outcome
   */
  public MATCHED match(Message m, long now) {
    return match(m, false, now);
  }

  /**
   * Tests the message with an option to suppress the post-match timeout check.
   *
   * <p>When {@code noTimeout} is {@code false}, a message that matches after the filter has expired
   * yields {@link MATCHED#TIMED_OUT_AND_MATCHED}. When {@code true}, the method reports only {@link
   * MATCHED#MATCHED} or a non-match/timeout result from the preliminary checks.
   *
   * @param m message to evaluate
   * @param noTimeout if {@code true}, skip the "matched but expired" check
   * @param now current time in milliseconds
   * @return the match outcome
   */
  public MATCHED match(Message m, boolean noTimeout, long now) {
    if (orFilter != null) {
      MATCHED matched = orFilter.match(m, noTimeout, now);
      if (matched != MATCHED.NONE) return matched; // includes timeouts
    }

    final MATCHED resultNoMatch = timeout < now ? MATCHED.TIMED_OUT : MATCHED.NONE;

    if (isTypeOrSourceMismatch(m)) {
      // Timeout immediately, but don't check the callback, so we still need the periodic check.
      return resultNoMatch;
    }

    if (hasFieldMismatch(m)) {
      return resultNoMatch;
    }

    if (!noTimeout && reallyTimedOut(now)) {
      if (LOG.isDebugEnabled()) LOG.debug("Matched but timed out: {}", this);
      return MATCHED.TIMED_OUT_AND_MATCHED;
    }
    return MATCHED.MATCHED;
  }

  private boolean isTypeOrSourceMismatch(Message m) {
    return (type != null && !type.equals(m.getSpec()))
        || (source != null && !source.equals(m.getSource()));
  }

  private boolean hasFieldMismatch(Message m) {
    synchronized (fields) {
      for (int i = 0; i < fieldNames.size(); i++) {
        final String fieldName = fieldNames.get(i);
        if (!m.isSet(fieldName)) {
          return true;
        }
        final Object fieldValue = fields.get(i);
        final Object messageValue = m.getFromPayload(fieldName);
        // check the cheaper hashCode before the full equals.
        if (fieldValue.hashCode() != messageValue.hashCode() || !fieldValue.equals(messageValue)) {
          return true;
        }
      }
    }
    return false;
  }

  public boolean matched() {
    return matchedFlag;
  }

  /**
   * Returns the peer associated with the most recent disconnect or restart event related to this
   * filter.
   *
   * @return the affected {@link PeerContext}, or {@code null} if none
   */
  public PeerContext droppedConnection() {
    return droppedConnection;
  }

  boolean reallyTimedOut(long time) {
    if (callback != null && callback.shouldTimeout()) timeout = -1; // timeout immediately
    return timeout < time;
  }

  /**
   * Indicates whether the filter should be removed from the active set.
   *
   * @param time current time in milliseconds
   * @return {@code true} if the filter already matched (which is considered an error here) or has
   *     timed out; {@code false} otherwise
   */
  boolean timedOut(long time) {
    if (matchedFlag) {
      LOG.error(
          "Impossible: filter already matched in timedOut(): {}", this, new Exception("error"));
      return true; // Remove it.
    }
    return reallyTimedOut(time);
  }

  /**
   * Returns the last message that matched this filter, if any. The value is set by {@link
   * #setMessage(Message)} and cleared by {@link #clearMatched()}.
   */
  public synchronized Message getMessage() {
    return message;
  }

  /**
   * Records that a message matched this filter and wakes any waiters.
   *
   * <p>Side effects: sets the matched flag and calls {@link #notifyAll()} while holding this
   * instance's monitor.
   *
   * @param message the matched message
   */
  public synchronized void setMessage(Message message) {
    this.message = message;
    // Avoid race conditions where it is removed from the filter list because of a timeout but not
    // woken up.
    matchedFlag = true;
    notifyAll();
  }

  /**
   * Returns the originally requested timeout duration, in milliseconds. A value of {@code 0}
   * indicates that {@link #setNoTimeout()} was used.
   */
  @SuppressWarnings("unused")
  public long getInitialTimeout() {
    return initialTimeout;
  }

  /**
   * Returns the absolute expiration time in milliseconds since the epoch.
   *
   * @return {@link Long#MAX_VALUE} when no timeout is set
   */
  public long getTimeout() {
    return timeout;
  }

  /** Returns a concise description including the message type name. */
  @Override
  public String toString() {
    return super.toString() + ":" + type.getName();
  }

  /**
   * Clears the matched state and propagates to any chained {@link #or(MessageFilter)} filter.
   * Callers use this when reusing a filter instance.
   */
  public void clearMatched() {
    // If the filter matched in an _or, and it is re-used, then
    // we need to clear all the _or's.
    MessageFilter or;
    synchronized (this) {
      matchedFlag = false;
      message = null;
      or = orFilter;
    }
    if (or != null) or.clearMatched();
  }

  /** Removes any previously set alternate filter. */
  public void clearOr() {
    orFilter = null;
  }

  /**
   * Returns {@code true} if the given peer is the one this filter is constrained to (including any
   * chained alternate filter).
   */
  public boolean matchesDroppedConnection(PeerContext ctx) {
    if (source == ctx) return true;
    if (orFilter != null) return orFilter.matchesDroppedConnection(ctx);
    return false;
  }

  /**
   * Returns {@code true} if the given peer is the one this filter is constrained to (including any
   * chained alternate filter). Intended for restart notifications.
   */
  public boolean matchesRestartedConnection(PeerContext ctx) {
    if (source == ctx) return true;
    if (orFilter != null) return orFilter.matchesRestartedConnection(ctx);
    return false;
  }

  /**
   * Notifies waiters and the callback (if any) that the associated peer disconnected.
   *
   * <p>Caller must ensure the event relates to this filter (see {@link
   * #matchesDroppedConnection(PeerContext)}).
   *
   * @param ctx peer that disconnected
   * @param executor executor used when the callback is {@link SlowAsyncMessageFilterCallback}
   */
  public void onDroppedConnection(final PeerContext ctx, PriorityAwareExecutor executor) {
    final AsyncMessageFilterCallback cb;
    synchronized (this) {
      cb = callback;
      droppedConnection = ctx;
      notifyAll();
      byteCounter = null;
    }
    if (cb != null) {
      if (cb instanceof SlowAsyncMessageFilterCallback slowCallback) {
        executor.execute(
            new PrioRunnable() {

              @Override
              public void run() {
                cb.onDisconnect(ctx);
              }

              @Override
              public int getPriority() {
                return slowCallback.getPriority();
              }
            });
      } else {
        cb.onDisconnect(ctx);
      }
    }
  }

  /**
   * Notifies waiters and the callback (if any) that the associated peer restarted.
   *
   * <p>Caller must ensure the event relates to this filter (see {@link
   * #matchesRestartedConnection(PeerContext)}).
   *
   * @param ctx peer that restarted
   * @param executor executor used when the callback is {@link SlowAsyncMessageFilterCallback}
   */
  public void onRestartedConnection(final PeerContext ctx, PriorityAwareExecutor executor) {
    final AsyncMessageFilterCallback cb;
    synchronized (this) {
      droppedConnection = ctx;
      cb = callback;
      notifyAll();
      byteCounter = null;
    }
    if (cb != null) {
      if (cb instanceof SlowAsyncMessageFilterCallback slowCallback) {
        executor.execute(
            new PrioRunnable() {

              @Override
              public void run() {
                cb.onRestarted(ctx);
              }

              @Override
              public int getPriority() {
                return slowCallback.getPriority();
              }
            });
      } else {
        cb.onRestarted(ctx);
      }
    }
  }

  /**
   * Notifies waiters that the filter matched and invokes the callback if present.
   *
   * <p>If the callback implements {@link SlowAsyncMessageFilterCallback}, the invocation is
   * scheduled on the supplied {@link PriorityAwareExecutor}; otherwise it is called inline.
   */
  public void onMatched(PriorityAwareExecutor executor) {
    final Message msg;
    final AsyncMessageFilterCallback cb;
    ByteCounter ctr;
    synchronized (this) {
      msg = message;
      cb = callback;
      ctr = byteCounter;
      // Clear matched before calling callback in case we are re-added.
      if (callback != null) clearMatched();
    }
    if (cb != null) {
      if (cb instanceof SlowAsyncMessageFilterCallback slowCallback)
        executor.execute(
            new PrioRunnable() {

              @Override
              public void run() {
                cb.onMatched(msg);
              }

              @Override
              public int getPriority() {
                return slowCallback.getPriority();
              }
            },
            "Slow callback for " + cb);
      else cb.onMatched(msg);
      if (ctr != null) ctr.receivedBytes(msg.receivedByteCount());
    }
  }

  /** Notifies waiters and the callback (if any) that the filter timed out. */
  public void onTimedOut(PriorityAwareExecutor executor) {
    final AsyncMessageFilterCallback cb;
    synchronized (this) {
      notifyAll();
      cb = callback;
    }
    if (cb != null) {
      if (cb instanceof SlowAsyncMessageFilterCallback slowCallback) {
        executor.execute(
            new PrioRunnable() {

              @Override
              public void run() {
                cb.onTimeout();
              }

              @Override
              public int getPriority() {
                return slowCallback.getPriority();
              }
            });
      } else cb.onTimeout();
    }
  }

  /** Returns {@code true} if the constrained connection is dropped or has restarted. */
  public boolean anyConnectionsDropped() {
    if (matchedFlag) return false;
    if (source != null) {
      if (!source.isConnected()) return true;
      if (source.getBootID() != oldBootId) return true; // Counts as a disconnect.
    }
    if (orFilter != null) return orFilter.anyConnectionsDropped();
    return false;
  }

  /** Indicates whether a callback is registered. */
  public synchronized boolean hasCallback() {
    return callback != null;
  }

  /**
   * Block on this filter's monitor until a message is matched, the peer is dropped/restarted, or
   * the filter times out. This encapsulates the wait/notify pattern so callers don't need to
   * synchronize on the filter reference directly.
   *
   * <p>Threading: Uses this filter instance as the monitor. Matching and connection events call
   * {@link #notifyAll()} while holding the same monitor, so waiting here is woken reliably.
   *
   * @return the matched {@link Message}, or null if the filter timed out.
   * @throws DisconnectedException if the associated peer disconnects or restarts while waiting.
   */
  Message waitForSignalOrTimeout() throws DisconnectedException {
    synchronized (this) {
      try {
        long now;
        while (true) {
          now = System.currentTimeMillis();
          if (matchedFlag || droppedConnection != null || reallyTimedOut(now)) {
            break;
          }
          long wait = timeout - now;
          if (wait <= 0) break;
          this.wait(wait);
        }
        if (droppedConnection != null) throw new DisconnectedException();
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
      }
      return message;
    }
  }
}
