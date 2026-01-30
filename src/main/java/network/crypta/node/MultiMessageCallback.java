package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;

/**
 * Aggregates multiple asynchronous message sends and emits two group-level callbacks.
 *
 * <p>For a set of messages, this class delivers:
 *
 * <ul>
 *   <li>{@code sent(boolean success)} exactly once after all messages have either been sent or
 *       failed to send (e.g., due to disconnect). This ends the "send" phase; completion may still
 *       be pending.
 *   <li>{@code finish(boolean success)} exactly once after all messages have completed (each was
 *       acknowledged or failed). This ends the overall operation.
 * </ul>
 *
 * <p>Both callbacks occur only after {@link #arm()} is called. Call {@link #make()} once for every
 * message, pass the returned {@link AsyncMessageCallback} to the send, then call {@link #arm()} to
 * allow the aggregated callbacks to fire.
 *
 * <p>Thread-safety: All state is guarded by this instance's intrinsic lock. Per-message callbacks
 * may be invoked from I/O or worker threads; overrides of {@link #sent(boolean)} and {@link
 * #finish(boolean)} must be thread-safe and return promptly.
 *
 * <p>Success semantics: the {@code success} argument is {@code true} only if no message reported a
 * send or completion failure; otherwise it is {@code false}.
 *
 * <p>Typical usage:
 *
 * <pre>
 * Message m1 = ...;
 * Message m2 = ...;
 * PeerNode pn = ...;
 * MultiMessageCallback mcb = new MultiMessageCallback() {
 *   &#064;Override
 *   protected void finish(boolean success) {
 *     // All messages finished (acknowledged or failed); see 'success'.
 *   }
 *   &#064;Override
 *   protected void sent(boolean success) {
 *     // All messages have been sent (or failed to send); see 'success'.
 *   }
 * };
 * pn.transport().sendAsync(m1, mcb.make(), ctr);
 * pn.transport().sendAsync(m2, mcb.make(), ctr);
 * mcb.arm();
 * </pre>
 */
public abstract class MultiMessageCallback {

  /**
   * Number of messages that have not yet completed (acknowledged or permanently failed). Guarded by
   * {@code this}.
   */
  private int waiting;

  /** Number of messages that have not yet reported {@link AsyncMessageCallback#sent()}. */
  private int waitingForSend;

  /**
   * {@code true} after {@link #arm()} is called. {@link #finish(boolean)} and {@link
   * #sent(boolean)} are invoked only when armed.
   */
  private boolean armed;

  /**
   * {@code true} if any message failed to send or complete successfully. Aggregated into the
   * overall {@code success} flag.
   */
  private boolean someFailed;

  /**
   * Called once when all messages have completed (each acknowledged or failed).
   *
   * @param success {@code true} if all messages completed successfully; {@code false} otherwise.
   */
  abstract void finish(boolean success);

  /**
   * Called once when all messages have either been sent or failed to send.
   *
   * @param success {@code true} if every message reached the {@code sent()} state without failure;
   *     {@code false} otherwise.
   */
  abstract void sent(boolean success);

  /**
   * Creates and registers a per-message callback.
   *
   * <p>Precondition: {@link #arm()} has not been called. After registering the last message, call
   * {@link #arm()} to allow aggregated callbacks to be delivered.
   *
   * @return a new {@link AsyncMessageCallback} to attach to the message send
   */
  public AsyncMessageCallback make() {
    synchronized (this) {
      assert !armed;
      AsyncMessageCallback cb = new MessageCallbackImpl();
      waiting++;
      waitingForSend++;
      return cb;
    }
  }

  /**
   * Implementation of {@link AsyncMessageCallback} used by {@link #make()}.
   *
   * <p>Updates the enclosing instance's counters under the same monitor and triggers aggregated
   * callbacks when their counters reach zero. Group callbacks are invoked outside the synchronized
   * block to avoid re-entrance.
   */
  private final class MessageCallbackImpl implements AsyncMessageCallback {

    private boolean finished;
    private boolean sent;

    @Override
    public void sent() {
      boolean success;
      synchronized (MultiMessageCallback.this) {
        // Ignore duplicate 'sent' signals or completions already observed.
        if (finished || sent) return;
        sent = true;
        waitingForSend--;
        // Emit the group 'sent' callback only when all messages reported 'sent' and we are armed.
        if (waitingForSend > 0) return;
        if (!armed) return;
        success = !someFailed;
      }
      MultiMessageCallback.this.sent(success);
    }

    @Override
    public void acknowledged() {
      complete(true);
    }

    @Override
    public void disconnected() {
      complete(false);
    }

    @Override
    public void fatalError() {
      complete(false);
    }

    private void complete(boolean success) {
      boolean callSent = false;
      synchronized (MultiMessageCallback.this) {
        // First completion wins for this message; ignore subsequent calls.
        if (finished) return;
        if (!sent) {
          sent = true;
          waitingForSend--;
          if (waitingForSend == 0) callSent = true;
        }
        if (!success) someFailed = true;
        finished = true;
        waiting--;
        // Fire 'finish' only when all messages have completed and we are armed.
        if (!finished()) return;
        if (someFailed) success = false;
      }
      if (callSent) MultiMessageCallback.this.sent(success);
      finish(success);
    }
  }

  /**
   * Arms the aggregator so group callbacks may be delivered.
   *
   * <p>After calling this method, {@link #sent(boolean)} is invoked when all messages have reported
   * {@code sent()}, and {@link #finish(boolean)} is invoked when all messages have completed. If no
   * messages were registered, callbacks may be invoked immediately.
   */
  public void arm() {
    boolean success;
    boolean callSent = false;
    boolean complete;
    synchronized (this) {
      armed = true;
      complete = waiting == 0;
      if (waitingForSend == 0) callSent = true;
      success = !someFailed;
    }
    if (callSent) sent(success);
    if (complete) finish(success);
  }

  /**
   * Indicates whether all messages have completed and the aggregator is armed.
   *
   * @return {@code true} when armed and the number of unfinished messages is zero
   */
  protected final synchronized boolean finished() {
    return armed && waiting == 0;
  }
}
