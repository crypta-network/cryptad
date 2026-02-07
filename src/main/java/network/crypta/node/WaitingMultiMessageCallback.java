package network.crypta.node;

/**
 * Multi-message aggregator that supports synchronous waiting for completion.
 *
 * <p>This implementation provides {@link #waitFor()} to block the current thread until the
 * aggregated operation has finished (i.e., after {@link #finish(boolean)} is invoked and {@link
 * #finished()} returns {@code true}). The intermediate group event {@link #sent(boolean)} is
 * intentionally ignored.
 *
 * <p>Thread-safety: All methods synchronize in this instance. Waiters call {@link #waitFor()}, and
 * completion notifies them via {@code notifyAll()} on the same monitor.
 *
 * <p>Usage overview:
 *
 * <ol>
 *   <li>Create the callback and register per-message callbacks via {@link #make()} on the
 *       superclass.
 *   <li>Call {@link #arm()} to allow group callbacks.
 *   <li>Call {@link #waitFor()} to block until the overall operation completes.
 * </ol>
 */
public class WaitingMultiMessageCallback extends MultiMessageCallback {

  private boolean completionNotified;

  /**
   * Wakes all threads blocked in {@link #waitFor()} once aggregation completes.
   *
   * <p>Invoked exactly once by the superclass when all messages have finished and the aggregator is
   * armed. The {@code success} flag is not used here; callers waiting on completion do not observe
   * it through this method.
   *
   * @param success {@code true} when all messages completed successfully; ignored.
   */
  @Override
  synchronized void finish(boolean success) {
    // Notify all waiters that completion has been reached.
    completionNotified = true;
    notifyAll();
  }

  /**
   * Blocks the current thread until {@link #finished()} returns {@code true}.
   *
   * <p>Interrupts are intentionally ignored to uphold the contract that this method returns only
   * after the overall operation completes (that is, after {@link #finish(boolean)} has been
   * invoked). Propagating or restoring the interrupt status would allow an early return. Tests in
   * {@code WaitingMultiMessageCallbackTest} cover this behavior.
   */
  @SuppressWarnings("java:S2142") // InterruptedException intentionally ignored; see method Javadoc
  public synchronized void waitFor() {
    while (!completionNotified && !finished()) {
      try {
        wait();
      } catch (InterruptedException _) {
        // Deliberately ignore; do not restore interrupt status to preserve the blocking contract.
      }
    }
  }

  @Override
  void sent(boolean success) {
    // No-op: this implementation only cares about overall completion, not the interim 'sent' event.
  }
}
