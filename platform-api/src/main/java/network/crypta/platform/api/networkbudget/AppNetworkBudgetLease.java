package network.crypta.platform.api.networkbudget;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Closeable in-process concurrency lease for one allowed budget decision.
 *
 * <p>Leases release only process-local concurrency counters. Durable rate counters are already
 * consumed when the decision is allowed, so closing a lease never rewrites request history.
 *
 * <p>Callers should hold the lease only around the network work that consumed the concurrency slot,
 * usually with try-with-resources. Closing is idempotent: the first close schedules the release
 * action, and later close calls are ignored. The class is thread-safe for the active flag, but the
 * budget service still treats leases as short-lived request-scoped objects rather than shared
 * workflow state.
 */
public final class AppNetworkBudgetLease implements AutoCloseable {
  private static final AppNetworkBudgetLease NOOP = new AppNetworkBudgetLease(() -> {});

  private final Runnable releaseAction;
  private final long observationId;
  private final AtomicBoolean active = new AtomicBoolean(true);
  private final AtomicBoolean closeRequested = new AtomicBoolean();

  AppNetworkBudgetLease(Runnable releaseAction) {
    this(releaseAction, 0);
  }

  AppNetworkBudgetLease(Runnable releaseAction, long observationId) {
    this.observationId = observationId;
    this.releaseAction = Objects.requireNonNull(releaseAction, "releaseAction");
  }

  /**
   * Returns a no-op lease for unbudgeted reduced embeddings and host/operator paths.
   *
   * <p>The no-op lease lets callers use one cleanup pattern even when a reduced embedding omits the
   * shared network budget service or a denied decision needs an inert lease value. Closing it does
   * not change counters and is safe to repeat.
   *
   * @return reusable no-op lease that never releases process-local counters
   */
  public static AppNetworkBudgetLease noop() {
    return NOOP;
  }

  /**
   * Returns whether this lease still owns transient holds.
   *
   * <p>For a real lease, {@code true} means the associated concurrency counters are still charged
   * to the app and operation. For the no-op lease, the value reflects whether the shared no-op
   * object has been closed, not any durable or process-local budget state.
   *
   * @return {@code true} until immediate or deferred hold release
   */
  public boolean active() {
    return active.get();
  }

  /**
   * Returns native admission identity, or zero for uninstrumented leases.
   *
   * @return process-local identity
   */
  public long observationId() {
    return observationId;
  }

  private final Object terminationLock = new Object();
  private java.util.concurrent.CompletionStage<Void> ownerTermination;

  /**
   * Defers transient hold release until the asynchronous native owner acknowledges termination.
   * Must be called by the owning request before close; normal completion does not refund durable
   * charges. Exceptional completion retains holds because owner termination remains unknown.
   *
   * @param terminal native terminal acknowledgment
   */
  public void deferUntil(java.util.concurrent.CompletionStage<Void> terminal) {
    synchronized (terminationLock) {
      if (this == NOOP) {
        return;
      }
      if (closeRequested.get()) {
        throw new IllegalStateException("budget hold already closed");
      }
      ownerTermination = Objects.requireNonNull(terminal, "terminal");
    }
  }

  private void releaseHold() {
    if (active.compareAndSet(true, false)) {
      releaseAction.run();
    }
  }

  @Override
  public void close() {
    if (closeRequested.compareAndSet(false, true)) {
      java.util.concurrent.CompletionStage<Void> terminal;
      synchronized (terminationLock) {
        terminal = ownerTermination;
      }
      if (terminal == null) {
        releaseHold();
      } else {
        terminal.thenRun(this::releaseHold);
      }
    }
  }
}
