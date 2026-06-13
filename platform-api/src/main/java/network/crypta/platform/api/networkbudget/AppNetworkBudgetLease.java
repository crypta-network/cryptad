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
 * usually with try-with-resources. Closing is idempotent: the first close runs the release action,
 * and later close calls are ignored. The class is thread-safe for the active flag, but the budget
 * service still treats leases as short-lived request-scoped objects rather than shared workflow
 * state.
 */
public final class AppNetworkBudgetLease implements AutoCloseable {
  private static final AppNetworkBudgetLease NOOP = new AppNetworkBudgetLease(() -> {});

  private final Runnable releaseAction;
  private final AtomicBoolean active = new AtomicBoolean(true);

  AppNetworkBudgetLease(Runnable releaseAction) {
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
   * Returns whether this lease has not yet been closed.
   *
   * <p>For a real lease, {@code true} means the associated concurrency counters are still charged
   * to the app and operation. For the no-op lease, the value reflects whether the shared no-op
   * object has been closed, not any durable or process-local budget state.
   *
   * @return {@code true} while this lease object has not observed a close call
   */
  public boolean active() {
    return active.get();
  }

  @Override
  public void close() {
    if (active.compareAndSet(true, false)) {
      releaseAction.run();
    }
  }
}
