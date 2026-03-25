package network.crypta.runtime.core;

import java.util.Objects;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.RequestQueuePort;
import network.crypta.runtime.spi.RequestQueuePriority;
import network.crypta.runtime.spi.RequestQueueTask;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.support.io.NativeThread;

/**
 * Legacy daemon-backed implementation of the runtime request-queue SPI.
 *
 * <p>This adapter keeps persistent-request queue traversal inside the daemon root module while
 * exposing only the JDK-level runtime SPI surface to infrastructure code. It delegates directly to
 * the existing {@link NodeClientCore} persistence runner and ticker, translates daemon-specific
 * queue failures into {@link RequestQueueUnavailableException}, and preserves the priority mapping
 * historically used by the FCP queue-control paths.
 *
 * <p>The adapter is intentionally thin and stateless apart from its reference to the live {@link
 * NodeClientCore}. It does not add retries, buffering, or policy. Callers therefore see the same
 * queue acceptance rules, delayed scheduling behavior, and checkpoint semantics that the daemon
 * already applies internally.
 */
public final class LegacyRequestQueuePort implements RequestQueuePort {
  private static final int LISTING_PRIORITY = NativeThread.PriorityLevel.HIGH_PRIORITY.value - 1;

  private final NodeClientCore core;

  /**
   * Creates a request-queue adapter backed by the supplied client core.
   *
   * <p>The supplied core remains the source of truth for persistence state, queue selection, and
   * delayed task scheduling throughout the adapter's lifetime.
   *
   * @param core live daemon client core that owns the persistence runner and ticker
   */
  public LegacyRequestQueuePort(NodeClientCore core) {
    this.core = Objects.requireNonNull(core);
  }

  @Override
  public boolean isPersistenceDatabaseKilled() {
    return core.killedDatabase();
  }

  @Override
  public void submitPersistentJob(RequestQueueTask task, RequestQueuePriority priority)
      throws RequestQueueUnavailableException {
    Objects.requireNonNull(task);
    Objects.requireNonNull(priority);
    try {
      core.getClientContext().jobRunner.queue(_ -> task.run(), nativePriority(priority));
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException("Persistent request queue unavailable", e);
    }
  }

  @Override
  public void scheduleLater(Runnable task, long delayMillis) {
    core.getClientContext().ticker.queueTimedJob(Objects.requireNonNull(task), delayMillis);
  }

  private static int nativePriority(RequestQueuePriority priority) {
    return switch (priority) {
      case NORMAL -> NativeThread.PriorityLevel.NORM_PRIORITY.value;
      case HIGH -> NativeThread.PriorityLevel.HIGH_PRIORITY.value;
      case LISTING -> LISTING_PRIORITY;
    };
  }
}
