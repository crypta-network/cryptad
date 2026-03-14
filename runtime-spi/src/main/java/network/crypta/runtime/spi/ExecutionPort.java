package network.crypta.runtime.spi;

/**
 * Schedules named background work without exposing the daemon's executor implementation.
 *
 * <p>This port is the narrow execution boundary that higher-level adapters use when they need to
 * hand work back to the running node. Callers submit a fully prepared {@link Runnable} together
 * with a stable descriptive name, and the runtime implementation decides how that work is queued,
 * labeled, and executed. The SPI deliberately omits priorities, executor handles, and lifecycle
 * controls so infrastructure code can depend on the capability without learning daemon-internal
 * scheduling types.
 *
 * <p>Implementations may execute the task on an existing worker pool, on a dedicated service, or on
 * another runtime-managed mechanism. The caller should therefore treat the submission as
 * asynchronous and avoid assuming a specific thread or ordering policy unless the implementation
 * documents one.
 *
 * @see RuntimePorts
 */
@FunctionalInterface
public interface ExecutionPort {
  /**
   * Schedules a unit of work for runtime-managed execution.
   *
   * <p>Implementations submit {@code task} using the daemon's existing scheduling behavior. The
   * {@code name} identifies the work for diagnostics, thread naming, or logging, but it does not
   * alter the task's business semantics. Callers should pass a non-blocking task whenever possible
   * and should assume the work may begin after this method returns rather than immediately on the
   * current thread.
   *
   * @param task runnable work item to submit to the runtime without further wrapping by the caller
   * @param name descriptive task name used for runtime bookkeeping and operational diagnostics
   */
  void execute(Runnable task, String name);
}
