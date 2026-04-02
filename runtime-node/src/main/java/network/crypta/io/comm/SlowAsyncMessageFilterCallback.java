package network.crypta.io.comm;

/**
 * Callback variant for filter events whose handlers may block or take noticeable time to run.
 *
 * <p>Implementations indicate that their {@link AsyncMessageFilterCallback} methods can perform
 * work that should not run inline on transport or maintenance threads. When a callback implements
 * this interface, the filter machinery schedules the invocation on a background executor using the
 * priority supplied by {@link #getPriority()} rather than calling it directly.
 *
 * <p>Scheduling details:
 *
 * <ul>
 *   <li>Callbacks are dispatched via a {@link network.crypta.support.PriorityAwareExecutor} using a
 *       {@code Runnable} that carries the returned priority.
 *   <li>The exact priority scale is executor-specific. In the built-in pooled executor,
 *       implementations typically return one of the values from {@link
 *       network.crypta.support.io.NativeThread.PriorityLevel} (e.g., {@code NORM_PRIORITY.value}).
 * </ul>
 *
 * <p>Thread-safety: Implementations may be called concurrently on different events; any shared
 * state must be protected appropriately.
 */
public interface SlowAsyncMessageFilterCallback extends AsyncMessageFilterCallback {

  /**
   * Returns the scheduling priority to use when dispatching the callback on a worker thread.
   *
   * <p>The value is interpreted by the underlying executor. For the default pooled executor,
   * recommended values are the {@link network.crypta.support.io.NativeThread.PriorityLevel#value
   * priority} constants provided by {@code NativeThread.PriorityLevel} where larger numbers
   * generally denote higher urgency.
   *
   * @return an integer priority understood by the executor
   */
  int getPriority();
}
