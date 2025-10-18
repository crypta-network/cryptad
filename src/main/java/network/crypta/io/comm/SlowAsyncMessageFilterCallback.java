package network.crypta.io.comm;

/**
 * Callback for {@link MessageFilter} whose handlers may perform long‑running or blocking work.
 *
 * <p>Unlike a regular {@link AsyncMessageFilterCallback}, implementations of this interface may be
 * executed on a scheduler that understands task priorities. When a matching event occurs, the
 * caller may submit the callback to a {@link network.crypta.support.PriorityAwareExecutor} so that
 * it runs asynchronously with the requested priority. This avoids executing expensive work on
 * threads that hold internal locks or dispatch loops.
 */
public interface SlowAsyncMessageFilterCallback extends AsyncMessageFilterCallback {

  /**
   * Returns the callback's scheduling priority used by priority‑aware executors.
   *
   * <p>Higher values represent higher priority. Implementations typically return one of the integer
   * values defined by {@link network.crypta.support.io.NativeThread.PriorityLevel} but are free to
   * choose any value accepted by the executor.
   *
   * @return a non‑negative integer priority; larger values indicate higher priority
   */
  int getPriority();
}
