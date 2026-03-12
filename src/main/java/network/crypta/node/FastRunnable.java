package network.crypta.node;

/**
 * Marker interface for short, non‑blocking tasks that are safe to execute inline on
 * latency‑sensitive threads.
 *
 * <p>Schedulers in this codebase (for example {@link PacketSender} as well as ticker
 * implementations such as {@link network.crypta.support.PrioritizedTicker} and {@link
 * network.crypta.support.TrivialTicker}) may check whether a task implements {@code FastRunnable}.
 * When it does, they can invoke {@link #run()} directly on the calling thread to minimize
 * scheduling overhead and wake‑up latency. Tasks that do not implement this interface are typically
 * offloaded to an executor.
 *
 * <p>Contract for implementers: - Keep the body of {@link #run()} very short and avoid blocking
 * operations (sleep, I/O, waiting on locks, long computations). A slow "fast" task can stall the
 * networking/ticker thread and degrade throughput. - Assume execution occurs on a shared
 * infrastructure thread; do not perform work that may rely on thread‑local context or
 * thread‑affinity semantics. - Unchecked exceptions will be handled by the calling scheduler;
 * implementations should avoid throwing when possible.
 *
 * <p>Memory visibility follows the usual {@link Runnable} semantics; there are no extra
 * happens‑before guarantees beyond those established by the scheduler invoking {@link #run()}.
 *
 * @see PacketSender
 * @see network.crypta.support.PrioritizedTicker
 * @see network.crypta.support.TrivialTicker
 */
public interface FastRunnable extends Runnable {}
