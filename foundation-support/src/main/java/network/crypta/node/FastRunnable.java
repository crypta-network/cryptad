package network.crypta.node;

/**
 * Marker interface for short, non-blocking tasks that are safe to execute inline on
 * latency-sensitive threads.
 *
 * <p>Schedulers in this codebase, including the packet sender and ticker implementations in the
 * runtime layer, may check whether a task implements {@code FastRunnable}. When it does, they can
 * invoke {@link #run()} directly on the calling thread to minimize scheduling overhead and wake-up
 * latency. Tasks that do not implement this interface are typically offloaded to an executor.
 *
 * <p>Implementations are expected to keep {@link #run()} extremely short and to avoid blocking
 * operations such as sleep, I/O, lock contention, or long computations. A slow "fast" task can
 * stall a networking or ticker thread and reduce overall throughput. Callers may invoke these tasks
 * on shared infrastructure threads, so implementations should not rely on thread-local state or
 * thread-affinity behavior. Unchecked exceptions are handled by the calling scheduler, but
 * implementations should still avoid throwing when practical.
 *
 * <p>Memory visibility follows the usual {@link Runnable} contract. This marker does not add any
 * extra happens-before guarantees beyond those established by the scheduler that invokes {@link
 * #run()}.
 */
public interface FastRunnable extends Runnable {}
