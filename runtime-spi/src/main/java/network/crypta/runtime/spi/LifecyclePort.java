package network.crypta.runtime.spi;

/**
 * Exposes read-only node lifecycle state needed by infrastructure adapters.
 *
 * <p>This port provides a minimal view of daemon lifecycle progress to components that need to
 * adjust behavior during startup, steady-state operation, or shutdown. The SPI stays intentionally
 * conservative: callers can observe current state and timestamps, but they cannot trigger or alter
 * lifecycle transitions. That keeps the boundary safe for low-level infrastructure code while still
 * allowing request handlers, listeners, or status reporters to avoid work at the wrong phase.
 *
 * <p>The values reported here preserve the runtime's existing semantics. Implementations should not
 * synthesize new states or reinterpret timing data. Callers should therefore use these methods as a
 * thin view over the live daemon rather than as an independent state machine.
 *
 * @see RuntimePorts
 */
public interface LifecyclePort {
  /**
   * Reports whether the runtime considers startup complete.
   *
   * <p>This method exposes the daemon's current "started" flag so adapters can avoid assuming the
   * node is fully available too early. A return value of {@code true} means the runtime has reached
   * its normal started state according to existing daemon semantics. A return value of {@code
   * false} may mean startup is still in progress or that the node never completed startup.
   *
   * @return {@code true} when the runtime reports that startup has completed, otherwise {@code
   *     false}
   */
  @SuppressWarnings("unused")
  boolean hasStarted();

  /**
   * Reports whether a shutdown has been initiated.
   *
   * <p>This exposes the runtime's current stopping flag for code that should avoid starting new
   * long-lived work while shutdown is underway. A value of {@code true} does not imply that all
   * services have already stopped; it only indicates that the runtime has entered its stopping
   * phase. Callers should treat it as a conservative signal and prefer graceful behavior when it is
   * set.
   *
   * @return {@code true} when the runtime is in its stopping phase, otherwise {@code false}
   */
  boolean isStopping();

  /**
   * Reports whether the runtime was launched under the Tanuki wrapper.
   *
   * <p>This exposes the daemon's existing wrapper-detection flag without changing its meaning.
   * Management and HTTP code use it only as runtime metadata when deciding whether wrapper-backed
   * restart affordances should be shown. A return value of {@code false} therefore means callers
   * must not assume wrapper restart support is available.
   *
   * @return {@code true} when the runtime is using the wrapper according to existing daemon
   *     semantics, otherwise {@code false}
   */
  boolean isUsingWrapper();

  /**
   * Returns the startup timestamp recorded by the runtime in milliseconds.
   *
   * <p>The value is the daemon's own startup time metadata, exposed without reinterpretation. It is
   * useful for status reporting and elapsed-time calculations that need a stable runtime-provided
   * reference point. Callers should not infer more precision than milliseconds, and they should use
   * the value together with the same time base expected by the surrounding daemon code.
   *
   * @return runtime startup time metadata expressed in milliseconds using the daemon's existing
   *     convention
   */
  @SuppressWarnings("unused")
  long startupTimeMillis();
}
