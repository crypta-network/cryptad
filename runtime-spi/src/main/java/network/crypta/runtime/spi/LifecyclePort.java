package network.crypta.runtime.spi;

/** Exposes read-only node lifecycle state needed by infrastructure adapters. */
public interface LifecyclePort {
  boolean hasStarted();

  boolean isStopping();

  long startupTimeMillis();
}
