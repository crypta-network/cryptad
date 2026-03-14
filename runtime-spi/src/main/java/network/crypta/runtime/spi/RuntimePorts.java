package network.crypta.runtime.spi;

/** Aggregate entrypoint for runtime-facing SPI adapters used by higher layers. */
public interface RuntimePorts {
  ExecutionPort execution();

  RandomnessPort randomness();

  TransferAccessPort transferAccess();

  LifecyclePort lifecycle();
}
