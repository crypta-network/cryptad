package network.crypta.runtime.spi;

/** Schedules named background work without exposing the daemon executor type. */
@FunctionalInterface
public interface ExecutionPort {
  void execute(Runnable task, String name);
}
