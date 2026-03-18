package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;

/**
 * Shared runtime-port bundle used by the legacy queue toadlets.
 *
 * <p>The download and upload queue pages share the same detached read-path and mutation runtime
 * ports. Grouping them in one small record keeps constructor signatures stable while preserving the
 * option to add other queue-specific ports later without widening the main toadlet constructor
 * again.
 *
 * <p>This record lives in the HTTP layer because it models HTTP wiring rather than a daemon-side
 * runtime capability. The queue toadlets can accept one stable parameter today and still grow to
 * include additional queue-related ports in later migrations without repeating constructor churn.
 *
 * @param queuePagePort detached queue-page read port
 * @param queueMutationPort detached queue-mutation port
 */
public record QueueToadletRuntimePorts(
    QueuePagePort queuePagePort, QueueMutationPort queueMutationPort) {
  /**
   * Creates one validated queue-toadlet port bundle.
   *
   * @param queuePagePort detached queue-page read port shared by the download and upload toadlets
   * @param queueMutationPort detached queue-mutation port shared by the download and upload
   *     toadlets
   * @throws NullPointerException if either port is {@code null}
   */
  public QueueToadletRuntimePorts {
    Objects.requireNonNull(queuePagePort);
    Objects.requireNonNull(queueMutationPort);
  }
}
