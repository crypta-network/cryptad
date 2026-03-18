package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.TransferAccessPort;

/**
 * Shared runtime-port bundle used by the legacy queue toadlets.
 *
 * <p>The download and upload queue pages share the same detached read-path, mutation, and
 * transfer-policy runtime ports, the download side also uses the queue-download creation port, and
 * the upload side uses the queue-insert creation port. Grouping them in one small record keeps
 * constructor signatures stable while preserving the option to add other queue-specific ports later
 * without widening the main toadlet constructor again.
 *
 * <p>This record lives in the HTTP layer because it models HTTP wiring rather than a daemon-side
 * runtime capability. The queue toadlets can accept one stable parameter today and still grow to
 * include additional queue-related ports in later migrations without repeating constructor churn.
 *
 * @param queuePagePort detached queue-page read port
 * @param transferAccessPort detached transfer-policy port used by queue-local path checks
 * @param queueDownloadPort detached queue-download port used for new persistent downloads
 * @param queueInsertPort detached queue-insert port used for new persistent uploads and local
 *     inserts
 * @param queueMutationPort detached queue-mutation port
 */
public record QueueToadletRuntimePorts(
    QueuePagePort queuePagePort,
    TransferAccessPort transferAccessPort,
    QueueDownloadPort queueDownloadPort,
    QueueInsertPort queueInsertPort,
    QueueMutationPort queueMutationPort) {
  /**
   * Creates one validated queue-toadlet port bundle.
   *
   * @param queuePagePort detached queue-page read port shared by the download and upload toadlets
   * @param transferAccessPort detached transfer-policy port shared by the download and upload
   *     toadlets
   * @param queueDownloadPort detached queue-download port shared by the download and upload
   *     toadlets
   * @param queueInsertPort detached queue-insert port shared by the download and upload toadlets
   * @param queueMutationPort detached queue-mutation port shared by the download and upload
   *     toadlets
   * @throws NullPointerException if any port is {@code null}
   */
  public QueueToadletRuntimePorts {
    Objects.requireNonNull(queuePagePort);
    Objects.requireNonNull(transferAccessPort);
    Objects.requireNonNull(queueDownloadPort);
    Objects.requireNonNull(queueInsertPort);
    Objects.requireNonNull(queueMutationPort);
  }
}
