package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.TransferAccessPort;

/**
 * Shared runtime-port bundle used by the legacy queue toadlets.
 *
 * <p>The download and upload queue pages share the same detached read-path, mutation, and
 * transfer-policy runtime ports, the download side also uses the queue-download creation port, and
 * the upload side uses the queue-insert creation port. The shared queue UI also still exposes the
 * remaining support-oriented availability, persistence, and panic helpers, plus the legacy
 * "recommend to friends" action, so the bundle now carries the detached queue-support, darknet
 * peer-list, and messaging ports used by those paths. Grouping them in one small record keeps
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
 * @param queueSupportPort detached queue-support port used for backend enablement, persistence
 *     state, and panic actions
 * @param queueCompletionPort detached queue-completion port used for per-side completion-tracker
 *     startup
 * @param darknetConnectionsPort detached darknet friends-page companion port used by queue
 *     recommendation rendering
 * @param darknetMessagingPort detached darknet messaging port used by queue recommendation sends
 */
public record QueueToadletRuntimePorts(
    QueuePagePort queuePagePort,
    TransferAccessPort transferAccessPort,
    QueueDownloadPort queueDownloadPort,
    QueueInsertPort queueInsertPort,
    QueueMutationPort queueMutationPort,
    QueueSupportPort queueSupportPort,
    QueueCompletionPort queueCompletionPort,
    DarknetConnectionsPort darknetConnectionsPort,
    DarknetMessagingPort darknetMessagingPort) {
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
   * @param queueSupportPort detached queue-support port shared by the download and upload toadlets
   *     for backend enablement, persistence state, and panic actions
   * @param queueCompletionPort detached queue-completion port shared by the download and upload
   *     toadlets for per-side completion-tracker startup
   * @param darknetConnectionsPort detached darknet friends-page companion port shared by the
   *     download and upload toadlets for queue recommendation rendering
   * @param darknetMessagingPort detached darknet messaging port shared by the download and upload
   *     toadlets for queue recommendation sends
   * @throws NullPointerException if any port is {@code null}
   */
  public QueueToadletRuntimePorts {
    Objects.requireNonNull(queuePagePort);
    Objects.requireNonNull(transferAccessPort);
    Objects.requireNonNull(queueDownloadPort);
    Objects.requireNonNull(queueInsertPort);
    Objects.requireNonNull(queueMutationPort);
    Objects.requireNonNull(queueSupportPort);
    Objects.requireNonNull(queueCompletionPort);
    Objects.requireNonNull(darknetConnectionsPort);
    Objects.requireNonNull(darknetMessagingPort);
  }
}
