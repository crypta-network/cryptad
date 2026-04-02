package network.crypta.runtime.admin;

import java.util.List;
import java.util.Objects;
import network.crypta.runtime.admin.queue.QueueAdminBackend;
import network.crypta.runtime.admin.queue.QueueDownloadStatusView;
import network.crypta.runtime.admin.queue.QueueRequestStatusView;
import network.crypta.runtime.admin.queue.QueueUploadFileStatusView;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.RequestQueueUnavailableException;

/**
 * Legacy daemon-backed implementation of the queue-mutation runtime SPI.
 *
 * <p>This adapter keeps the remaining existing-request queue mutations inside the daemon root
 * module while exposing only a narrow JDK-level interface to higher layers. It resolves the live
 * queue backend lazily through a runtime-owned seam so construction does not force early endpoint
 * initialization during startup.
 *
 * <p>The adapter preserves the current queue-mutation semantics exactly: selected identifiers are
 * forwarded directly to the blocking queue operations, and the finished-upload and
 * finished-download cleanup paths use the same status filters that the HTTP layer previously
 * applied inline.
 *
 * @see QueueMutationPort
 */
public final class LegacyQueueMutationPort implements QueueMutationPort {
  private final QueueAdminBackend queueBackend;

  /**
   * Creates a queue-mutation adapter backed by the supplied queue backend.
   *
   * <p>The adapter does not force resolution of the backing queue implementation during
   * construction. Callers can therefore create it as part of early runtime-port wiring and rely on
   * the individual mutation methods to reach the current queue backend lazily.
   *
   * @param queueBackend runtime-owned queue backend seam for existing-request mutations
   */
  public LegacyQueueMutationPort(QueueAdminBackend queueBackend) {
    this.queueBackend = Objects.requireNonNull(queueBackend);
  }

  /** {@inheritDoc} */
  @Override
  public void removeRequests(List<String> identifiers) throws RequestQueueUnavailableException {
    Objects.requireNonNull(identifiers);
    for (String identifier : identifiers) {
      queueBackend.removeGlobalRequestBlocking(identifier);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void restartRequests(List<String> identifiers, boolean disableFilterData)
      throws RequestQueueUnavailableException {
    Objects.requireNonNull(identifiers);
    for (String identifier : identifiers) {
      queueBackend.restartBlocking(identifier, disableFilterData);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void changePriority(List<String> identifiers, short newPriorityClass)
      throws RequestQueueUnavailableException {
    Objects.requireNonNull(identifiers);
    for (String identifier : identifiers) {
      queueBackend.modifyGlobalRequestBlocking(identifier, null, newPriorityClass);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void removeFinishedUploads() throws RequestQueueUnavailableException {
    for (QueueRequestStatusView requestStatus : globalRequests()) {
      if (requestStatus instanceof QueueUploadFileStatusView upload && upload.hasSucceeded()) {
        queueBackend.removeGlobalRequestBlocking(upload.getIdentifier());
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void removeFinishedDownloads() throws RequestQueueUnavailableException {
    for (QueueRequestStatusView requestStatus : globalRequests()) {
      if (requestStatus instanceof QueueDownloadStatusView download
          && download.isPersistent()
          && download.hasSucceeded()
          && download.isTotalFinalized()
          && !download.toTempSpace()) {
        queueBackend.removeGlobalRequestBlocking(download.getIdentifier());
      }
    }
  }

  private QueueRequestStatusView[] globalRequests() throws RequestQueueUnavailableException {
    return queueBackend.getGlobalRequests();
  }
}
