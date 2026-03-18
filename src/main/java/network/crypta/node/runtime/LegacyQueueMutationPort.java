package network.crypta.node.runtime;

import java.util.List;
import java.util.Objects;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.DownloadRequestStatus;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.RequestStatus;
import network.crypta.clients.fcp.UploadFileRequestStatus;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.RequestQueueUnavailableException;

/**
 * Legacy daemon-backed implementation of the queue-mutation runtime SPI.
 *
 * <p>This adapter keeps the remaining existing-request queue mutations inside the daemon root
 * module while exposing only a narrow JDK-level interface to higher layers. It resolves the live
 * {@link FCPServer} lazily through {@link NodeClientCore#getEndpoints()} so construction does not
 * force early endpoint initialization during startup.
 *
 * <p>The adapter preserves the current queue-mutation semantics exactly: selected identifiers are
 * forwarded directly to the legacy blocking FCP operations, and the finished-upload and
 * finished-download cleanup paths use the same status filters that the HTTP layer previously
 * applied inline. Persistence-disabled failures are translated to {@link
 * RequestQueueUnavailableException}.
 *
 * <p>Use this implementation when runtime wiring still depends on the legacy daemon internals but
 * higher layers should only see the narrow {@link QueueMutationPort} contract. The class is
 * state-light and holds only the owning {@link NodeClientCore}; each mutation resolves the live
 * {@link FCPServer} on demand so startup order remains unchanged and tests can substitute core
 * collaborators without constructing extra queue abstractions.
 *
 * <ul>
 *   <li>Selected-request mutations delegate directly to the blocking FCP operations.
 *   <li>Bulk cleanup methods preserve the legacy status filters exactly.
 *   <li>Persistence-disabled failures are mapped to the runtime-SPI exception type.
 * </ul>
 *
 * @see QueueMutationPort
 */
public final class LegacyQueueMutationPort implements QueueMutationPort {
  private final NodeClientCore core;

  /**
   * Creates a queue-mutation adapter backed by the supplied client core.
   *
   * <p>The adapter does not resolve the {@link FCPServer} during construction. Callers can
   * therefore create it as part of early runtime-port wiring, before endpoint initialization is
   * complete, and rely on the individual mutation methods to get the current server lazily.
   *
   * @param core live daemon client core that provides lazy access to runtime endpoints
   */
  public LegacyQueueMutationPort(NodeClientCore core) {
    this.core = Objects.requireNonNull(core);
  }

  /** {@inheritDoc} */
  @Override
  public void removeRequests(List<String> identifiers) throws RequestQueueUnavailableException {
    Objects.requireNonNull(identifiers);
    try {
      FCPServer fcpServer = fcpServer();
      for (String identifier : identifiers) {
        fcpServer.removeGlobalRequestBlocking(identifier);
      }
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException("Persistent request queue unavailable", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void restartRequests(List<String> identifiers, boolean disableFilterData)
      throws RequestQueueUnavailableException {
    Objects.requireNonNull(identifiers);
    try {
      FCPServer fcpServer = fcpServer();
      for (String identifier : identifiers) {
        fcpServer.restartBlocking(identifier, disableFilterData);
      }
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException("Persistent request queue unavailable", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void changePriority(List<String> identifiers, short newPriorityClass)
      throws RequestQueueUnavailableException {
    Objects.requireNonNull(identifiers);
    try {
      FCPServer fcpServer = fcpServer();
      for (String identifier : identifiers) {
        fcpServer.modifyGlobalRequestBlocking(identifier, null, newPriorityClass);
      }
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException("Persistent request queue unavailable", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void removeFinishedUploads() throws RequestQueueUnavailableException {
    FCPServer fcpServer = fcpServer();
    for (RequestStatus requestStatus : globalRequests()) {
      if (requestStatus instanceof UploadFileRequestStatus upload && upload.hasSucceeded()) {
        removeRequest(fcpServer, upload.getIdentifier());
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void removeFinishedDownloads() throws RequestQueueUnavailableException {
    FCPServer fcpServer = fcpServer();
    for (RequestStatus requestStatus : globalRequests()) {
      if (requestStatus instanceof DownloadRequestStatus download
          && download.isPersistent()
          && download.hasSucceeded()
          && download.isTotalFinalized()
          && !download.toTempSpace()) {
        removeRequest(fcpServer, download.getIdentifier());
      }
    }
  }

  private void removeRequest(FCPServer fcpServer, String identifier)
      throws RequestQueueUnavailableException {
    try {
      fcpServer.removeGlobalRequestBlocking(identifier);
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException("Persistent request queue unavailable", e);
    }
  }

  private RequestStatus[] globalRequests() throws RequestQueueUnavailableException {
    try {
      return fcpServer().getGlobalRequests();
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException("Persistent request queue unavailable", e);
    }
  }

  private FCPServer fcpServer() {
    FCPServer fcpServer = core.getEndpoints().getFCPServer();
    if (fcpServer == null) {
      throw new IllegalStateException("FCP server unavailable");
    }
    return fcpServer;
  }
}
