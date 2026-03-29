package network.crypta.runtime.endpoints.fcp;

import java.util.Objects;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.DownloadRequestStatus;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.RequestStatus;
import network.crypta.clients.fcp.UploadDirRequestStatus;
import network.crypta.clients.fcp.UploadFileRequestStatus;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.admin.queue.QueueAdminBackend;
import network.crypta.runtime.admin.queue.QueueDownloadStatusView;
import network.crypta.runtime.admin.queue.QueueRequestStatusView;
import network.crypta.runtime.admin.queue.QueueUploadDirStatusView;
import network.crypta.runtime.admin.queue.QueueUploadFileStatusView;
import network.crypta.runtime.spi.RequestQueueUnavailableException;

/**
 * Implements the runtime-owned queue administration seam on top of the live FCP server.
 *
 * <p>This bridge keeps the remaining FCP-specific queue knowledge inside {@code
 * network.crypta.runtime.endpoints.fcp}. Runtime-admin callers interact only with the runtime-owned
 * queue seam, while this type resolves the live {@link FCPServer} lazily from {@link
 * NodeClientCore}, translates persistence failures into {@link RequestQueueUnavailableException},
 * and adapts protocol-specific {@link RequestStatus} objects into the narrow runtime-owned status
 * views used by diagnostics and queue mutations.
 *
 * <p>The implementation is intentionally small and mechanical. It does not reinterpret the queue
 * state, cache snapshots, or change the FCP wire behavior. Each call reaches the current FCP server
 * state, preserving the existing distinction between an unavailable persistent request queue and
 * the complete absence of an FCP server.
 */
public final class FcpQueueAdminBackend implements QueueAdminBackend {
  private static final String QUEUE_UNAVAILABLE = "Persistent request queue unavailable";

  private final NodeClientCore core;

  /**
   * Creates an FCP-backed queue admin bridge.
   *
   * <p>Callers normally create one instance during runtime-port wiring and reuse it for the admin
   * adapters that still need queue diagnostics, queue support, or queue mutation behavior. The
   * constructor itself is side-effect free: it stores the client core and defers endpoint
   * resolution until a queue method is invoked.
   *
   * @param core daemon client core used to resolve the live FCP endpoint bundle on demand
   */
  public FcpQueueAdminBackend(NodeClientCore core) {
    this.core = Objects.requireNonNull(core, "core");
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation treats a missing FCP endpoint bundle or a missing FCP server as disabled
   * rather than exceptional. That lets runtime-admin probe queue availability during startup
   * without forcing endpoint initialization or triggering persistence access.
   */
  @Override
  public boolean isEnabled() {
    FCPServer fcpServer = fcpServerOrNull();
    return fcpServer != null && fcpServer.isEnabled();
  }

  /**
   * {@inheritDoc}
   *
   * <p>The bridge resolves the live {@link FCPServer} lazily for each call and adapts the returned
   * protocol-specific statuses into runtime-owned views before returning them. Persistence failures
   * are translated into {@link RequestQueueUnavailableException} so runtime-admin does not need to
   * know about the FCP-layer exception type.
   *
   * @throws IllegalStateException if no live FCP server is currently available from the endpoint
   *     bundle
   */
  @Override
  public QueueRequestStatusView[] getGlobalRequests() throws RequestQueueUnavailableException {
    try {
      return adapt(fcpServer().getGlobalRequests());
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException(QUEUE_UNAVAILABLE, e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>This delegates directly to the live FCP server once it has been resolved. The method keeps
   * the existing blocking behavior and only translates persistence-disabled failures into the
   * runtime-owned exception type used by higher layers.
   *
   * @throws IllegalStateException if no live FCP server is currently available from the endpoint
   *     bundle
   */
  @Override
  public boolean removeGlobalRequestBlocking(String identifier)
      throws RequestQueueUnavailableException {
    try {
      return fcpServer().removeGlobalRequestBlocking(identifier);
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException(QUEUE_UNAVAILABLE, e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>This forwards the restart request to the live FCP server without changing the identifier or
   * restart flags. Runtime-admin therefore preserves the legacy restart semantics while seeing only
   * the runtime-owned queue seam.
   *
   * @throws IllegalStateException if no live FCP server is currently available from the endpoint
   *     bundle
   */
  @Override
  public boolean restartBlocking(String identifier, boolean disableFilterData)
      throws RequestQueueUnavailableException {
    try {
      return fcpServer().restartBlocking(identifier, disableFilterData);
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException(QUEUE_UNAVAILABLE, e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>This forwards the mutation request to the live FCP server without translating the token or
   * priority arguments. The bridge keeps its role narrow by adapting only exception types and
   * request-status views, not backend-specific queue semantics.
   *
   * @throws IllegalStateException if no live FCP server is currently available from the endpoint
   *     bundle
   */
  @Override
  public boolean modifyGlobalRequestBlocking(String identifier, String newToken, short newPriority)
      throws RequestQueueUnavailableException {
    try {
      return fcpServer().modifyGlobalRequestBlocking(identifier, newToken, newPriority);
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException(QUEUE_UNAVAILABLE, e);
    }
  }

  private FCPServer fcpServer() {
    FCPServer fcpServer = fcpServerOrNull();
    if (fcpServer == null) {
      throw new IllegalStateException("FCP server unavailable");
    }
    return fcpServer;
  }

  private FCPServer fcpServerOrNull() {
    var endpoints = core.getEndpoints();
    return endpoints == null ? null : FcpEndpointHandles.serverOrNull(endpoints.getFcpEndpoint());
  }

  private QueueRequestStatusView[] adapt(RequestStatus[] statuses) {
    QueueRequestStatusView[] views = new QueueRequestStatusView[statuses.length];
    for (int i = 0; i < statuses.length; i++) {
      views[i] = adapt(statuses[i]);
    }
    return views;
  }

  private QueueRequestStatusView adapt(RequestStatus status) {
    if (status instanceof DownloadRequestStatus downloadStatus) {
      return new DownloadStatusView(downloadStatus);
    }
    if (status instanceof UploadFileRequestStatus uploadFileStatus) {
      return new UploadFileStatusView(uploadFileStatus);
    }
    if (status instanceof UploadDirRequestStatus uploadDirStatus) {
      return new UploadDirStatusView(uploadDirStatus);
    }
    return new RequestStatusViewAdapter(status);
  }

  private static class RequestStatusViewAdapter implements QueueRequestStatusView {
    private final RequestStatus status;

    private RequestStatusViewAdapter(RequestStatus status) {
      this.status = Objects.requireNonNull(status, "status");
    }

    @Override
    public String getIdentifier() {
      return status.getIdentifier();
    }

    @Override
    public boolean hasSucceeded() {
      return status.hasSucceeded();
    }

    @Override
    public boolean isPersistent() {
      return status.isPersistent();
    }

    @Override
    public boolean isTotalFinalized() {
      return status.isTotalFinalized();
    }
  }

  private static final class DownloadStatusView extends RequestStatusViewAdapter
      implements QueueDownloadStatusView {
    private final DownloadRequestStatus status;

    private DownloadStatusView(DownloadRequestStatus status) {
      super(status);
      this.status = status;
    }

    @Override
    public boolean toTempSpace() {
      return status.toTempSpace();
    }
  }

  private static final class UploadFileStatusView extends RequestStatusViewAdapter
      implements QueueUploadFileStatusView {
    private UploadFileStatusView(UploadFileRequestStatus status) {
      super(status);
    }
  }

  private static final class UploadDirStatusView extends RequestStatusViewAdapter
      implements QueueUploadDirStatusView {
    private UploadDirStatusView(UploadDirRequestStatus status) {
      super(status);
    }
  }
}
