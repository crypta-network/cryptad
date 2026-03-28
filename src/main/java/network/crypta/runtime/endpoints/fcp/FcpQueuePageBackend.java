package network.crypta.runtime.endpoints.fcp;

import java.io.File;
import java.time.Instant;
import java.util.Objects;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.ClientPut.COMPRESS_STATE;
import network.crypta.clients.fcp.DownloadRequestStatus;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.RequestStatus;
import network.crypta.clients.fcp.UploadDirRequestStatus;
import network.crypta.clients.fcp.UploadFileRequestStatus;
import network.crypta.clients.fcp.UploadRequestStatus;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.admin.queue.page.QueueCompressionState;
import network.crypta.runtime.admin.queue.page.QueuePageBackend;
import network.crypta.runtime.admin.queue.page.QueuePageDownloadView;
import network.crypta.runtime.admin.queue.page.QueuePageRequestView;
import network.crypta.runtime.admin.queue.page.QueuePageUploadDirView;
import network.crypta.runtime.admin.queue.page.QueuePageUploadFileView;
import network.crypta.runtime.admin.queue.page.QueuePageUploadView;
import network.crypta.runtime.spi.RequestQueueUnavailableException;

/**
 * Implements the runtime-owned queue-page seam on top of the live FCP server.
 *
 * <p>This bridge keeps the remaining FCP-specific queue-page knowledge inside {@code
 * network.crypta.runtime.endpoints.fcp}. Runtime-admin callers interact only with runtime-owned
 * queue-page views, while this type resolves the live {@link FCPServer} lazily, translates
 * persistence failures into {@link RequestQueueUnavailableException}, and adapts protocol-specific
 * request statuses into the minimal runtime-owned view used by {@code LegacyQueuePagePort}.
 *
 * <p>The bridge is intentionally mechanical. It does not try to redesign queue semantics, cache
 * snapshots, or normalize more data than the legacy page currently consumes. Missing FCP access is
 * treated as an empty queue-page snapshot, so the daemon startup order stays unchanged, while an
 * actual persistent-queue failure still surfaces as a runtime SPI exception that the HTTP layer
 * already knows how to report.
 */
public final class FcpQueuePageBackend implements QueuePageBackend {
  private static final String QUEUE_UNAVAILABLE = "Persistent request queue unavailable";

  private final NodeClientCore core;

  /**
   * Creates an FCP-backed queue-page bridge.
   *
   * @param core daemon client core used to resolve the current FCP endpoint bundle on demand
   */
  public FcpQueuePageBackend(NodeClientCore core) {
    this.core = Objects.requireNonNull(core, "core");
  }

  /**
   * Returns the current global requests adapted into runtime-owned queue-page views.
   *
   * <p>The method resolves the FCP server lazily on each call, so constructing this backend does
   * not force endpoint initialization during startup. When no FCP server is currently available,
   * the bridge reports an empty queue snapshot. When the server exists but persistent queue access
   * is disabled, the method translates that protocol-specific failure into the runtime SPI
   * exception expected by callers above the seam.
   *
   * @return adapted global request views, or an empty array when the FCP queue cannot be reached
   *     yet
   * @throws RequestQueueUnavailableException if the persistent queue exists but cannot be queried
   */
  @Override
  public QueuePageRequestView[] getGlobalRequests() throws RequestQueueUnavailableException {
    FCPServer fcpServer = fcpServerOrNull();
    if (fcpServer == null) {
      return new QueuePageRequestView[0];
    }
    try {
      return adapt(fcpServer.getGlobalRequests());
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException(QUEUE_UNAVAILABLE, e);
    }
  }

  private FCPServer fcpServerOrNull() {
    var endpoints = core.getEndpoints();
    return endpoints == null ? null : endpoints.getFCPServer();
  }

  private QueuePageRequestView[] adapt(RequestStatus[] statuses) {
    QueuePageRequestView[] views = new QueuePageRequestView[statuses.length];
    for (int i = 0; i < statuses.length; i++) {
      views[i] = adapt(statuses[i]);
    }
    return views;
  }

  private QueuePageRequestView adapt(RequestStatus status) {
    if (status instanceof DownloadRequestStatus downloadStatus) {
      return new DownloadView(downloadStatus);
    }
    if (status instanceof UploadFileRequestStatus uploadFileStatus) {
      return new UploadFileView(uploadFileStatus);
    }
    if (status instanceof UploadDirRequestStatus uploadDirStatus) {
      return new UploadDirView(uploadDirStatus);
    }
    if (status instanceof UploadRequestStatus uploadStatus) {
      return new UploadView(uploadStatus);
    }
    return new RequestViewAdapter(status);
  }

  private static class RequestViewAdapter implements QueuePageRequestView {
    private final RequestStatus status;

    private RequestViewAdapter(RequestStatus status) {
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
    public boolean hasFinished() {
      return status.hasFinished();
    }

    @Override
    public short getPriority() {
      return status.getPriority();
    }

    @Override
    public int getTotalBlocks() {
      return status.getTotalBlocks();
    }

    @Override
    public boolean isTotalFinalized() {
      return status.isTotalFinalized();
    }

    @Override
    public int getMinBlocks() {
      return status.getMinBlocks();
    }

    @Override
    public int getFetchedBlocks() {
      return status.getFetchedBlocks();
    }

    @Override
    public Instant getLastSuccess() {
      return status.getLastSuccess();
    }

    @Override
    public Instant getLastFailure() {
      return status.getLastFailure();
    }

    @Override
    public FreenetURI getUri() {
      return status.getURI();
    }

    @Override
    public long getDataSize() {
      return status.getDataSize();
    }

    @Override
    public boolean isPersistent() {
      return status.isPersistent();
    }

    @Override
    public boolean isPersistentForever() {
      return status.isPersistentForever();
    }

    @Override
    public int getFatalyFailedBlocks() {
      return status.getFatalyFailedBlocks();
    }

    @Override
    public int getFailedBlocks() {
      return status.getFailedBlocks();
    }

    @Override
    public boolean isStarted() {
      return status.isStarted();
    }

    @Override
    public String getFailureReason(boolean longDescription) {
      return status.getFailureReason(longDescription);
    }

    @Override
    public String getPreferredFilenameSafe() {
      return status.getPreferredFilenameSafe();
    }
  }

  private static final class DownloadView extends RequestViewAdapter
      implements QueuePageDownloadView {
    private final DownloadRequestStatus status;

    private DownloadView(DownloadRequestStatus status) {
      super(status);
      this.status = status;
    }

    @Override
    public boolean toTempSpace() {
      return status.toTempSpace();
    }

    @Override
    public FetchExceptionMode getFailureCode() {
      return status.getFailureCode();
    }

    @Override
    public String getMimeType() {
      return status.getMIMEType();
    }

    @Override
    public File getDestFilename() {
      return status.getDestFilename();
    }

    @Override
    public CompatibilityMode[] getCompatibilityMode() {
      return status.getCompatibilityMode();
    }

    @Override
    public byte[] getOverriddenSplitfileCryptoKey() {
      return status.getOverriddenSplitfileCryptoKey();
    }

    @Override
    public boolean detectedDontCompress() {
      return status.detectedDontCompress();
    }
  }

  private static class UploadView extends RequestViewAdapter implements QueuePageUploadView {
    private final UploadRequestStatus status;

    private UploadView(UploadRequestStatus status) {
      super(status);
      this.status = status;
    }

    @Override
    public FreenetURI getFinalUri() {
      return status.getFinalURI();
    }
  }

  private static final class UploadFileView extends UploadView implements QueuePageUploadFileView {
    private final UploadFileRequestStatus status;

    private UploadFileView(UploadFileRequestStatus status) {
      super(status);
      this.status = status;
    }

    @Override
    public String getMimeType() {
      return status.getMIMEType();
    }

    @Override
    public File getOrigFilename() {
      return status.getOrigFilename();
    }

    @Override
    public QueueCompressionState getCompressionState() {
      return mapCompressionState(status.isCompressing());
    }

    private static QueueCompressionState mapCompressionState(COMPRESS_STATE state) {
      return switch (state) {
        case WAITING -> QueueCompressionState.WAITING;
        case COMPRESSING -> QueueCompressionState.COMPRESSING;
        case WORKING -> QueueCompressionState.WORKING;
      };
    }
  }

  private static final class UploadDirView extends UploadView implements QueuePageUploadDirView {
    private final UploadDirRequestStatus status;

    private UploadDirView(UploadDirRequestStatus status) {
      super(status);
      this.status = status;
    }

    @Override
    public long getTotalDataSize() {
      return status.getTotalDataSize();
    }

    @Override
    public int getNumberOfFiles() {
      return status.getNumberOfFiles();
    }
  }
}
