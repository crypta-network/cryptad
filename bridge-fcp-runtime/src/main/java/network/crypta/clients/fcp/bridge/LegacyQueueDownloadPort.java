package network.crypta.clients.fcp.bridge;

import java.io.IOException;
import java.util.Objects;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.NotAllowedException;
import network.crypta.clients.fcp.PersistentGlobalRequestParams;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueDownloadRejectedException;
import network.crypta.runtime.spi.QueueDownloadRequest;
import network.crypta.runtime.spi.RequestQueueUnavailableException;

/**
 * Legacy daemon-backed implementation of the queue-download runtime SPI.
 *
 * <p>This adapter keeps the remaining creation of new persistent downloads inside the daemon root
 * module while exposing only a small JDK-only request shape upstream. It resolves the live {@link
 * FCPServer} lazily through {@link NodeClientCore#getEndpoints()} so runtime-port construction does
 * not force early endpoint initialization during startup.
 *
 * <p>The adapter preserves the current queue-download behavior exactly: each request is bridged to
 * the legacy-blocking persistent-global-request call, disk-download disablement is delegated to the
 * client core, and policy rejections and persistence failures are mapped to the SPI-specific
 * checked exceptions expected by higher layers.
 *
 * <ul>
 *   <li>Startup wiring stays safe because {@link FCPServer} lookup happens only inside methods.
 *   <li>The adapter performs the minimal translation from detached SPI data to legacy daemon
 *       arguments.
 *   <li>Higher layers still own request parsing, path validation, and HTTP response selection.
 * </ul>
 *
 * @see QueueDownloadPort
 * @see QueueDownloadRequest
 */
public final class LegacyQueueDownloadPort implements QueueDownloadPort {
  private final NodeClientCore core;

  /**
   * Creates a queue-download adapter backed by the supplied client core.
   *
   * <p>The adapter stores only the core reference and resolves the live {@link FCPServer} lazily
   * for each enqueue call. This constructor is therefore safe to use during early runtime-port
   * assembly, before client endpoints and the FCP subsystem are fully initialized.
   *
   * @param core live daemon client core that provides queue access, download policy, and deferred
   *     endpoint lookup
   */
  public LegacyQueueDownloadPort(NodeClientCore core) {
    this.core = Objects.requireNonNull(core);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isDiskDownloadDisabled() {
    return core.isDownloadDisabled();
  }

  /** {@inheritDoc} */
  @Override
  public void enqueueDownload(QueueDownloadRequest request)
      throws QueueDownloadRejectedException, RequestQueueUnavailableException, IOException {
    Objects.requireNonNull(request);
    try {
      fcpServer()
          .makePersistentGlobalRequestBlocking(
              new PersistentGlobalRequestParams(
                  new FreenetURI(request.fetchUri()),
                  request.filterData(),
                  request.expectedMimeType(),
                  request.persistenceType(),
                  request.returnType(),
                  false,
                  request.downloadsDir()));
    } catch (NotAllowedException e) {
      throw new QueueDownloadRejectedException("Queue download rejected", e);
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException("Persistent request queue unavailable", e);
    }
  }

  private FCPServer fcpServer() {
    FCPServer fcpServer = FcpEndpointHandles.serverOrNull(core.getEndpoints().getFcpEndpoint());
    if (fcpServer == null) {
      throw new IllegalStateException("FCP server unavailable");
    }
    return fcpServer;
  }
}
