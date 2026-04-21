package network.crypta.clients.fcp.bridge;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.HighLevelSimpleClientImpl;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.TooManyFilesInsertException;
import network.crypta.clients.fcp.ClientPut;
import network.crypta.clients.fcp.ClientPutBase.UploadFrom;
import network.crypta.clients.fcp.ClientPutDir;
import network.crypta.clients.fcp.ClientPutUpload;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.FcpCompatibilityMode;
import network.crypta.clients.fcp.FcpInsertBehaviorOptions;
import network.crypta.clients.fcp.FcpInsertOptions;
import network.crypta.clients.fcp.FcpInsertRequest;
import network.crypta.clients.fcp.FcpInsertTuningOptions;
import network.crypta.clients.fcp.IdentifierCollisionException;
import network.crypta.clients.fcp.NotAllowedException;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.runtime.endpoints.ClientEndpoints;
import network.crypta.runtime.spi.QueueBrowserUploadInsertRequest;
import network.crypta.runtime.spi.QueueInsertFailureReason;
import network.crypta.runtime.spi.QueueInsertOutcome;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.runtime.spi.QueueInsertRejectedException;
import network.crypta.runtime.spi.QueueLocalDirectoryInsertRequest;
import network.crypta.runtime.spi.QueueLocalFileInsertRequest;
import network.crypta.runtime.spi.QueueUploadedFile;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Legacy daemon-backed implementation of the queue-insert runtime SPI.
 *
 * <p>This adapter keeps the remaining creation of new queue uploads and local inserts inside the
 * daemon root module while exposing only small JDK-only request shapes upstream. It preserves the
 * current legacy flow by scheduling work on the client-layer persister, recreating the matching
 * {@link ClientPut} or {@link ClientPutDir} request, and starting the request through the live
 * {@link FCPServer}.
 *
 * <p>The adapter is intentionally thin and stores only the owning {@link NodeClientCore}. The live
 * {@link FCPServer} is resolved lazily through {@link NodeClientCore#getEndpoints()} for each
 * request so runtime-port construction does not force early endpoint initialization during startup.
 * Browser-upload staging still happens before the persistent job is queued, which preserves the
 * older queue-toadlet behavior and avoids holding the persister runner while large uploads are
 * copied.
 *
 * <ul>
 *   <li>HTTP parsing and redirect mapping stay outside this class.
 *   <li>Persistent queue registration and legacy insert construction happen here.
 *   <li>Queue-unavailable conditions are translated into {@link RequestQueueUnavailableException}
 *       for stable caller handling.
 * </ul>
 */
public final class LegacyQueueInsertPort implements QueueInsertPort {
  private static final Logger LOG = LoggerFactory.getLogger(LegacyQueueInsertPort.class);

  private final NodeClientCore core;

  /**
   * Creates a queue-insert adapter backed by the supplied client core.
   *
   * <p>The adapter does not resolve daemon endpoints during construction. It only keeps the live
   * client core reference and defers queue access until one of the port methods is invoked.
   *
   * @param core live daemon client core that provides queue access, bucket factories, and deferred
   *     endpoint lookup
   */
  public LegacyQueueInsertPort(NodeClientCore core) {
    this.core = Objects.requireNonNull(core);
  }

  /** {@inheritDoc} */
  @Override
  public QueueInsertOutcome enqueueBrowserUploadInsert(QueueBrowserUploadInsertRequest request)
      throws QueueInsertRejectedException, RequestQueueUnavailableException, IOException {
    Objects.requireNonNull(request);
    try (TransferableBucketResource<RandomAccessBucket> copiedBucket =
        new TransferableBucketResource<>(copyUploadedFile(request.upload()))) {
      QueueInsertOutcome outcome =
          runInsertJob(() -> startBrowserUploadInsert(request, copiedBucket.bucket()));
      if (outcome == QueueInsertOutcome.STARTED) {
        copiedBucket.release();
      }
      return outcome;
    }
  }

  /** {@inheritDoc} */
  @Override
  public QueueInsertOutcome enqueueLocalFileInsert(QueueLocalFileInsertRequest request)
      throws QueueInsertRejectedException, RequestQueueUnavailableException, IOException {
    Objects.requireNonNull(request);
    return runInsertJob(() -> startLocalFileInsert(request));
  }

  /** {@inheritDoc} */
  @Override
  public QueueInsertOutcome enqueueLocalDirectoryInsert(QueueLocalDirectoryInsertRequest request)
      throws QueueInsertRejectedException, RequestQueueUnavailableException, IOException {
    Objects.requireNonNull(request);
    return runInsertJob(() -> startLocalDirectoryInsert(request));
  }

  private QueueInsertOutcome runInsertJob(InsertTask task)
      throws QueueInsertRejectedException, RequestQueueUnavailableException, IOException {
    CountDownLatch done = new CountDownLatch(1);
    AtomicReference<QueueInsertOutcome> outcomeRef = new AtomicReference<>();
    AtomicReference<QueueInsertRejectedException> rejectedRef = new AtomicReference<>();
    AtomicReference<RequestQueueUnavailableException> unavailableRef = new AtomicReference<>();
    AtomicReference<IOException> ioRef = new AtomicReference<>();
    AtomicReference<RuntimeException> runtimeRef = new AtomicReference<>();
    try {
      core.getClientLayerPersister()
          .queue(
              new PersistentJob() {
                @Override
                public String toString() {
                  return "LegacyQueueInsertPort";
                }

                @Override
                public boolean run(ClientContext context) {
                  try {
                    QueueInsertOutcome outcome = task.run();
                    outcomeRef.set(outcome);
                    return outcome == QueueInsertOutcome.STARTED;
                  } catch (QueueInsertRejectedException e) {
                    rejectedRef.set(e);
                  } catch (RequestQueueUnavailableException e) {
                    unavailableRef.set(e);
                  } catch (IOException e) {
                    ioRef.set(e);
                  } catch (RuntimeException e) {
                    runtimeRef.set(e);
                  } finally {
                    done.countDown();
                  }
                  return false;
                }
              },
              NativeThread.PriorityLevel.HIGH_PRIORITY.value + 1);
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException("Persistent request queue unavailable", e);
    }

    try {
      done.await();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while waiting for queue insert creation", e);
    }

    if (runtimeRef.get() != null) {
      throw runtimeRef.get();
    }
    if (rejectedRef.get() != null) {
      throw rejectedRef.get();
    }
    if (unavailableRef.get() != null) {
      throw unavailableRef.get();
    }
    if (ioRef.get() != null) {
      throw ioRef.get();
    }
    QueueInsertOutcome outcome = outcomeRef.get();
    if (outcome == null) {
      throw new IllegalStateException("Missing queue insert outcome");
    }
    return outcome;
  }

  private QueueInsertOutcome startBrowserUploadInsert(
      QueueBrowserUploadInsertRequest request, RandomAccessBucket copiedBucket)
      throws QueueInsertRejectedException, RequestQueueUnavailableException, IOException {
    FCPServer fcpServer = fcpServer();
    try {
      ClientPut clientPut = createBrowserUploadClientPut(request, copiedBucket, fcpServer);
      return startClientPut(clientPut, fcpServer, "Upload insert start collision");
    } catch (IdentifierCollisionException _) {
      LOG.error("Upload insert request collision: cannot put same file twice in same millisecond");
      return QueueInsertOutcome.IDENTIFIER_COLLISION;
    } catch (NotAllowedException e) {
      throw rejected(QueueInsertFailureReason.ACCESS_DENIED, e);
    } catch (FileNotFoundException e) {
      throw rejected(QueueInsertFailureReason.SOURCE_NOT_FOUND, e);
    } catch (MetadataUnresolvedException e) {
      LOG.error("Unresolved metadata in starting insert from data uploaded from browser: {}", e, e);
      return QueueInsertOutcome.METADATA_UNRESOLVED;
    }
  }

  private QueueInsertOutcome startLocalFileInsert(QueueLocalFileInsertRequest request)
      throws QueueInsertRejectedException, RequestQueueUnavailableException, IOException {
    try (TransferableBucketResource<FileBucket> bucket =
        new TransferableBucketResource<>(
            new FileBucket(request.sourceFile(), true, false, false, false))) {
      FCPServer fcpServer = fcpServer();
      try {
        ClientPut clientPut = createLocalFileClientPut(request, bucket.bucket(), fcpServer);
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Started global request to insert {} to {} as {}",
              request.sourceFile(),
              request.insertUri(),
              request.identifier());
        }
        QueueInsertOutcome outcome =
            startClientPut(clientPut, fcpServer, "Local file insert collision");
        if (outcome == QueueInsertOutcome.STARTED) {
          bucket.release();
        }
        return outcome;
      } catch (IdentifierCollisionException _) {
        LOG.error("Local file insert collision: cannot put same file twice in same millisecond");
        return QueueInsertOutcome.IDENTIFIER_COLLISION;
      } catch (NotAllowedException e) {
        throw rejected(QueueInsertFailureReason.ACCESS_DENIED, e);
      } catch (FileNotFoundException e) {
        throw rejected(QueueInsertFailureReason.SOURCE_NOT_FOUND, e);
      } catch (MetadataUnresolvedException e) {
        LOG.error("Unresolved metadata in starting insert from data from file: {}", e, e);
        return QueueInsertOutcome.METADATA_UNRESOLVED;
      }
    }
  }

  private QueueInsertOutcome startLocalDirectoryInsert(QueueLocalDirectoryInsertRequest request)
      throws QueueInsertRejectedException, RequestQueueUnavailableException, IOException {
    FCPServer fcpServer = fcpServer();
    try {
      ClientPutDir clientPutDir = createLocalDirectoryPut(request, fcpServer);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Started global request to insert dir {} to {} as {}",
            request.sourceDirectory(),
            request.insertUri(),
            request.identifier());
      }
      return startClientPut(clientPutDir, fcpServer, "Local directory insert collision");
    } catch (IdentifierCollisionException _) {
      LOG.error("Local directory insert collision: cannot put same file twice in same millisecond");
      return QueueInsertOutcome.IDENTIFIER_COLLISION;
    } catch (FileNotFoundException e) {
      throw rejected(QueueInsertFailureReason.SOURCE_NOT_FOUND, e);
    } catch (TooManyFilesInsertException e) {
      throw rejected(QueueInsertFailureReason.TOO_MANY_FILES, e);
    }
  }

  private QueueInsertOutcome startClientPut(
      network.crypta.clients.fcp.ClientRequest request,
      FCPServer fcpServer,
      String collisionMessage)
      throws RequestQueueUnavailableException, IdentifierCollisionException {
    try {
      fcpServer.startBlocking(request);
      return QueueInsertOutcome.STARTED;
    } catch (IdentifierCollisionException _) {
      LOG.error("{}: cannot put same file twice in same millisecond", collisionMessage);
      return QueueInsertOutcome.IDENTIFIER_COLLISION;
    } catch (PersistenceDisabledException e) {
      throw new RequestQueueUnavailableException("Persistent request queue unavailable", e);
    }
  }

  private RandomAccessBucket copyUploadedFile(QueueUploadedFile upload) throws IOException {
    RandomAccessBucket copiedBucket =
        core.getPersistentTempBucketFactory().makeBucket(upload.size());
    try (InputStream inputStream = upload.openStream();
        OutputStream outputStream = copiedBucket.getOutputStream()) {
      inputStream.transferTo(outputStream);
      return copiedBucket;
    } catch (IOException e) {
      copiedBucket.free();
      throw e;
    }
  }

  private FcpInsertRequest insertRequest(FCPServer fcpServer, String insertUri, String identifier)
      throws IOException {
    try {
      return new FcpInsertRequest(
          fcpServer.getGlobalForeverClient(),
          new FreenetURI(insertUri),
          identifier,
          Integer.MAX_VALUE,
          null,
          RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
          Persistence.FOREVER,
          null,
          true);
    } catch (MalformedURLException e) {
      throw new IOException("Invalid insert URI", e);
    }
  }

  private static FcpInsertOptions insertOptions(
      boolean compress, String compatibilityMode, byte[] overrideSplitfileCryptoKey) {
    return new FcpInsertOptions(
        new FcpInsertBehaviorOptions(false, !compress, false, -1, null, false, false, false),
        new FcpInsertTuningOptions(
            false,
            Node.FORK_ON_CACHEABLE_DEFAULT,
            null,
            HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK,
            HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER,
            FcpCompatibilityMode.valueOf(compatibilityMode).intern()),
        overrideSplitfileCryptoKey);
  }

  private static QueueInsertRejectedException rejected(
      QueueInsertFailureReason reason, Exception cause) {
    return new QueueInsertRejectedException(reason, "Queue insert rejected: " + reason, cause);
  }

  ClientPut createBrowserUploadClientPut(
      QueueBrowserUploadInsertRequest request, RandomAccessBucket copiedBucket, FCPServer fcpServer)
      throws NotAllowedException,
          MetadataUnresolvedException,
          IdentifierCollisionException,
          IOException {
    return new ClientPut(
        insertRequest(fcpServer, request.insertUri(), request.identifier()),
        insertOptions(
            request.compress(), request.compatibilityMode(), request.overrideSplitfileCryptoKey()),
        new ClientPutUpload(
            UploadFrom.DIRECT,
            null,
            request.upload().contentType(),
            copiedBucket,
            null,
            request.filenameForKey(),
            false),
        fcpServer);
  }

  ClientPut createLocalFileClientPut(
      QueueLocalFileInsertRequest request, FileBucket bucket, FCPServer fcpServer)
      throws NotAllowedException,
          MetadataUnresolvedException,
          IdentifierCollisionException,
          IOException {
    return new ClientPut(
        insertRequest(fcpServer, request.insertUri(), request.identifier()),
        insertOptions(
            request.compress(), request.compatibilityMode(), request.overrideSplitfileCryptoKey()),
        new ClientPutUpload(
            UploadFrom.DISK,
            request.sourceFile(),
            request.contentType(),
            bucket,
            null,
            request.targetFilename(),
            false),
        fcpServer);
  }

  ClientPutDir createLocalDirectoryPut(
      QueueLocalDirectoryInsertRequest request, FCPServer fcpServer)
      throws IOException, TooManyFilesInsertException {
    return new ClientPutDir(
        insertRequest(fcpServer, request.insertUri(), request.identifier()),
        insertOptions(
            request.compress(), request.compatibilityMode(), request.overrideSplitfileCryptoKey()),
        request.sourceDirectory(),
        null,
        false,
        false,
        fcpServer);
  }

  private FCPServer fcpServer() throws RequestQueueUnavailableException {
    ClientEndpoints clientEndpoints = core.getEndpoints();
    if (clientEndpoints == null) {
      throw new RequestQueueUnavailableException("Persistent request queue unavailable");
    }
    FCPServer fcpServer = FcpEndpointHandles.serverOrNull(clientEndpoints.getFcpEndpoint());
    if (fcpServer == null) {
      throw new RequestQueueUnavailableException("Persistent request queue unavailable");
    }
    return fcpServer;
  }

  @FunctionalInterface
  private interface InsertTask {
    QueueInsertOutcome run()
        throws QueueInsertRejectedException, RequestQueueUnavailableException, IOException;
  }

  private static final class TransferableBucketResource<T extends Bucket> implements AutoCloseable {
    private T bucket;

    private TransferableBucketResource(T bucket) {
      this.bucket = Objects.requireNonNull(bucket);
    }

    private T bucket() {
      return bucket;
    }

    private void release() {
      bucket = null;
    }

    @Override
    public void close() {
      if (bucket != null) {
        bucket.free();
      }
    }
  }
}
