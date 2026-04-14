package network.crypta.clients.fcp.bridge;

import java.io.IOException;
import java.io.Serial;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientPutter;
import network.crypta.client.async.ClientPutterOptions;
import network.crypta.client.async.ClientPutterRequest;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.ContainerInserter;
import network.crypta.client.async.DefaultManifestPutter;
import network.crypta.client.async.InsertRequestParams;
import network.crypta.client.async.ManifestPutter;
import network.crypta.client.async.ManifestPutterParams;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.TooManyFilesInsertException;
import network.crypta.client.async.USKCallback;
import network.crypta.client.async.USKFoundEdition;
import network.crypta.client.async.USKManager;
import network.crypta.client.async.USKProgressCallback;
import network.crypta.clients.fcp.ClientPutDirExecution;
import network.crypta.clients.fcp.ClientPutDirExecutionSpec;
import network.crypta.clients.fcp.ClientPutExecution;
import network.crypta.clients.fcp.ClientPutExecutionSpec;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.clients.fcp.FCPConnectionHandler;
import network.crypta.clients.fcp.FcpInsertRuntimeSupport;
import network.crypta.clients.fcp.SubscribeUSKCallbacks;
import network.crypta.clients.fcp.SubscribeUSKMessage;
import network.crypta.clients.fcp.UskSubscriptionHandle;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.USK;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ResumeFailedException;

/**
 * Core-backed implementation of {@link FcpInsertRuntimeSupport}.
 *
 * <p>This adapter owns the concrete translation between the adapter-owned detached insert/USK seam
 * and the live daemon runtime.
 */
record CoreFcpInsertRuntimeSupport(
    NodeClientCore core, Supplier<TransferAccessPort> transferAccessSupplier)
    implements FcpInsertRuntimeSupport {

  CoreFcpInsertRuntimeSupport(
      NodeClientCore core, Supplier<TransferAccessPort> transferAccessSupplier) {
    this.core = Objects.requireNonNull(core);
    this.transferAccessSupplier = Objects.requireNonNull(transferAccessSupplier);
  }

  @Override
  public InsertContext defaultPersistentInsertContext() {
    return clientContext().getDefaultPersistentInsertContext();
  }

  @Override
  public TransferAccessPort transferAccess() {
    return Objects.requireNonNull(transferAccessSupplier.get());
  }

  @Override
  public BucketFactory bucketFactory(boolean persistentForever) {
    return clientContext().getBucketFactory(persistentForever);
  }

  @Override
  public RandomAccessBucket allocatePersistentUploadBucket(long length)
      throws IOException, PersistenceDisabledException {
    if (core.killedDatabase()) {
      throw new PersistenceDisabledException();
    }
    return core.getPersistentTempBucketFactory().makeBucket(length);
  }

  @Override
  public FreenetURI normalizeInsertUri(FreenetURI uri, String filename) {
    if ("SSK".equals(uri.getKeyType()) && uri.getDocName() == null && uri.getRoutingKey() == null) {
      String resolvedFilename = (filename == null || filename.isEmpty()) ? "key" : filename;
      InsertableClientSSK key = InsertableClientSSK.createRandom(clientContext().random, "");
      return key.getInsertURI().setDocName(resolvedFilename);
    }
    return uri;
  }

  @Override
  public ClientPutExecution createSingleFileExecution(ClientPutExecutionSpec executionSpec) {
    return new CoreClientPutExecution(executionSpec);
  }

  @Override
  public ClientPutDirExecution createDirectoryExecution(ClientPutDirExecutionSpec executionSpec)
      throws TooManyFilesInsertException {
    return new CoreClientPutDirExecution(
        executionSpec, createManifestPutter(executionSpec, clientContext()));
  }

  @Override
  public UskSubscriptionHandle subscribeUSK(
      SubscribeUSKMessage message, SubscribeUSKCallbacks callbacks, FCPConnectionHandler handler) {
    return new CoreUskSubscription(message, callbacks, handler);
  }

  private ClientContext clientContext() {
    return Objects.requireNonNull(core.getClientContext());
  }

  static ClientPutExecution wrapLegacySingleFileExecution(Object legacyPutter) {
    if (legacyPutter == null) {
      return null;
    }
    if (legacyPutter instanceof ClientPutter putter) {
      return new CoreClientPutExecution(putter);
    }
    throw new IllegalArgumentException(
        "Legacy single-file putter is not a ClientPutter: " + legacyPutter.getClass().getName());
  }

  static ClientPutDirExecution wrapLegacyDirectoryExecution(
      Object legacyPutter, ClientPutDirExecutionSpec executionSpec) {
    if (legacyPutter == null) {
      return null;
    }
    if (legacyPutter instanceof ManifestPutter putter) {
      return new CoreClientPutDirExecution(executionSpec, putter);
    }
    throw new IllegalArgumentException(
        "Legacy directory putter is not a ManifestPutter: " + legacyPutter.getClass().getName());
  }

  private static final class CoreClientPutExecution implements ClientPutExecution {
    @Serial private static final long serialVersionUID = 1L;

    private final ClientPutter putter;

    private CoreClientPutExecution(ClientPutExecutionSpec spec) {
      ClientPutterRequest putterRequest =
          new ClientPutterRequest(
              new InsertRequestParams(
                  spec.callback(),
                  spec.targetURI(),
                  spec.insertContext(),
                  spec.requestParams().priorityClass()),
              spec.data(),
              spec.clientMetadata(),
              spec.isMetadata());
      ClientPutterOptions putterOptions =
          new ClientPutterOptions(
              spec.targetFilename(),
              spec.binaryBlob(),
              spec.overrideSplitfileCryptoKey(),
              spec.metadataThreshold());
      this.putter = new ClientPutter(putterRequest, putterOptions);
    }

    private CoreClientPutExecution(ClientPutter putter) {
      this.putter = Objects.requireNonNull(putter);
    }

    @Override
    public ClientRequester requester() {
      return putter;
    }

    @Override
    public void start(ClientContext context) throws InsertException {
      putter.start(context);
    }

    @Override
    public boolean canRestart() {
      return putter.canRestart();
    }

    @Override
    public boolean restart(ClientContext context) throws InsertException {
      return putter.restart(context);
    }

    @Override
    public byte[] getSplitfileCryptoKey() {
      return putter.getSplitfileCryptoKey();
    }
  }

  private static final class CoreClientPutDirExecution implements ClientPutDirExecution {
    @Serial private static final long serialVersionUID = 1L;

    private final ClientPutDirExecutionSpec spec;
    private ManifestPutter putter;

    private CoreClientPutDirExecution(ClientPutDirExecutionSpec spec, ManifestPutter putter) {
      this.spec = spec;
      this.putter = putter;
    }

    @Override
    public ClientRequester requester() {
      return putter;
    }

    @Override
    public void start(ClientContext context) throws InsertException {
      putter.start(context);
    }

    @Override
    public boolean canRestart() {
      return putter != null;
    }

    @Override
    public boolean restart(ClientContext context) throws InsertException {
      try {
        putter = createManifestPutter(spec, context);
      } catch (TooManyFilesInsertException e) {
        throw new InsertException(InsertException.InsertExceptionMode.TOO_MANY_FILES, e, null);
      }
      putter.start(context);
      return true;
    }

    @Override
    public byte[] getSplitfileCryptoKey() {
      return putter.getSplitfileCryptoKey();
    }

    @Override
    public int countFiles() {
      return putter.countFiles();
    }

    @Override
    public long totalSize() {
      return putter.totalSize();
    }

    @Override
    public void resumeMetadata(Map<String, Object> manifestElements, ClientContext context)
        throws ResumeFailedException {
      ContainerInserter.resumeMetadata(manifestElements, context);
    }
  }

  private static ManifestPutter createManifestPutter(
      ClientPutDirExecutionSpec spec, ClientContext context) throws TooManyFilesInsertException {
    ManifestPutterParams params =
        new ManifestPutterParams(
            new InsertRequestParams(
                spec.callback(),
                spec.requestParams().uri(),
                spec.insertContext(),
                spec.priorityClass()),
            spec.manifestElements(),
            spec.defaultName(),
            spec.forceCryptoKey(),
            context);
    return DefaultManifestPutter.create(
        params, spec.requestParams().persistence() == Persistence.FOREVER);
  }

  private final class CoreUskSubscription implements UskSubscriptionHandle {
    @Serial private static final long serialVersionUID = 1L;

    private final USK usk;
    private final AtomicReference<USKCallback> unsubscribeToken = new AtomicReference<>();

    private CoreUskSubscription(
        SubscribeUSKMessage message,
        SubscribeUSKCallbacks callbacks,
        FCPConnectionHandler handler) {
      this.usk = message.key();
      USKProgressAdapter progressAdapter = new USKProgressAdapter(callbacks);
      RequestClient requestClient =
          handler.getRebootClient().lowLevelClient(message.realTimeFlag());

      USKCallback token;
      if (message.shouldPoll() && message.sparsePoll()) {
        token =
            uskManager()
                .subscribeSparse(
                    message.key(), progressAdapter, message.ignoreUSKDatehints(), requestClient);
      } else {
        uskManager()
            .subscribe(
                message.key(),
                progressAdapter,
                message.shouldPoll(),
                message.ignoreUSKDatehints(),
                requestClient);
        token = progressAdapter;
      }
      unsubscribeToken.set(token);
    }

    @Override
    public void unsubscribe() {
      USKCallback token = unsubscribeToken.getAndSet(null);
      if (token != null) {
        uskManager().unsubscribe(usk, token);
      }
    }

    private USKManager uskManager() {
      return core.getUskManager();
    }

    private final class USKProgressAdapter implements USKProgressCallback {
      private final SubscribeUSKCallbacks callbacks;

      private USKProgressAdapter(SubscribeUSKCallbacks callbacks) {
        this.callbacks = Objects.requireNonNull(callbacks);
      }

      @Override
      public void onFoundEdition(USKFoundEdition foundEdition) {
        if (callbacks.isClosed()) {
          unsubscribe();
          return;
        }
        callbacks.onFoundEdition(
            foundEdition.edition(),
            foundEdition.key(),
            foundEdition.newKnownGood(),
            foundEdition.newSlotToo());
      }

      @Override
      public short getPollingPriorityNormal() {
        return callbacks.pollingPriorityNormal();
      }

      @Override
      public short getPollingPriorityProgress() {
        return callbacks.pollingPriorityProgress();
      }

      @Override
      public void onSendingToNetwork(ClientContext context) {
        callbacks.onSendingToNetwork();
      }

      @Override
      public void onRoundFinished(ClientContext context) {
        callbacks.onRoundFinished();
      }
    }
  }
}
