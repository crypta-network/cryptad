package network.crypta.clients.fcp.bridge;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.client.Metadata;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.client.async.BaseClientPutter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.client.async.ClientPutter;
import network.crypta.client.async.ClientPutterOptions;
import network.crypta.client.async.ClientPutterRequest;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.CompatibilityAnalyser;
import network.crypta.client.async.ContainerInserter;
import network.crypta.client.async.DefaultManifestPutter;
import network.crypta.client.async.InsertRequestParams;
import network.crypta.client.async.ManifestPutter;
import network.crypta.client.async.ManifestPutterParams;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentClientCallback;
import network.crypta.client.async.TooManyFilesInsertException;
import network.crypta.client.async.USKCallback;
import network.crypta.client.async.USKFoundEdition;
import network.crypta.client.async.USKManager;
import network.crypta.client.async.USKProgressCallback;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.clients.fcp.ClientPutDirExecution;
import network.crypta.clients.fcp.ClientPutDirExecutionSpec;
import network.crypta.clients.fcp.ClientPutExecution;
import network.crypta.clients.fcp.ClientPutExecutionSpec;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.clients.fcp.DefaultFcpInsertContextHandle;
import network.crypta.clients.fcp.FCPConnectionHandler;
import network.crypta.clients.fcp.FcpCompatibilityAnalysis;
import network.crypta.clients.fcp.FcpCompatibilityMode;
import network.crypta.clients.fcp.FcpInsertBehaviorOptions;
import network.crypta.clients.fcp.FcpInsertCallback;
import network.crypta.clients.fcp.FcpInsertCallbackState;
import network.crypta.clients.fcp.FcpInsertContextHandle;
import network.crypta.clients.fcp.FcpInsertContextLimits;
import network.crypta.clients.fcp.FcpInsertOptions;
import network.crypta.clients.fcp.FcpInsertRuntimeSupport;
import network.crypta.clients.fcp.FcpInsertTuningOptions;
import network.crypta.clients.fcp.FcpRequestRuntimeContext;
import network.crypta.clients.fcp.FcpRequesterHandle;
import network.crypta.clients.fcp.PersistentPutDirEntrySnapshot;
import network.crypta.clients.fcp.SubscribeUSKCallbacks;
import network.crypta.clients.fcp.SubscribeUSKMessage;
import network.crypta.clients.fcp.UskSubscriptionHandle;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.CryptoResumeContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.USK;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ResumeFailedException;

/**
 * Core-backed implementation of {@link FcpInsertRuntimeSupport}.
 *
 * <p>This adapter owns the concrete translation between the adapter-owned detached insert/USK seam
 * and the live daemon runtime. It also centralizes the compatibility-mode translation used when
 * detached FCP compatibility snapshots are mapped back onto the runtime's mutable {@link
 * InsertContext} and {@link CompatibilityAnalyser} implementations.
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
  public FcpInsertContextHandle defaultPersistentInsertContextHandle() {
    return toInsertContextHandle(clientContext().getDefaultPersistentInsertContext());
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
  public RandomAccessBucket createRedirectMetadataBucket(
      ClientMetadata metadata, FreenetURI redirectTarget, boolean persistentForever)
      throws MetadataUnresolvedException, IOException {
    Metadata redirectMetadata =
        new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, redirectTarget, metadata);
    return redirectMetadata.toBucket(bucketFactory(persistentForever));
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

  static FcpCompatibilityMode toCompatibilityMode(
      InsertContext.CompatibilityMode compatibilityMode) {
    return FcpCompatibilityMode.valueOf(compatibilityMode.name());
  }

  static InsertContext.CompatibilityMode toRuntimeCompatibilityMode(
      FcpCompatibilityMode compatibilityMode) {
    return InsertContext.CompatibilityMode.byCode(compatibilityMode.intern().code());
  }

  static FcpCompatibilityAnalysis toCompatibilityAnalysis(CompatibilityAnalyser analyser) {
    FcpCompatibilityAnalysis analysis = new FcpCompatibilityAnalysis();
    analysis.merge(
        toCompatibilityMode(analyser.min()),
        toCompatibilityMode(analyser.max()),
        analyser.getCryptoKey(),
        analyser.dontCompress(),
        analyser.definitive());
    return analysis;
  }

  static CompatibilityAnalyser toRuntimeCompatibilityAnalyser(FcpCompatibilityAnalysis analysis) {
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();
    analyser.merge(
        toRuntimeCompatibilityMode(analysis.min()),
        toRuntimeCompatibilityMode(analysis.max()),
        analysis.getCryptoKey(),
        analysis.dontCompress(),
        analysis.definitive());
    return analyser;
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

  private static ClientContext requireClientContext(PersistentRequestRuntimeContext context) {
    if (context instanceof FcpRequestRuntimeContext requestContext) {
      return requireClientContext(requestContext.persistentRequestRuntimeContext());
    }
    if (context instanceof ClientContext clientContext) {
      return clientContext;
    }
    String contextType = context == null ? "null" : context.getClass().getName();
    throw new IllegalArgumentException(
        "FCP insert runtime requires ClientContext but got " + contextType);
  }

  private static FcpInsertContextHandle toInsertContextHandle(InsertContext context) {
    return new DefaultFcpInsertContextHandle(
        new FcpInsertContextLimits(
            context.getConsecutiveRNFsCountAsSuccess(),
            context.getSplitfileSegmentDataBlocks(),
            context.getSplitfileSegmentCheckBlocks()),
        new FcpInsertOptions(
            new FcpInsertBehaviorOptions(
                context.isGetCHKOnly(),
                context.isDontCompress(),
                context.isLocalRequestOnly(),
                context.getMaxInsertRetries(),
                context.isEarlyEncode(),
                false,
                context.isIgnoreUSKDatehints()),
            new FcpInsertTuningOptions(
                context.isCanWriteClientCache(),
                context.isForkOnCacheable(),
                context.getCompressorDescriptor(),
                context.getExtraInsertsSingleBlock(),
                context.getExtraInsertsSplitfileHeaderBlock(),
                toCompatibilityMode(context.getCompatibilityMode())),
            null));
  }

  static FcpInsertContextHandle wrapLegacyInsertContext(Object legacyInsertContext)
      throws java.io.InvalidObjectException {
    if (legacyInsertContext == null) {
      return null;
    }
    if (legacyInsertContext instanceof InsertContext context) {
      return new DefaultFcpInsertContextHandle(
          context.getEventProducer(),
          new FcpInsertContextLimits(
              context.getConsecutiveRNFsCountAsSuccess(),
              context.getSplitfileSegmentDataBlocks(),
              context.getSplitfileSegmentCheckBlocks()),
          new FcpInsertOptions(
              new FcpInsertBehaviorOptions(
                  context.isGetCHKOnly(),
                  context.isDontCompress(),
                  context.isLocalRequestOnly(),
                  context.getMaxInsertRetries(),
                  context.isEarlyEncode(),
                  false,
                  context.isIgnoreUSKDatehints()),
              new FcpInsertTuningOptions(
                  context.isCanWriteClientCache(),
                  context.isForkOnCacheable(),
                  context.getCompressorDescriptor(),
                  context.getExtraInsertsSingleBlock(),
                  context.getExtraInsertsSplitfileHeaderBlock(),
                  toCompatibilityMode(context.getCompatibilityMode())),
              null));
    }
    throw new java.io.InvalidObjectException(
        "Legacy insert context is not an InsertContext: "
            + legacyInsertContext.getClass().getName());
  }

  private static InsertContext toRuntimeInsertContext(FcpInsertContextHandle contextHandle) {
    InsertContextOptions options =
        InsertContextOptions.builder()
            .retryLimits(
                contextHandle.getMaxInsertRetries(),
                contextHandle.getConsecutiveRnfsCountAsSuccess())
            .splitfileSegmentLimits(
                contextHandle.getSplitfileSegmentDataBlocks(),
                contextHandle.getSplitfileSegmentCheckBlocks())
            .clientOptions(
                contextHandle.eventProducer(),
                contextHandle.canWriteClientCache(),
                contextHandle.forkOnCacheable(),
                contextHandle.localRequestOnly())
            .compressorDescriptor(contextHandle.getCompressorDescriptor())
            .redundancy(
                contextHandle.getExtraInsertsSingleBlock(),
                contextHandle.getExtraInsertsSplitfileHeaderBlock())
            .compatibility(toRuntimeCompatibilityMode(contextHandle.getCompatibilityMode()))
            .build();
    InsertContext runtimeContext = new InsertContext(options);
    runtimeContext.setGetCHKOnly(contextHandle.getCHKOnly());
    runtimeContext.setDontCompress(contextHandle.isDontCompress());
    runtimeContext.setIgnoreUSKDatehints(contextHandle.ignoreUSKDatehints());
    runtimeContext.setEarlyEncode(contextHandle.earlyEncode());
    return runtimeContext;
  }

  static Object legacyInsertContextForSerialization(FcpInsertContextHandle contextHandle) {
    if (contextHandle == null) {
      return null;
    }
    return toRuntimeInsertContext(contextHandle);
  }

  static ClientPutExecution wrapLegacySingleFileExecution(Object legacyPutter)
      throws java.io.InvalidObjectException {
    if (legacyPutter == null) {
      return null;
    }
    if (legacyPutter instanceof ClientPutter putter) {
      return new CoreClientPutExecution(putter);
    }
    throw new java.io.InvalidObjectException(
        "Legacy single-file putter is not a ClientPutter: " + legacyPutter.getClass().getName());
  }

  static ClientPutDirExecution wrapLegacyDirectoryExecution(
      Object legacyPutter, ClientPutDirExecutionSpec executionSpec)
      throws java.io.InvalidObjectException {
    if (legacyPutter == null) {
      return null;
    }
    if (legacyPutter instanceof ManifestPutter putter) {
      return new CoreClientPutDirExecution(executionSpec, putter);
    }
    throw new java.io.InvalidObjectException(
        "Legacy directory putter is not a ManifestPutter: " + legacyPutter.getClass().getName());
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class CoreClientPutExecution implements ClientPutExecution {
    @Serial private static final long serialVersionUID = 1L;

    private final ClientPutter putter;

    private CoreClientPutExecution(ClientPutExecutionSpec spec) {
      ClientPutterRequest putterRequest =
          new ClientPutterRequest(
              new InsertRequestParams(
                  new CoreInsertCallbackAdapter(spec.callback()),
                  spec.targetURI(),
                  toRuntimeInsertContext(spec.insertContext()),
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
    public FcpRequesterHandle requester() {
      return new CoreRequesterHandle(putter);
    }

    @Override
    public Object legacySerializableRequester() {
      return putter;
    }

    @Override
    public void start(PersistentRequestRuntimeContext context) throws InsertException {
      putter.start(requireClientContext(context));
    }

    @Override
    public boolean canRestart() {
      return putter.canRestart();
    }

    @Override
    public boolean restart(PersistentRequestRuntimeContext context) throws InsertException {
      return putter.restart(requireClientContext(context));
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
    public FcpRequesterHandle requester() {
      return new CoreRequesterHandle(putter);
    }

    @Override
    public Object legacySerializableRequester() {
      return putter;
    }

    @Override
    public void start(PersistentRequestRuntimeContext context) throws InsertException {
      putter.start(requireClientContext(context));
    }

    @Override
    public boolean canRestart() {
      return putter != null;
    }

    @Override
    public boolean restart(PersistentRequestRuntimeContext context) throws InsertException {
      ClientContext clientContext = requireClientContext(context);
      try {
        putter = createManifestPutter(spec, clientContext);
      } catch (TooManyFilesInsertException e) {
        throw new InsertException(InsertException.InsertExceptionMode.TOO_MANY_FILES, e, null);
      }
      putter.start(clientContext);
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
    public List<PersistentPutDirEntrySnapshot> persistentPutDirEntries() {
      return CorePersistentPutDirSnapshotter.snapshot(spec.manifestElements());
    }

    @Override
    public void resumeMetadata(
        Map<String, Object> manifestElements, FcpRequestRuntimeContext context)
        throws ResumeFailedException {
      ContainerInserter.resumeMetadata(manifestElements, requireClientContext(context));
    }
  }

  private static ManifestPutter createManifestPutter(
      ClientPutDirExecutionSpec spec, ClientContext context) throws TooManyFilesInsertException {
    ManifestPutterParams params =
        new ManifestPutterParams(
            new InsertRequestParams(
                new CoreInsertCallbackAdapter(spec.callback()),
                spec.requestParams().uri(),
                toRuntimeInsertContext(spec.insertContext()),
                spec.priorityClass()),
            spec.manifestElements(),
            spec.defaultName(),
            spec.forceCryptoKey(),
            context);
    return DefaultManifestPutter.create(
        params, spec.requestParams().persistence() == Persistence.FOREVER);
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class CoreRequesterHandle implements FcpRequesterHandle {
    @Serial private static final long serialVersionUID = 1L;

    private final ClientRequester requester;

    private CoreRequesterHandle(ClientRequester requester) {
      this.requester = Objects.requireNonNull(requester);
    }

    @Override
    public void cancel(PersistentRequestRuntimeContext context) {
      requester.cancel(requireClientContext(context));
    }

    @Override
    public void setPriorityClass(short priorityClass, PersistentRequestRuntimeContext context) {
      requester.setPriorityClass(priorityClass, requireClientContext(context));
    }

    @Override
    public void setExternalRequestIdentifier(String externalRequestIdentifier) {
      requester.setExternalRequestIdentifier(externalRequestIdentifier);
    }

    @Override
    public void onResume(PersistentRequestRuntimeContext context) throws ResumeFailedException {
      requester.onResume(requireClientContext(context));
    }

    @Override
    public void onShutdown(PersistentRequestRuntimeContext context) {
      requester.onShutdown(requireClientContext(context));
    }

    @Override
    public String toString() {
      return requester.toString();
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class CoreInsertCallbackAdapter
      implements ClientPutCallback, PersistentClientCallback, Serializable {
    @Serial private static final long serialVersionUID = 1L;

    private final FcpInsertCallback callback;

    private CoreInsertCallbackAdapter(FcpInsertCallback callback) {
      this.callback = Objects.requireNonNull(callback);
    }

    @Override
    public void onGeneratedURI(FreenetURI uri, BaseClientPutter state) {
      callback.onGeneratedURI(uri, wrapState(state));
    }

    @Override
    public void onGeneratedMetadata(Bucket metadata, BaseClientPutter state) {
      callback.onGeneratedMetadata(metadata, wrapState(state));
    }

    @Override
    public void onFetchable(BaseClientPutter state) {
      callback.onFetchable(wrapState(state));
    }

    @Override
    public void onSuccess(BaseClientPutter state) {
      callback.onSuccess(wrapState(state));
    }

    @Override
    public void onFailure(InsertException e, BaseClientPutter state) {
      callback.onFailure(e, wrapState(state));
    }

    @Override
    public void onResume(ClientContext context) throws ResumeFailedException {
      callback.onResume(toRequestRuntimeContext(context));
    }

    @Override
    public RequestClient getRequestClient() {
      return callback.getRequestClient();
    }

    @Override
    public void getClientDetail(DataOutputStream dos, ChecksumChecker checker) throws IOException {
      callback.getClientDetail(dos, checker);
    }

    private static FcpInsertCallbackState wrapState(BaseClientPutter state) {
      return state == null ? null : new CoreInsertCallbackState(state);
    }

    private static FcpRequestRuntimeContext toRequestRuntimeContext(ClientContext context) {
      return new CoreFcpRequestRuntimeContext(Objects.requireNonNull(context));
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class CoreInsertCallbackState implements FcpInsertCallbackState {
    private final BaseClientPutter putter;

    private CoreInsertCallbackState(BaseClientPutter putter) {
      this.putter = Objects.requireNonNull(putter);
    }

    @Override
    public FreenetURI getURI() {
      return putter.getURI();
    }

    @Override
    public String toString() {
      return putter.toString();
    }
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

  private record CoreFcpRequestRuntimeContext(ClientContext clientContext)
      implements FcpRequestRuntimeContext, CryptoResumeContext {

    @Override
    public java.util.Random fastWeakRandom() {
      return clientContext.fastWeakRandom();
    }

    @Override
    public network.crypta.support.io.PersistentFilenameGenerator getPersistentFilenameGenerator() {
      return clientContext.getPersistentFilenameGenerator();
    }

    @Override
    public network.crypta.support.io.PersistentFileTracker getPersistentFileTracker() {
      return clientContext.getPersistentFileTracker();
    }

    @Override
    public MasterSecret getPersistentMasterSecret() {
      return clientContext.getPersistentMasterSecret();
    }

    @Override
    public PersistentRequestRuntimeContext persistentRequestRuntimeContext() {
      return clientContext;
    }
  }
}
