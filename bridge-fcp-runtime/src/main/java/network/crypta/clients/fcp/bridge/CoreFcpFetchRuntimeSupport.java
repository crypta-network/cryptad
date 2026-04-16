package network.crypta.clients.fcp.bridge;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.async.BinaryBlobWriter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientGetterOptions;
import network.crypta.client.async.ClientGetterRequest;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.PersistentClientCallback;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.clients.fcp.ClientGet;
import network.crypta.clients.fcp.ClientGetExecution;
import network.crypta.clients.fcp.ClientGetExecutionSpec;
import network.crypta.clients.fcp.ClientGetFetchConfig;
import network.crypta.clients.fcp.FcpFetchRuntimeSupport;
import network.crypta.clients.fcp.FcpRequestRuntimeContext;
import network.crypta.clients.fcp.FcpRequesterHandle;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.NullBucket;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;

/**
 * Core-backed implementation of {@link FcpFetchRuntimeSupport}.
 *
 * <p>This adapter owns the concrete translation between the adapter-owned detached GET seam and the
 * live daemon fetch runtime.
 */
record CoreFcpFetchRuntimeSupport(
    Supplier<ClientContext> clientContextSupplier,
    Supplier<TransferAccessPort> transferAccessSupplier)
    implements FcpFetchRuntimeSupport {

  @SuppressWarnings("java:S2095")
  private static final Bucket NULL_BUCKET = new NullBucket();

  CoreFcpFetchRuntimeSupport(
      Supplier<ClientContext> clientContextSupplier,
      Supplier<TransferAccessPort> transferAccessSupplier) {
    this.clientContextSupplier = Objects.requireNonNull(clientContextSupplier);
    this.transferAccessSupplier = Objects.requireNonNull(transferAccessSupplier);
  }

  CoreFcpFetchRuntimeSupport(
      NodeClientCore core, Supplier<TransferAccessPort> transferAccessSupplier) {
    NodeClientCore nonNullCore = Objects.requireNonNull(core);
    this(nonNullCore::getClientContext, transferAccessSupplier);
  }

  CoreFcpFetchRuntimeSupport(
      ClientContext clientContext, Supplier<TransferAccessPort> transferAccessSupplier) {
    ClientContext nonNullClientContext = Objects.requireNonNull(clientContext);
    this(() -> nonNullClientContext, transferAccessSupplier);
  }

  @Override
  public ClientGetFetchConfig defaultPersistentFetchConfig() {
    return toFetchConfig(clientContext().getDefaultPersistentFetchContext());
  }

  @Override
  public void encodeFetchConfig(ClientGetFetchConfig fetchConfig, DataOutputStream dos)
      throws IOException {
    materializeFetchContext(fetchConfig, null).writeTo(dos);
  }

  @Override
  public ClientGetFetchConfig decodeFetchConfig(DataInputStream dis)
      throws IOException, StorageFormatException {
    return toFetchConfig(new FetchContext(dis));
  }

  @Override
  public DataInputStream openChecksummed(
      DataInputStream dis, ChecksumChecker checker, long maxLength)
      throws IOException, StorageFormatException {
    try {
      return new DataInputStream(
          checker.checksumReaderWithLength(dis, clientContext().tempBucketFactory, maxLength));
    } catch (ChecksumFailedException e) {
      StorageFormatException storageFormatException = new StorageFormatException("Checksum failed");
      storageFormatException.initCause(e);
      throw storageFormatException;
    }
  }

  @Override
  public Bucket restorePersistentBucket(DataInputStream dis)
      throws IOException, StorageFormatException, ResumeFailedException {
    ClientContext context = clientContext();
    return BucketTools.restoreFrom(
        dis,
        context.persistentFG,
        context.getPersistentFileTracker(),
        context.getPersistentMasterSecret());
  }

  @Override
  public TransferAccessPort transferAccess() {
    return Objects.requireNonNull(transferAccessSupplier.get());
  }

  @Override
  public ClientGetExecution createExecution(ClientGetExecutionSpec executionSpec)
      throws IOException {
    return new CoreClientGetExecution(clientContextSupplier, executionSpec);
  }

  private ClientContext clientContext() {
    return Objects.requireNonNull(clientContextSupplier.get());
  }

  private static FetchContext materializeFetchContext(
      ClientGetFetchConfig fetchConfig, ClientEventListener eventListener) {
    FetchContextOptions options =
        FetchContextOptions.builder()
            .limits(
                fetchConfig.getMaxOutputLength(),
                fetchConfig.getMaxTempLength(),
                fetchConfig.getMaxMetadataSize())
            .archiveLimits(
                fetchConfig.getMaxRecursionLevel(),
                fetchConfig.getMaxArchiveRestarts(),
                fetchConfig.getMaxArchiveLevels(),
                fetchConfig.getDontEnterImplicitArchives())
            .retryLimits(
                fetchConfig.getMaxSplitfileBlockRetries(),
                fetchConfig.getMaxNonSplitfileRetries(),
                fetchConfig.getMaxUSKRetries())
            .splitfileLimits(
                fetchConfig.getAllowSplitfiles(),
                fetchConfig.getMaxDataBlocksPerSegment(),
                fetchConfig.getMaxCheckBlocksPerSegment())
            .behavior(
                fetchConfig.getFollowRedirects(),
                fetchConfig.getLocalRequestOnly(),
                fetchConfig.getFilterData())
            .clientOptions(
                new SimpleEventProducer(),
                fetchConfig.getIgnoreTooManyPathComponents(),
                fetchConfig.getCanWriteClientCache())
            .filterOverrides(
                fetchConfig.getCharset(),
                fetchConfig.getOverrideMime(),
                fetchConfig.getSchemeHostAndPort())
            .build();
    return createFetchContext(fetchConfig, eventListener, options);
  }

  private static FetchContext createFetchContext(
      ClientGetFetchConfig fetchConfig,
      ClientEventListener eventListener,
      FetchContextOptions options) {
    FetchContext fetchContext = new FetchContext(options);
    fetchContext.setIgnoreStore(fetchConfig.getIgnoreStore());
    fetchContext.setReturnZIPManifests(fetchConfig.getReturnZIPManifests());
    fetchContext.setAllowedMIMETypes(copyAllowedMimeTypes(fetchConfig.getAllowedMimeTypes()));
    fetchContext.setCooldownRetries(fetchConfig.getCooldownRetries());
    fetchContext.setCooldownTime(fetchConfig.getCooldownTime(), true);
    fetchContext.setIgnoreUSKDatehints(fetchConfig.getIgnoreUSKDatehints());
    if (eventListener != null) {
      fetchContext.getEventProducer().addEventListener(eventListener);
    }
    return fetchContext;
  }

  private static ClientGetFetchConfig toFetchConfig(FetchContext fetchContext) {
    ClientGetFetchConfig fetchConfig = new ClientGetFetchConfig();
    fetchConfig.setMaxOutputLength(fetchContext.getMaxOutputLength());
    fetchConfig.setMaxTempLength(fetchContext.getMaxTempLength());
    fetchConfig.setMaxRecursionLevel(fetchContext.getMaxRecursionLevel());
    fetchConfig.setMaxArchiveRestarts(fetchContext.getMaxArchiveRestarts());
    fetchConfig.setMaxArchiveLevels(fetchContext.getMaxArchiveLevels());
    fetchConfig.setDontEnterImplicitArchives(fetchContext.getDontEnterImplicitArchives());
    fetchConfig.setMaxSplitfileBlockRetries(fetchContext.getMaxSplitfileBlockRetries());
    fetchConfig.setMaxNonSplitfileRetries(fetchContext.getMaxNonSplitfileRetries());
    fetchConfig.setMaxUSKRetries(fetchContext.getMaxUSKRetries());
    fetchConfig.setAllowSplitfiles(fetchContext.getAllowSplitfiles());
    fetchConfig.setFollowRedirects(fetchContext.getFollowRedirects());
    fetchConfig.setLocalRequestOnly(fetchContext.getLocalRequestOnly());
    fetchConfig.setIgnoreStore(fetchContext.getIgnoreStore());
    fetchConfig.setMaxMetadataSize(fetchContext.getMaxMetadataSize());
    fetchConfig.setMaxDataBlocksPerSegment(fetchContext.getMaxDataBlocksPerSegment());
    fetchConfig.setMaxCheckBlocksPerSegment(fetchContext.getMaxCheckBlocksPerSegment());
    fetchConfig.setReturnZIPManifests(fetchContext.getReturnZIPManifests());
    fetchConfig.setFilterData(fetchContext.getFilterData());
    fetchConfig.setIgnoreTooManyPathComponents(fetchContext.getIgnoreTooManyPathComponents());
    fetchConfig.setAllowedMimeTypes(copyAllowedMimeTypes(fetchContext.getAllowedMIMETypes()));
    fetchConfig.setCharset(fetchContext.getCharset());
    fetchConfig.setCanWriteClientCache(fetchContext.getCanWriteClientCache());
    fetchConfig.setOverrideMime(fetchContext.getOverrideMIME());
    fetchConfig.setCooldownRetries(fetchContext.getCooldownRetries());
    fetchConfig.setCooldownTime(fetchContext.getCooldownTime());
    fetchConfig.setIgnoreUSKDatehints(fetchContext.getIgnoreUSKDatehints());
    fetchConfig.setSchemeHostAndPort(fetchContext.getSchemeHostAndPort());
    return fetchConfig;
  }

  private static Set<String> copyAllowedMimeTypes(Set<String> allowedMimeTypes) {
    return allowedMimeTypes == null ? null : new HashSet<>(allowedMimeTypes);
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
        "FCP GET execution resume requires ClientContext but got " + contextType);
  }

  private static final class CoreClientGetExecution implements ClientGetExecution {
    @Serial private static final long serialVersionUID = 1L;

    private transient Supplier<ClientContext> clientContextSupplier;
    private final ClientGetter getter;
    private FcpRequesterHandle requesterHandle;

    private CoreClientGetExecution(
        Supplier<ClientContext> clientContextSupplier, ClientGetExecutionSpec executionSpec)
        throws IOException {
      this.clientContextSupplier = Objects.requireNonNull(clientContextSupplier);
      CoreCallbackAdapter callback = new CoreCallbackAdapter(executionSpec.request());
      FetchContext fetchContext =
          materializeFetchContext(executionSpec.fetchConfig(), executionSpec.eventListener());
      ClientGetterRequest getterRequest =
          new ClientGetterRequest(
              callback, executionSpec.uri(), fetchContext, executionSpec.priorityClass());
      ClientGetterOptions options = createOptions(executionSpec, fetchContext);
      this.getter = new ClientGetter(getterRequest, options);
      this.requesterHandle = new CoreRequesterHandle(getter);
    }

    @Override
    public FcpRequesterHandle requester() {
      if (requesterHandle == null) {
        requesterHandle = new CoreRequesterHandle(getter);
      }
      return requesterHandle;
    }

    @Override
    public void onResume(PersistentRequestRuntimeContext context) {
      clientContextSupplier = () -> requireClientContext(context);
    }

    @Override
    public void start() throws FetchException {
      getter.start(clientContext());
    }

    @Override
    public boolean canRestart() {
      return getter.canRestart();
    }

    @Override
    public boolean restart(FreenetURI redirect, boolean filterData) throws FetchException {
      return getter.restart(redirect, filterData, clientContext());
    }

    @Override
    public String expectedMime() {
      return getter.expectedMIME();
    }

    @Override
    public long expectedSize() {
      return getter.expectedSize();
    }

    @Override
    public Bucket blobBucket() {
      return getter.getBlobBucket();
    }

    @Override
    public boolean writeTrivialProgress(DataOutputStream dos) throws IOException {
      return getter.writeTrivialProgress(dos);
    }

    @Override
    public boolean resumeFromTrivialProgress(DataInputStream dis) throws IOException {
      return getter.resumeFromTrivialProgress(dis, clientContext());
    }

    @Override
    public boolean resumedFetcher() {
      return getter.resumedFetcher();
    }

    private ClientContext clientContext() {
      return Objects.requireNonNull(clientContextSupplier.get());
    }

    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
      in.defaultReadObject();
      clientContextSupplier = null;
      if (requesterHandle == null) {
        requesterHandle = new CoreRequesterHandle(getter);
      }
    }

    private ClientGetterOptions createOptions(
        ClientGetExecutionSpec executionSpec, FetchContext fetchContext) throws IOException {
      Bucket returnBucket = executionSpec.returnBucket();
      if (executionSpec.binaryBlob()) {
        Bucket blobBucket = returnBucket;
        if (blobBucket == null) {
          blobBucket =
              clientContext()
                  .getBucketFactory(executionSpec.persistenceForever())
                  .makeBucket(fetchContext.getMaxOutputLength());
        }
        return new ClientGetterOptions(
            NULL_BUCKET,
            new BinaryBlobWriter(blobBucket),
            false,
            executionSpec.initialMetadata(),
            executionSpec.extensionCheck());
      }
      if (executionSpec.discardData()) {
        returnBucket = NULL_BUCKET;
      }
      return new ClientGetterOptions(
          returnBucket,
          null,
          false,
          executionSpec.initialMetadata(),
          executionSpec.extensionCheck());
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class CoreCallbackAdapter
      implements ClientGetCallback, PersistentClientCallback, Serializable {
    @Serial private static final long serialVersionUID = 1L;

    private final ClientGet request;

    private CoreCallbackAdapter(ClientGet request) {
      this.request = request;
    }

    @Override
    public void onSuccess(FetchResult result, ClientGetter state) {
      request.onSuccess(result, new CallbackSuccessExecution(state));
    }

    @Override
    public void onFailure(FetchException e) {
      request.onFailure(e);
    }

    @Override
    public void onResume(ClientContext context) throws ResumeFailedException {
      request.onResume(context);
    }

    @Override
    public RequestClient getRequestClient() {
      return request.getRequestClient();
    }

    @Override
    public void getClientDetail(DataOutputStream dos, ChecksumChecker checker) throws IOException {
      request.getClientDetail(dos, checker);
    }
  }

  private static final class CallbackSuccessExecution implements ClientGetExecution {
    @Serial private static final long serialVersionUID = 1L;

    private final ClientGetter getter;
    private final FcpRequesterHandle requesterHandle;

    private CallbackSuccessExecution(ClientGetter getter) {
      this.getter = Objects.requireNonNull(getter);
      this.requesterHandle = new CoreRequesterHandle(getter);
    }

    @Override
    public FcpRequesterHandle requester() {
      return requesterHandle;
    }

    @Override
    public void onResume(PersistentRequestRuntimeContext context) {
      // Success callback executions are ephemeral wrappers and do not hold resume-only state.
    }

    @Override
    public void start() {
      throw new UnsupportedOperationException("Success callback execution cannot be started");
    }

    @Override
    public boolean canRestart() {
      return getter.canRestart();
    }

    @Override
    public boolean restart(FreenetURI redirect, boolean filterData) {
      throw new UnsupportedOperationException("Success callback execution cannot be restarted");
    }

    @Override
    public String expectedMime() {
      return getter.expectedMIME();
    }

    @Override
    public long expectedSize() {
      return getter.expectedSize();
    }

    @Override
    public Bucket blobBucket() {
      return getter.getBlobBucket();
    }

    @Override
    public boolean writeTrivialProgress(DataOutputStream dos) throws IOException {
      return getter.writeTrivialProgress(dos);
    }

    @Override
    public boolean resumeFromTrivialProgress(DataInputStream dis) {
      throw new UnsupportedOperationException(
          "Success callback execution cannot resume trivial progress");
    }

    @Override
    public boolean resumedFetcher() {
      return getter.resumedFetcher();
    }
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
}
