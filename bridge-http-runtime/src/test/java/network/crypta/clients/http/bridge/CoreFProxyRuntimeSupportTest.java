package network.crypta.clients.http.bridge;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.DownloadCache;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.http.FProxyRuntimeSupport;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.SecurityLevels;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.services.NodeServicesSubsystem;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedConstruction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class CoreFProxyRuntimeSupportTest {

  @Test
  void constructor_whenCoreIsNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new CoreFProxyRuntimeSupport(null));
  }

  @Test
  void delegates_whenCoreProvidesValues_expectSameValuesAndBackgroundExecution() {
    RuntimeContext context =
        newRuntimeContext(NETWORK_THREAT_LEVEL.NORMAL, PHYSICAL_THREAT_LEVEL.HIGH);
    ClientContext clientContext = mock(ClientContext.class);
    File downloadsDir = new File("build/tmp/downloads");
    File downloadTarget = new File(downloadsDir, "target.bin");
    File[] allowedDirs = {downloadsDir, new File("build/tmp/shared")};
    when(context.core().getClientContext()).thenReturn(clientContext);
    when(context.core().isDownloadDisabled()).thenReturn(true);
    when(context.core().getDownloadsDir()).thenReturn(downloadsDir);
    when(context.core().allowDownloadTo(downloadTarget)).thenReturn(false);
    when(context.core().getAllowedDownloadDirs()).thenReturn(allowedDirs);

    assertSame(downloadsDir, context.runtimeSupport().downloadsDir());
    assertSame(allowedDirs, context.runtimeSupport().allowedDownloadDirs());
    assertTrue(context.runtimeSupport().isDownloadDisabled());
    assertFalse(context.runtimeSupport().allowDownloadTo(downloadTarget));
    assertSame(context.fproxyConfig(), context.runtimeSupport().fproxyConfig());

    Runnable task = mock(Runnable.class);
    context.runtimeSupport().executeBackground(task);

    verify(context.executor()).execute(task);
  }

  @Test
  void createTempBucket_whenFactoryAllocatesBucket_returnsSameBucket() throws IOException {
    RuntimeContext context =
        newRuntimeContext(NETWORK_THREAT_LEVEL.NORMAL, PHYSICAL_THREAT_LEVEL.NORMAL);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    when(context.core().getTempBucketFactory()).thenReturn(tempBucketFactory);
    when(tempBucketFactory.makeBucket(4096L)).thenReturn(bucket);

    var actualBucket = context.runtimeSupport().createTempBucket(4096L);

    assertSame(bucket, actualBucket);
  }

  @Test
  void createTempBucket_whenFactoryThrowsIOException_propagatesIOException() throws IOException {
    RuntimeContext context =
        newRuntimeContext(NETWORK_THREAT_LEVEL.NORMAL, PHYSICAL_THREAT_LEVEL.NORMAL);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    IOException failure = new IOException("disk full");
    when(context.core().getTempBucketFactory()).thenReturn(tempBucketFactory);
    when(tempBucketFactory.makeBucket(-1L)).thenThrow(failure);

    //noinspection resource
    IOException thrown =
        assertThrows(IOException.class, () -> context.runtimeSupport().createTempBucket(-1L));

    assertSame(failure, thrown);
  }

  @Test
  void lookupCachedResult_whenDownloadCacheMissing_returnsNull() {
    RuntimeContext context =
        newRuntimeContext(NETWORK_THREAT_LEVEL.NORMAL, PHYSICAL_THREAT_LEVEL.NORMAL);
    ClientContext clientContext = mock(ClientContext.class);
    FreenetURI uri = mock(FreenetURI.class);
    when(context.core().getClientContext()).thenReturn(clientContext);
    when(clientContext.getDownloadCache()).thenReturn(null);

    var result = context.runtimeSupport().lookupCachedResult(uri, true);

    assertNull(result);
  }

  @Test
  void lookupCachedResult_whenDownloadCachePresent_delegatesLookupParameters() {
    RuntimeContext context =
        newRuntimeContext(NETWORK_THREAT_LEVEL.NORMAL, PHYSICAL_THREAT_LEVEL.NORMAL);
    ClientContext clientContext = mock(ClientContext.class);
    DownloadCache downloadCache = mock(DownloadCache.class);
    CacheFetchResult cacheFetchResult = mock(CacheFetchResult.class);
    FreenetURI uri = mock(FreenetURI.class);
    when(context.core().getClientContext()).thenReturn(clientContext);
    when(clientContext.getDownloadCache()).thenReturn(downloadCache);
    when(downloadCache.lookupInstant(uri, false, false, null)).thenReturn(cacheFetchResult);

    var result = context.runtimeSupport().lookupCachedResult(uri, false);

    assertSame(cacheFetchResult, result);
  }

  @Test
  void startFetch_whenStarted_returnsCancelableHandleAndForwardsCallback() throws Exception {
    RuntimeContext context =
        newRuntimeContext(NETWORK_THREAT_LEVEL.NORMAL, PHYSICAL_THREAT_LEVEL.NORMAL);
    ClientContext clientContext = mock(ClientContext.class);
    FreenetURI uri = mock(FreenetURI.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RequestClient requestClient = mock(RequestClient.class);
    FProxyRuntimeSupport.FetchCallback callback = mock(FProxyRuntimeSupport.FetchCallback.class);
    FetchResult fetchResult = mock(FetchResult.class);
    FetchException failure = new FetchException(FetchException.FetchExceptionMode.DATA_NOT_FOUND);
    when(context.core().getClientContext()).thenReturn(clientContext);

    AtomicReference<List<?>> constructorArguments = new AtomicReference<>();
    try (MockedConstruction<ClientGetter> getters =
        mockConstruction(
            ClientGetter.class,
            (_, construction) ->
                constructorArguments.set(new ArrayList<>(construction.arguments())))) {
      FProxyRuntimeSupport.FetchHandle handle =
          context
              .runtimeSupport()
              .startFetch(uri, fetchContext, (short) 7, requestClient, callback);

      ClientGetter getter = getters.constructed().getFirst();
      verify(clientContext).start(getter);

      ClientGetCallback runtimeCallback = (ClientGetCallback) constructorArguments.get().getFirst();
      assertSame(requestClient, runtimeCallback.getRequestClient());

      runtimeCallback.onSuccess(fetchResult, getter);
      runtimeCallback.onFailure(failure);

      verify(callback).onSuccess(fetchResult);
      verify(callback).onFailure(failure);

      handle.cancel();

      verify(getter).cancel(clientContext);
    }

    assertSame(uri, constructorArguments.get().get(1));
    assertSame(fetchContext, constructorArguments.get().get(2));
    assertEquals((short) 7, constructorArguments.get().get(3));
  }

  @Test
  void startFetch_whenPersistenceDisabled_throwsInternalErrorFetchException() {
    RuntimeContext context =
        newRuntimeContext(NETWORK_THREAT_LEVEL.NORMAL, PHYSICAL_THREAT_LEVEL.NORMAL);
    ClientContext clientContext = mock(ClientContext.class);
    FreenetURI uri = mock(FreenetURI.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RequestClient requestClient = mock(RequestClient.class);
    FProxyRuntimeSupport.FetchCallback callback = mock(FProxyRuntimeSupport.FetchCallback.class);
    when(context.core().getClientContext()).thenReturn(clientContext);

    try (var _ =
        mockConstruction(
            ClientGetter.class,
            (getter, _) ->
                doThrow(new PersistenceDisabledException()).when(clientContext).start(getter))) {
      FetchException thrown =
          assertThrows(
              FetchException.class,
              () ->
                  context
                      .runtimeSupport()
                      .startFetch(uri, fetchContext, (short) 1, requestClient, callback));

      assertEquals(FetchException.FetchExceptionMode.INTERNAL_ERROR, thrown.getMode());
      assertInstanceOf(PersistenceDisabledException.class, thrown.getCause());
      verifyNoInteractions(callback);
    }
  }

  @ParameterizedTest
  @MethodSource("physicalThreatLevelMappings")
  void physicalThreatLevel_whenSecurityLevelsProvideValue_expectDetachedEnumReturned(
      PHYSICAL_THREAT_LEVEL threatLevel, FProxyRuntimeSupport.PhysicalThreatLevel expected) {
    RuntimeContext context = newRuntimeContext(NETWORK_THREAT_LEVEL.NORMAL, threatLevel);

    assertEquals(expected, context.runtimeSupport().physicalThreatLevel());
  }

  @ParameterizedTest
  @MethodSource("networkThreatLevelMappings")
  void networkThreatLevel_whenSecurityLevelsProvideValue_expectDetachedEnumReturned(
      NETWORK_THREAT_LEVEL threatLevel, FProxyRuntimeSupport.NetworkThreatLevel expected) {
    RuntimeContext context = newRuntimeContext(threatLevel, PHYSICAL_THREAT_LEVEL.NORMAL);

    assertEquals(expected, context.runtimeSupport().networkThreatLevel());
  }

  private static Stream<Arguments> physicalThreatLevelMappings() {
    return Stream.of(
        Arguments.of(PHYSICAL_THREAT_LEVEL.LOW, FProxyRuntimeSupport.PhysicalThreatLevel.LOW),
        Arguments.of(PHYSICAL_THREAT_LEVEL.NORMAL, FProxyRuntimeSupport.PhysicalThreatLevel.NORMAL),
        Arguments.of(PHYSICAL_THREAT_LEVEL.HIGH, FProxyRuntimeSupport.PhysicalThreatLevel.HIGH),
        Arguments.of(
            PHYSICAL_THREAT_LEVEL.MAXIMUM, FProxyRuntimeSupport.PhysicalThreatLevel.MAXIMUM));
  }

  private static Stream<Arguments> networkThreatLevelMappings() {
    return Stream.of(
        Arguments.of(NETWORK_THREAT_LEVEL.LOW, FProxyRuntimeSupport.NetworkThreatLevel.LOW),
        Arguments.of(NETWORK_THREAT_LEVEL.NORMAL, FProxyRuntimeSupport.NetworkThreatLevel.NORMAL),
        Arguments.of(NETWORK_THREAT_LEVEL.HIGH, FProxyRuntimeSupport.NetworkThreatLevel.HIGH),
        Arguments.of(
            NETWORK_THREAT_LEVEL.MAXIMUM, FProxyRuntimeSupport.NetworkThreatLevel.MAXIMUM));
  }

  private static RuntimeContext newRuntimeContext(
      NETWORK_THREAT_LEVEL networkThreatLevel, PHYSICAL_THREAT_LEVEL physicalThreatLevel) {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    SecurityLevels securityLevels = mock(SecurityLevels.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    PersistentConfig config = mock(PersistentConfig.class);
    SubConfig fproxyConfig = mock(SubConfig.class);
    when(core.getNode()).thenReturn(node);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getNetworkThreatLevel()).thenReturn(networkThreatLevel);
    when(securityLevels.getPhysicalThreatLevel()).thenReturn(physicalThreatLevel);
    when(node.network()).thenReturn(network);
    when(network.executor()).thenReturn(executor);
    when(node.getConfig()).thenReturn(config);
    when(config.get("fproxy")).thenReturn(fproxyConfig);
    return new RuntimeContext(new CoreFProxyRuntimeSupport(core), core, executor, fproxyConfig);
  }

  private record RuntimeContext(
      CoreFProxyRuntimeSupport runtimeSupport,
      NodeClientCore core,
      PriorityAwareExecutor executor,
      SubConfig fproxyConfig) {}
}
