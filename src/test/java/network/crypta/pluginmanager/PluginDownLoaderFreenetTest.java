package network.crypta.pluginmanager;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.FetchWaiter;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.SplitfileProgressTimestamps;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.pluginmanager.PluginManager.PluginProgress;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // JUnit-style names: method_whenCondition_expectOutcome
class PluginDownLoaderFreenetTest {

  private static final String VALID_CHK_URI =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";

  @Test
  void checkSource_whenValidFreenetKey_expectParsedUri() throws Exception {
    PluginDownLoaderFreenet downloader =
        new PluginDownLoaderFreenet(
            mockHLSC(), mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS), false);

    FreenetURI out = downloader.checkSource("KSK@gpl.txt");

    assertEquals(new FreenetURI("KSK@gpl.txt"), out);
  }

  @Test
  void checkSource_whenInvalidKey_expectPluginNotFoundWithCause() {
    PluginDownLoaderFreenet downloader =
        new PluginDownLoaderFreenet(
            mockHLSC(), mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS), false);
    String invalid = "not a freenet uri";

    PluginNotFoundException ex =
        assertThrows(PluginNotFoundException.class, () -> downloader.checkSource(invalid));

    assertEquals("not a valid freenet key: " + invalid, ex.getMessage());
    assertInstanceOf(MalformedURLException.class, ex.getCause());
  }

  @ParameterizedTest
  @CsvSource({
    "KSK@gpl.txt, KSK@gpl.txt",
    "KSK@site/plugins/MyPlugin.jar, MyPlugin.jar",
    "trailingSlash/, ''",
    "noSlash, noSlash"
  })
  void getPluginName_whenCalled_expectDerivedName(String source, String expectedName)
      throws Exception {
    PluginDownLoaderFreenet downloader =
        new PluginDownLoaderFreenet(
            mockHLSC(), mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS), false);

    String name = downloader.getPluginName(source);

    assertEquals(expectedName, name);
  }

  @Test
  void getSHA1sum_whenCalled_expectNull() {
    PluginDownLoaderFreenet downloader =
        new PluginDownLoaderFreenet(
            mockHLSC(), mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS), false);

    assertNull(assertDoesNotThrow(downloader::getSHA1sum));
  }

  @Test
  void fatalFailure_whenNewInstance_expectFalse() {
    PluginDownLoaderFreenet downloader =
        new PluginDownLoaderFreenet(
            mockHLSC(), mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS), false);

    assertFalse(downloader.fatalFailure());
  }

  @Test
  void isLoadingFromFreenet_whenCalled_expectTrue() {
    PluginDownLoaderFreenet downloader =
        new PluginDownLoaderFreenet(
            mockHLSC(), mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS), false);

    assertTrue(downloader.isLoadingFromFreenet());
  }

  @Test
  void getRetryDownloader_whenCalled_expectNewInstanceWithDesperateEnabled() {
    HighLevelSimpleClient hlsc = mockHLSC();
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PluginDownLoaderFreenet downloader = new PluginDownLoaderFreenet(hlsc, node, false);

    PluginDownLoader<FreenetURI> retry = downloader.getRetryDownloader();

    assertNotSame(downloader, retry);
    assertInstanceOf(PluginDownLoaderFreenet.class, retry);
    assertTrue(((PluginDownLoaderFreenet) retry).desperate);
    verify(hlsc, times(2)).copy();
  }

  @Test
  void tryCancel_whenNoInFlightGetter_expectNoException() {
    PluginDownLoaderFreenet downloader =
        new PluginDownLoaderFreenet(
            mockHLSC(), mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS), false);

    assertDoesNotThrow(downloader::tryCancel);
  }

  @Test
  void getInputStream_whenFetchSucceeds_returnsBucketInputStreamAndMarksDownloading()
      throws Exception {
    FetchContext fetchContext = mock(FetchContext.class);
    ClientContext clientContext = mock(ClientContext.class);
    HighLevelSimpleClient hlsc = mockHLSC();
    when(hlsc.getFetchContext()).thenReturn(fetchContext);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeClientCore core = mock(NodeClientCore.class);
    when(node.services().clientCore()).thenReturn(core);
    when(core.getClientContext()).thenReturn(clientContext);
    when(node.getNonPersistentClientBulk()).thenReturn(mock(RequestClient.class));

    byte[] expectedBytes = "plugin-bytes".getBytes(StandardCharsets.UTF_8);
    ByteArrayInputStream expectedStream = new ByteArrayInputStream(expectedBytes);
    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(expectedStream);
    ClientMetadata metadata = mock(ClientMetadata.class);
    FetchResult fetchResult = FetchResult.create(metadata, bucket);

    try (MockedConstruction<FetchWaiter> mockedWaiter =
            mockConstruction(
                FetchWaiter.class,
                (mock, ctx) -> when(mock.waitForCompletion()).thenReturn(fetchResult));
        MockedConstruction<ClientGetter> mockedGetter = mockConstruction(ClientGetter.class)) {
      PluginDownLoaderFreenet downloader = new PluginDownLoaderFreenet(hlsc, node, false);
      downloader.setSource(VALID_CHK_URI);
      PluginProgress progress = mock(PluginProgress.class);

      try (InputStream in = downloader.getInputStream(progress)) {
        assertEquals("plugin-bytes", new String(in.readAllBytes(), StandardCharsets.UTF_8));
      }

      verify(bucket).free();
      assertFalse(downloader.fatalFailure());
      verify(progress).setDownloading();
      verify(hlsc).addEventHook(any());
      verify(clientContext).start(any(ClientGetter.class));
      assertEquals(1, mockedWaiter.constructed().size());
      assertEquals(1, mockedGetter.constructed().size());
    }
  }

  @Test
  void getInputStream_whenSplitfileProgressFinalized_expectProgressCountersUpdated()
      throws Exception {
    FetchContext fetchContext = mock(FetchContext.class);
    ClientContext clientContext = mock(ClientContext.class);
    HighLevelSimpleClient hlsc = mockHLSC();
    when(hlsc.getFetchContext()).thenReturn(fetchContext);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeClientCore core = mock(NodeClientCore.class);
    when(node.services().clientCore()).thenReturn(core);
    when(core.getClientContext()).thenReturn(clientContext);
    when(node.getNonPersistentClientBulk()).thenReturn(mock(RequestClient.class));

    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[] {1}));
    ClientMetadata metadata = mock(ClientMetadata.class);
    FetchResult fetchResult = FetchResult.create(metadata, bucket);

    ClientEventListener[] hookHolder = new ClientEventListener[1];
    doAnswer(
            invocation -> {
              hookHolder[0] = invocation.getArgument(0, ClientEventListener.class);
              return null;
            })
        .when(hlsc)
        .addEventHook(any());

    try (MockedConstruction<FetchWaiter> mockedWaiter =
            mockConstruction(
                FetchWaiter.class,
                (mock, ctx) -> when(mock.waitForCompletion()).thenReturn(fetchResult));
        MockedConstruction<ClientGetter> mockedGetter = mockConstruction(ClientGetter.class)) {
      PluginDownLoaderFreenet downloader = new PluginDownLoaderFreenet(hlsc, node, false);
      downloader.setSource(VALID_CHK_URI);
      PluginProgress progress = mock(PluginProgress.class);

      try (InputStream ignored = downloader.getInputStream(progress)) {
        assertEquals(1, ignored.read());
      }

      assertNotNull(hookHolder[0]);

      reset(progress);
      SplitfileProgressEvent split =
          new SplitfileProgressEvent(
              new SplitfileProgressCounts(100, 40, 3, 1, 80, 0, true),
              new SplitfileProgressTimestamps(null, null));
      hookHolder[0].receive(split, mock(ClientContext.class));

      verify(progress).setDownloadProgress(80, 40, 100, 3, 1, true);
      verify(clientContext).start(any(ClientGetter.class));
      assertEquals(1, mockedWaiter.constructed().size());
      assertEquals(1, mockedGetter.constructed().size());
    }
  }

  @Test
  void getInputStream_whenSplitfileProgressNotFinalized_expectNoProgressCountersUpdated()
      throws Exception {
    FetchContext fetchContext = mock(FetchContext.class);
    ClientContext clientContext = mock(ClientContext.class);
    HighLevelSimpleClient hlsc = mockHLSC();
    when(hlsc.getFetchContext()).thenReturn(fetchContext);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeClientCore core = mock(NodeClientCore.class);
    when(node.services().clientCore()).thenReturn(core);
    when(core.getClientContext()).thenReturn(clientContext);
    when(node.getNonPersistentClientBulk()).thenReturn(mock(RequestClient.class));

    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[] {1}));
    ClientMetadata metadata = mock(ClientMetadata.class);
    FetchResult fetchResult = FetchResult.create(metadata, bucket);

    ClientEventListener[] hookHolder = new ClientEventListener[1];
    doAnswer(
            invocation -> {
              hookHolder[0] = invocation.getArgument(0, ClientEventListener.class);
              return null;
            })
        .when(hlsc)
        .addEventHook(any());

    try (MockedConstruction<FetchWaiter> mockedWaiter =
            mockConstruction(
                FetchWaiter.class,
                (mock, ctx) -> when(mock.waitForCompletion()).thenReturn(fetchResult));
        MockedConstruction<ClientGetter> mockedGetter = mockConstruction(ClientGetter.class)) {
      PluginDownLoaderFreenet downloader = new PluginDownLoaderFreenet(hlsc, node, false);
      downloader.setSource(VALID_CHK_URI);
      PluginProgress progress = mock(PluginProgress.class);

      try (InputStream ignored = downloader.getInputStream(progress)) {
        assertEquals(1, ignored.read());
      }

      assertNotNull(hookHolder[0]);

      reset(progress);
      SplitfileProgressEvent split =
          new SplitfileProgressEvent(
              new SplitfileProgressCounts(100, 40, 3, 1, 80, 0, false),
              new SplitfileProgressTimestamps(null, null));
      hookHolder[0].receive(split, mock(ClientContext.class));

      verify(progress, never())
          .setDownloadProgress(anyInt(), anyInt(), anyInt(), anyInt(), anyInt(), anyBoolean());
      verify(clientContext).start(any(ClientGetter.class));
      assertEquals(1, mockedWaiter.constructed().size());
      assertEquals(1, mockedGetter.constructed().size());
    }
  }

  @Test
  void getInputStream_whenDesperate_setsUnlimitedRetryCounts() throws Exception {
    FetchContext fetchContext = mock(FetchContext.class);
    ClientContext clientContext = mock(ClientContext.class);
    HighLevelSimpleClient hlsc = mockHLSC();
    when(hlsc.getFetchContext()).thenReturn(fetchContext);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeClientCore core = mock(NodeClientCore.class);
    when(node.services().clientCore()).thenReturn(core);
    when(core.getClientContext()).thenReturn(clientContext);
    when(node.getNonPersistentClientBulk()).thenReturn(mock(RequestClient.class));

    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[] {1, 2, 3}));
    ClientMetadata metadata = mock(ClientMetadata.class);
    FetchResult fetchResult = FetchResult.create(metadata, bucket);

    try (MockedConstruction<FetchWaiter> mockedWaiter =
            mockConstruction(
                FetchWaiter.class,
                (mock, ctx) -> when(mock.waitForCompletion()).thenReturn(fetchResult));
        MockedConstruction<ClientGetter> mockedGetter = mockConstruction(ClientGetter.class)) {
      PluginDownLoaderFreenet downloader = new PluginDownLoaderFreenet(hlsc, node, true);
      downloader.setSource(VALID_CHK_URI);

      try (InputStream ignored = downloader.getInputStream(mock(PluginProgress.class))) {
        assertEquals(1, ignored.read());
      }

      verify(fetchContext).setMaxNonSplitfileRetries(-1);
      verify(fetchContext).setMaxSplitfileBlockRetries(-1);
      verify(clientContext).start(any(ClientGetter.class));
      assertEquals(1, mockedWaiter.constructed().size());
      assertEquals(1, mockedGetter.constructed().size());
    }
  }

  @Test
  void getInputStream_whenFetchThrowsFatalException_setsFatalFailureAndThrowsPluginNotFound()
      throws Exception {
    FetchContext fetchContext = mock(FetchContext.class);
    ClientContext clientContext = mock(ClientContext.class);
    HighLevelSimpleClient hlsc = mockHLSC();
    when(hlsc.getFetchContext()).thenReturn(fetchContext);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeClientCore core = mock(NodeClientCore.class);
    when(node.services().clientCore()).thenReturn(core);
    when(core.getClientContext()).thenReturn(clientContext);
    when(node.getNonPersistentClientBulk()).thenReturn(mock(RequestClient.class));

    FetchException fatal = new FetchException(FetchExceptionMode.INVALID_URI);
    try (MockedConstruction<FetchWaiter> mockedWaiter =
            mockConstruction(
                FetchWaiter.class, (mock, ctx) -> when(mock.waitForCompletion()).thenThrow(fatal));
        MockedConstruction<ClientGetter> mockedGetter = mockConstruction(ClientGetter.class)) {
      PluginDownLoaderFreenet downloader = new PluginDownLoaderFreenet(hlsc, node, false);
      downloader.setSource(VALID_CHK_URI);

      PluginNotFoundException ex =
          assertThrows(
              PluginNotFoundException.class,
              () -> downloader.getInputStream(mock(PluginProgress.class)));

      assertNotNull(ex.getMessage());
      assertTrue(downloader.fatalFailure());
      verify(clientContext).start(any(ClientGetter.class));
      assertEquals(1, mockedWaiter.constructed().size());
      assertEquals(1, mockedGetter.constructed().size());
    }
  }

  @Test
  void getInputStream_whenFetchThrowsNonFatalException_doesNotSetFatalFailure() throws Exception {
    FetchContext fetchContext = mock(FetchContext.class);
    ClientContext clientContext = mock(ClientContext.class);
    HighLevelSimpleClient hlsc = mockHLSC();
    when(hlsc.getFetchContext()).thenReturn(fetchContext);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeClientCore core = mock(NodeClientCore.class);
    when(node.services().clientCore()).thenReturn(core);
    when(core.getClientContext()).thenReturn(clientContext);
    when(node.getNonPersistentClientBulk()).thenReturn(mock(RequestClient.class));

    FetchException nonFatal = new FetchException(FetchExceptionMode.DATA_NOT_FOUND);
    try (MockedConstruction<FetchWaiter> mockedWaiter =
            mockConstruction(
                FetchWaiter.class,
                (mock, ctx) -> when(mock.waitForCompletion()).thenThrow(nonFatal));
        MockedConstruction<ClientGetter> mockedGetter = mockConstruction(ClientGetter.class)) {
      PluginDownLoaderFreenet downloader = new PluginDownLoaderFreenet(hlsc, node, false);
      downloader.setSource(VALID_CHK_URI);

      assertThrows(
          PluginNotFoundException.class,
          () -> downloader.getInputStream(mock(PluginProgress.class)));

      assertFalse(downloader.fatalFailure());
      verify(clientContext).start(any(ClientGetter.class));
      assertEquals(1, mockedWaiter.constructed().size());
      assertEquals(1, mockedGetter.constructed().size());
    }
  }

  @Test
  void getInputStream_whenFetchPermanentRedirect_retriesWithNewUri() throws Exception {
    FetchContext fetchContext = mock(FetchContext.class);
    ClientContext clientContext = mock(ClientContext.class);
    HighLevelSimpleClient hlsc = mockHLSC();
    when(hlsc.getFetchContext()).thenReturn(fetchContext);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeClientCore core = mock(NodeClientCore.class);
    when(node.services().clientCore()).thenReturn(core);
    when(core.getClientContext()).thenReturn(clientContext);
    when(node.getNonPersistentClientBulk()).thenReturn(mock(RequestClient.class));

    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream())
        .thenReturn(new ByteArrayInputStream("ok".getBytes(StandardCharsets.UTF_8)));
    ClientMetadata metadata = mock(ClientMetadata.class);
    FetchResult fetchResult = FetchResult.create(metadata, bucket);

    FreenetURI redirectedUri = new FreenetURI("KSK@redirected");
    FetchException redirect =
        new FetchException(FetchExceptionMode.PERMANENT_REDIRECT, -1, false, null, redirectedUri);

    List<FreenetURI> getterUris = new ArrayList<>();
    try (MockedConstruction<FetchWaiter> mockedWaiter =
            mockConstruction(
                FetchWaiter.class,
                (mock, ctx) -> {
                  if (ctx.getCount() == 1) {
                    when(mock.waitForCompletion()).thenThrow(redirect);
                  } else {
                    when(mock.waitForCompletion()).thenReturn(fetchResult);
                  }
                });
        MockedConstruction<ClientGetter> mockedGetter =
            mockConstruction(
                ClientGetter.class,
                (mock, ctx) -> getterUris.add((FreenetURI) ctx.arguments().get(1)))) {
      PluginDownLoaderFreenet downloader = new PluginDownLoaderFreenet(hlsc, node, false);
      downloader.setSource(VALID_CHK_URI);

      try (InputStream in = downloader.getInputStream(mock(PluginProgress.class))) {
        assertEquals("ok", new String(in.readAllBytes(), StandardCharsets.UTF_8));
      }

      assertFalse(downloader.fatalFailure());
      assertEquals(2, mockedWaiter.constructed().size());
      assertEquals(2, mockedGetter.constructed().size());
      assertEquals(2, getterUris.size());
      assertEquals(new FreenetURI(VALID_CHK_URI), getterUris.get(0));
      assertEquals(redirectedUri, getterUris.get(1));
    }
  }

  @Test
  void tryCancel_whenInFlightGetter_expectCancelInvokedWithClientContext() throws Exception {
    FetchContext fetchContext = mock(FetchContext.class);
    ClientContext clientContext = mock(ClientContext.class);
    HighLevelSimpleClient hlsc = mockHLSC();
    when(hlsc.getFetchContext()).thenReturn(fetchContext);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeClientCore core = mock(NodeClientCore.class);
    when(node.services().clientCore()).thenReturn(core);
    when(core.getClientContext()).thenReturn(clientContext);
    when(node.getNonPersistentClientBulk()).thenReturn(mock(RequestClient.class));

    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[] {1}));
    ClientMetadata metadata = mock(ClientMetadata.class);
    FetchResult fetchResult = FetchResult.create(metadata, bucket);

    try (MockedConstruction<FetchWaiter> mockedWaiter =
            mockConstruction(
                FetchWaiter.class,
                (mock, ctx) -> when(mock.waitForCompletion()).thenReturn(fetchResult));
        MockedConstruction<ClientGetter> mockedGetter = mockConstruction(ClientGetter.class)) {
      PluginDownLoaderFreenet downloader = new PluginDownLoaderFreenet(hlsc, node, false);
      downloader.setSource(VALID_CHK_URI);
      PluginProgress progress = mock(PluginProgress.class);

      try (InputStream ignored = downloader.getInputStream(progress)) {
        assertEquals(1, ignored.read());
      }

      downloader.tryCancel();

      assertEquals(1, mockedWaiter.constructed().size());
      ClientGetter constructedGetter = mockedGetter.constructed().getFirst();
      verify(constructedGetter).cancel(clientContext);
      verify(fetchContext, never()).setMaxNonSplitfileRetries(-1);
      verify(fetchContext, never()).setMaxSplitfileBlockRetries(-1);
    }
  }

  private static HighLevelSimpleClient mockHLSC() {
    HighLevelSimpleClient hlsc = mock(HighLevelSimpleClient.class);
    when(hlsc.copy()).thenReturn(hlsc);
    return hlsc;
  }
}
