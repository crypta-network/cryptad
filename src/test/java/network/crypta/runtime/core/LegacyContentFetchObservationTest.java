package network.crypta.runtime.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SuppressWarnings("java:S100")
class LegacyContentFetchObservationTest {
  @Test
  void invalidNativeFetchReleasesActivityWithoutCallingCore() {
    NodeClientCore core = mock(NodeClientCore.class);
    LegacyContentFetchPort port = new LegacyContentFetchPort(core);
    var request = new BoundedContentFetchRequest("invalid-key", 32, Duration.ofSeconds(1), "test");
    assertThrows(ContentFetchException.class, () -> port.fetchContent(request));
    var result = port.observation();
    assertEquals(1, result.startedOperations());
    assertEquals(1, result.failedOperations());
    assertEquals(0, result.inFlightOperations());
    verifyNoInteractions(core);
  }

  @Test
  void interruptCancelsNativeGetterAndReleasesObservedActivity() throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    HighLevelSimpleClient client =
        mock(HighLevelSimpleClient.class, withSettings().extraInterfaces(RequestClient.class));
    ClientGetter getter = mock(ClientGetter.class);
    ClientContext context = mock(ClientContext.class);
    FetchContext fetchContext = mock(FetchContext.class);
    when(core.getClientContext()).thenReturn(context);
    when(core.makeClient(anyShort(), eq(false), eq(false))).thenReturn(client);
    when(client.getFetchContext()).thenReturn(fetchContext);
    CountDownLatch started = new CountDownLatch(1);
    when(client.fetch(any(FreenetURI.class), anyLong(), any(), any(), anyShort()))
        .thenAnswer(
            _ -> {
              started.countDown();
              return getter;
            });
    LegacyContentFetchPort port = new LegacyContentFetchPort(core);
    var request =
        new BoundedContentFetchRequest(
            FreenetURI.EMPTY_CHK_URI.toString(), 32, Duration.ofSeconds(30), "test");
    AtomicReference<Throwable> outcome = new AtomicReference<>();
    Thread worker =
        Thread.ofPlatform()
            .unstarted(
                () -> {
                  try {
                    port.fetchContent(request);
                  } catch (Throwable failure) {
                    outcome.set(failure);
                  }
                });
    worker.start();
    try {
      assertTrue(started.await(5, TimeUnit.SECONDS));
      assertEquals(1, port.observation().inFlightOperations());
      worker.interrupt();
      worker.join(5000);
      assertFalse(worker.isAlive());
      assertInstanceOf(ContentFetchException.class, outcome.get());
      assertEquals(0, port.observation().inFlightOperations());
      assertEquals(1, port.observation().failedOperations());
      verify(getter).cancel(context);
    } finally {
      worker.interrupt();
      worker.join(5000);
    }
  }

  @Test
  void fetchContent_whenMaterializedSuccessfully_expectSuccessfulReleasedObservation()
      throws Exception {
    NativeFixture fixture = new NativeFixture();
    fixture.completeSuccessfully();

    var result = fixture.port.fetchContent(fixture.request);

    assertArrayEquals(new byte[] {1, 2}, result.bytes());
    assertCompleted(fixture.port, true);
  }

  @Test
  void fetchContent_whenStreamedSuccessfully_expectSuccessfulReleasedObservation()
      throws Exception {
    NativeFixture fixture = new NativeFixture();
    fixture.completeSuccessfully();
    ByteArrayOutputStream destination = new ByteArrayOutputStream();

    fixture.port.fetchContent(fixture.request, destination);

    assertArrayEquals(new byte[] {1, 2}, destination.toByteArray());
    assertCompleted(fixture.port, true);
  }

  @Test
  void fetchContent_whenDestinationThrows_expectFailedReleasedObservation() throws Exception {
    NativeFixture fixture = new NativeFixture();
    fixture.completeSuccessfully();
    IOException failure = new IOException("write failed");
    OutputStream destination =
        new OutputStream() {
          @Override
          public void write(int value) throws IOException {
            throw failure;
          }
        };

    IOException actual =
        assertThrows(
            IOException.class, () -> fixture.port.fetchContent(fixture.request, destination));

    assertSame(failure, actual);
    assertCompleted(fixture.port, false);
  }

  @Test
  void fetchContent_whenCallbackFails_expectFailedReleasedObservation() throws Exception {
    NativeFixture fixture = new NativeFixture();
    when(fixture.client.fetch(any(FreenetURI.class), anyLong(), any(), any(), anyShort()))
        .thenAnswer(
            invocation -> {
              ClientGetCallback callback = invocation.getArgument(2);
              callback.onFailure(
                  new FetchException(FetchException.FetchExceptionMode.DATA_NOT_FOUND));
              return fixture.getter;
            });

    ContentFetchException failure =
        assertThrows(ContentFetchException.class, () -> fixture.port.fetchContent(fixture.request));

    assertEquals(ContentFetchException.CATALOG_FETCH_FAILED, failure.errorCode());
    assertCompleted(fixture.port, false);
  }

  @Test
  void fetchContent_whenCoreThrowsUnexpectedly_expectFailedReleasedObservation() {
    NodeClientCore core = mock(NodeClientCore.class);
    LegacyContentFetchPort port = new LegacyContentFetchPort(core);
    var request =
        new BoundedContentFetchRequest(
            FreenetURI.EMPTY_CHK_URI.toString(), 32, Duration.ofSeconds(1), "test");
    IllegalStateException failure = new IllegalStateException("unavailable");
    when(core.makeClient(anyShort(), eq(false), eq(false))).thenThrow(failure);

    IllegalStateException actual =
        assertThrows(IllegalStateException.class, () -> port.fetchContent(request));

    assertSame(failure, actual);
    assertCompleted(port, false);
  }

  private static void assertCompleted(LegacyContentFetchPort port, boolean success) {
    var observation = port.observation();
    assertEquals(1, observation.startedOperations());
    assertEquals(success ? 1 : 0, observation.successfulOperations());
    assertEquals(success ? 0 : 1, observation.failedOperations());
    assertEquals(0, observation.inFlightOperations());
    assertEquals(2, observation.sequence());
    assertFalse(observation.truncated());
  }

  private static final class NativeFixture {
    final HighLevelSimpleClient client =
        mock(HighLevelSimpleClient.class, withSettings().extraInterfaces(RequestClient.class));
    final ClientGetter getter = mock(ClientGetter.class);
    final LegacyContentFetchPort port;
    final BoundedContentFetchRequest request =
        new BoundedContentFetchRequest(
            FreenetURI.EMPTY_CHK_URI.toString(), 32, Duration.ofSeconds(1), "test");

    NativeFixture() {
      NodeClientCore core = mock(NodeClientCore.class);
      FetchContext context = mock(FetchContext.class);
      when(core.makeClient(anyShort(), eq(false), eq(false))).thenReturn(client);
      when(client.getFetchContext()).thenReturn(context);
      port = new LegacyContentFetchPort(core);
    }

    void completeSuccessfully() throws FetchException {
      FetchResult result =
          FetchResult.create(
              new ClientMetadata("application/octet-stream"), new ArrayBucket(new byte[] {1, 2}));
      when(client.fetch(any(FreenetURI.class), anyLong(), any(), any(), anyShort()))
          .thenAnswer(
              invocation -> {
                ClientGetCallback callback = invocation.getArgument(2);
                callback.onSuccess(result, getter);
                return getter;
              });
    }
  }
}
