package network.crypta.support.compress;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.async.ClientContext;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;

class RealCompressorTest {

  private RealCompressor compressor;

  @AfterEach
  void tearDown() {
    // Ensure worker threads are stopped so the JVM can exit cleanly
    if (compressor != null) {
      compressor.shutdown();
    }
  }

  @Test
  @DisplayName("enqueueNewJob_whenContextIsSet_callsTryCompressWithSameContext")
  void enqueueNewJob_whenContextIsSet_callsTryCompressWithSameContext() throws Exception {
    // Arrange
    compressor = new RealCompressor();
    ClientContext ctx = mock(ClientContext.class);
    compressor.setClientContext(ctx);
    CompressJob job = mock(CompressJob.class);
    CountDownLatch called = new CountDownLatch(1);
    doAnswer(
            inv -> {
              called.countDown();
              return null;
            })
        .when(job)
        .tryCompress(any());

    // Act
    compressor.enqueueNewJob(job);

    // Assert
    assertTrue(called.await(2, TimeUnit.SECONDS), "tryCompress was not called in time");
    ArgumentCaptor<ClientContext> ctxCaptor = ArgumentCaptor.forClass(ClientContext.class);
    verify(job, times(1)).tryCompress(ctxCaptor.capture());
    assertSame(ctx, ctxCaptor.getValue(), "Compressor should pass the configured context");
    verify(job, never()).onFailure(any(), any(), any());
  }

  @Test
  @DisplayName("enqueueNewJob_whenTryCompressThrowsInsertException_callsOnFailureWithSameException")
  void enqueueNewJob_whenTryCompressThrowsInsertException_callsOnFailureWithSameException()
      throws Exception {
    // Arrange
    compressor = new RealCompressor();
    ClientContext ctx = mock(ClientContext.class);
    compressor.setClientContext(ctx);
    CompressJob job = mock(CompressJob.class);
    InsertException thrown = new InsertException(InsertExceptionMode.TOO_BIG);
    doThrow(thrown).when(job).tryCompress(any());
    CountDownLatch failed = new CountDownLatch(1);
    doAnswer(
            inv -> {
              failed.countDown();
              return null;
            })
        .when(job)
        .onFailure(any(), any(), any());

    // Act
    compressor.enqueueNewJob(job);

    // Assert
    assertTrue(failed.await(2, TimeUnit.SECONDS), "onFailure was not called in time");
    ArgumentCaptor<InsertException> exCaptor = ArgumentCaptor.forClass(InsertException.class);
    ArgumentCaptor<ClientContext> ctxCaptor = ArgumentCaptor.forClass(ClientContext.class);
    verify(job).onFailure(exCaptor.capture(), isNull(), ctxCaptor.capture());
    assertSame(thrown, exCaptor.getValue(), "Should forward the same InsertException instance");
    assertSame(ctx, ctxCaptor.getValue(), "Should forward the configured ClientContext");
  }

  @Test
  @DisplayName("enqueueNewJob_whenTryCompressThrowsThrowable_wrapsAsInternalErrorAndCallsOnFailure")
  void enqueueNewJob_whenTryCompressThrowsThrowable_wrapsAsInternalErrorAndCallsOnFailure()
      throws Exception {
    // Silence expected error-level log noise from RealCompressor for this test only (Linux CI).
    Logger logCompressor = (Logger) LoggerFactory.getLogger(RealCompressor.class);
    Logger logInsertEx =
        (Logger) LoggerFactory.getLogger(network.crypta.client.InsertException.class);
    Level prevCompressor = logCompressor.getLevel();
    Level prevInsertEx = logInsertEx.getLevel();
    logCompressor.setLevel(Level.OFF);
    logInsertEx.setLevel(Level.OFF);
    try {
      // Arrange
      compressor = new RealCompressor();
      ClientContext ctx = mock(ClientContext.class);
      compressor.setClientContext(ctx);
      CompressJob job = mock(CompressJob.class);
      RuntimeException boom = new RuntimeException("boom");
      doAnswer(
              inv -> {
                throw boom;
              })
          .when(job)
          .tryCompress(any());
      CountDownLatch failed = new CountDownLatch(1);
      doAnswer(
              inv -> {
                failed.countDown();
                return null;
              })
          .when(job)
          .onFailure(any(), any(), any());

      // Act
      compressor.enqueueNewJob(job);

      // Assert
      assertTrue(failed.await(2, TimeUnit.SECONDS), "onFailure was not called in time");
      ArgumentCaptor<InsertException> exCaptor = ArgumentCaptor.forClass(InsertException.class);
      verify(job).onFailure(exCaptor.capture(), isNull(), same(ctx));
      InsertException wrapped = exCaptor.getValue();
      assertThat(wrapped.getMode(), is(InsertExceptionMode.INTERNAL_ERROR));
      assertThat(wrapped.getCause(), is(boom));
    } finally {
      logCompressor.setLevel(prevCompressor);
      logInsertEx.setLevel(prevInsertEx);
    }
  }

  @Test
  @DisplayName("enqueueNewJob_afterShutdown_doesNotRunJob")
  void enqueueNewJob_afterShutdown_doesNotRunJob() throws Exception {
    // Arrange
    compressor = new RealCompressor();
    compressor.shutdown();
    CompressJob job = mock(CompressJob.class);

    // Act
    compressor.enqueueNewJob(job);

    // Assert (allow a brief window to ensure no background activity occurs)
    verify(job, after(200).never()).tryCompress(any());
    verify(job, after(200).never()).onFailure(any(), any(), any());
  }

  // Parameterized: verify that the context (null or non-null) is passed through to tryCompress
  static Object[] clientContexts() {
    return new Object[] {null, mock(ClientContext.class)};
  }

  @ParameterizedTest(name = "context={0}")
  @MethodSource("clientContexts")
  @DisplayName("enqueueNewJob_whenContextVaries_jobReceivesSameContext")
  void enqueueNewJob_whenContextVaries_jobReceivesSameContext(ClientContext ctx) throws Exception {
    // Arrange
    compressor = new RealCompressor();
    compressor.setClientContext(ctx);
    CompressJob job = mock(CompressJob.class);
    CountDownLatch called = new CountDownLatch(1);
    doAnswer(
            inv -> {
              called.countDown();
              return null;
            })
        .when(job)
        .tryCompress(any());

    // Act
    compressor.enqueueNewJob(job);

    // Assert
    assertTimeoutPreemptively(
        Duration.ofSeconds(2),
        () -> assertTrue(called.await(2, TimeUnit.SECONDS), "tryCompress was not called in time"));
    ArgumentCaptor<ClientContext> ctxCaptor = ArgumentCaptor.forClass(ClientContext.class);
    verify(job).tryCompress(ctxCaptor.capture());
    assertSame(ctx, ctxCaptor.getValue());
  }

  @Test
  @DisplayName("newThread_whenCalled_returnsNativeThreadWithMinPriorityAndName")
  void newThread_whenCalled_returnsNativeThreadWithMinPriorityAndName() {
    // Arrange
    RealCompressor.CompressorThreadFactory factory = new RealCompressor.CompressorThreadFactory();
    Runnable noop = () -> {};

    // Act
    Thread t = factory.newThread(noop);

    // Assert
    assertThat(t, instanceOf(NativeThread.class));
    assertThat(t.getName(), is("Compressor thread"));
    int expected = NativeThread.PriorityLevel.MIN_PRIORITY.value;
    assertThat(((NativeThread) t).getNativePriority(), is(expected));
  }
}
