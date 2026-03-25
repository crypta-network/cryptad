package network.crypta.runtime.updater;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.Ticker;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.api.RandomAccessBuffer;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.FileBucket;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class RevocationCheckerTest {

  @TempDir Path tempDir;

  @Mock NodeUpdateManager manager;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  Node node;

  @Mock NodeClientCore core;
  @Mock ClientContext clientContext;
  @Mock Ticker ticker;

  private File blobFile;
  private RevocationChecker checker;

  @BeforeEach
  void setUp() throws Exception {
    // Filesystem roots used by the checker
    File persistentTmpDir = tempDir.resolve("persistTmp").toFile();
    assertTrue(persistentTmpDir.mkdirs() || persistentTmpDir.exists());
    blobFile = tempDir.resolve("revocation.blob").toFile();

    // Minimal node wiring
    when(manager.getNode()).thenReturn(node);
    when(node.services().clientCore()).thenReturn(core);
    when(core.getPersistentTempDir()).thenReturn(persistentTmpDir);
    when(core.getClientContext()).thenReturn(clientContext);
    when(node.network().ticker()).thenReturn(ticker);

    // Fetch context for constructor path
    HighLevelSimpleClient hlsc = Mockito.mock(HighLevelSimpleClient.class);
    when(core.makeClient(Mockito.anyShort(), Mockito.anyBoolean(), Mockito.anyBoolean()))
        .thenReturn(hlsc);
    when(hlsc.getFetchContext()).thenReturn(getFetchContext());

    when(manager.getRevocationURI()).thenReturn(new FreenetURI("KSK@revocation.txt"));
    when(manager.isBlown()).thenReturn(false);

    checker = new RevocationChecker(manager, blobFile);
  }

  private static @NotNull FetchContext getFetchContext() {
    SimpleEventProducer ep = new SimpleEventProducer();
    return new FetchContext(
        FetchContextOptions.builder()
            .limits(Long.MAX_VALUE, Long.MAX_VALUE, 1024 * 1024)
            .archiveLimits(1, 1, 1, false)
            .retryLimits(0, 0, 0)
            .splitfileLimits(true, 1, 1)
            .behavior(true, false, false)
            .clientOptions(ep, false, true)
            .filterOverrides(null, null, null)
            .build());
  }

  @Test
  void start_whenManagerAlreadyBlown_expectFalseAndNoStart() throws Exception {
    // Arrange
    when(manager.isBlown()).thenReturn(true);

    // Act
    boolean alreadyRunning = checker.start(true, true);

    // Assert
    assertFalse(alreadyRunning);
    verify(clientContext, never()).start(Mockito.<ClientGetter>any());
  }

  @Test
  void getBlobBucket_whenNotBlown_expectNull() {
    // Arrange
    when(manager.isBlown()).thenReturn(false);

    // Act + Assert
    assertEquals(0, checker.getBlobSize());
    assertNull(checker.getBlobBucket());
    assertNull(checker.getBlobBuffer());
  }

  @Test
  void kill_whenActiveGetter_expectCancelCalled() throws Exception {
    // Arrange: start once to create a getter
    checker.start(false, true);
    ArgumentCaptor<ClientGetter> cgCap = ArgumentCaptor.forClass(ClientGetter.class);
    verify(clientContext, times(1)).start(cgCap.capture());

    // Replace internal getter with a spy so we can verify cancel()
    ClientGetter original = cgCap.getValue();
    ClientGetter spyGetter = Mockito.spy(original);
    java.lang.reflect.Field f = RevocationChecker.class.getDeclaredField("revocationGetter");
    f.setAccessible(true);
    f.set(checker, spyGetter);

    // Act
    checker.kill();

    // Assert: cancel invoked with the same client context
    verify(spyGetter, times(1)).cancel(clientContext);
  }

  @Test
  void onChangeRevocationURI_whenCalled_expectCancelAndRestart() throws Exception {
    // Arrange: initial start creates a getter
    checker.start(false, true);
    verify(clientContext, times(1)).start(Mockito.<ClientGetter>any());

    // Spy the internal getter to observe cancel()
    ArgumentCaptor<ClientGetter> cgCap = ArgumentCaptor.forClass(ClientGetter.class);
    verify(clientContext).start(cgCap.capture());
    ClientGetter spyGetter = Mockito.spy(cgCap.getValue());
    java.lang.reflect.Field f = RevocationChecker.class.getDeclaredField("revocationGetter");
    f.setAccessible(true);
    f.set(checker, spyGetter);

    // Act
    checker.onChangeRevocationURI();

    // Assert: old getter cancelled and a new start queued
    verify(spyGetter, times(1)).cancel(clientContext);
    verify(clientContext, times(2)).start(Mockito.<ClientGetter>any());
  }

  @Test
  void onFailure_whenCancelled_expectNoRestart() {
    // Arrange: baseline start count
    int before = Mockito.mockingDetails(clientContext).getInvocations().size();

    // Act
    checker.onFailure(new FetchException(FetchExceptionMode.CANCELLED), null, new ArrayBucket());

    // Assert: no additional starts
    int after = Mockito.mockingDetails(clientContext).getInvocations().size();
    assertEquals(before, after);
  }

  @Test
  void onFailure_whenNonRecentNonFatal_expectImmediateRestart() {
    // Arrange: create initial getter so restart path is exercised
    checker.start(false, true);
    int callsBefore = Mockito.mockingDetails(clientContext).getInvocations().size();

    // Act: ROUTE_NOT_FOUND is non-fatal and should trigger immediate restart
    checker.onFailure(
        new FetchException(FetchExceptionMode.ROUTE_NOT_FOUND), null, new ArrayBucket());

    // Assert: another start() call was made
    int callsAfter = Mockito.mockingDetails(clientContext).getInvocations().size();
    assertTrue(callsAfter > callsBefore);
  }

  @Test
  void start_whenStartThrowsRecentlyFailed_expectFalse_andNoBlow() throws Exception {
    // Arrange
    Mockito.doThrow(new FetchException(FetchExceptionMode.RECENTLY_FAILED))
        .when(clientContext)
        .start(Mockito.<ClientGetter>any());

    // Act
    boolean res = checker.start(false, true);

    // Assert
    assertFalse(res);
    verify(manager, never()).blow(any(String.class), Mockito.anyBoolean());
  }

  @Test
  void start_whenStartThrowsOtherFetchException_expectFalse_andBlowTrue() throws Exception {
    // Arrange
    Mockito.reset(clientContext); // clear any previous stubbing
    Mockito.doThrow(new FetchException(FetchExceptionMode.BUCKET_ERROR))
        .when(clientContext)
        .start(Mockito.<ClientGetter>any());

    // Act
    boolean res = checker.start(false, true);

    // Assert
    assertFalse(res);
    verify(manager, times(1)).blow(contains("Cannot start fetch"), eq(true));
  }

  @Test
  void getBlobBuffer_whenOnlyOnDiskAndBlown_expectReadableBuffer() throws Exception {
    // Arrange: write blob to disk, pretend blown at manager level
    try (FileOutputStream fos = new FileOutputStream(blobFile)) {
      fos.write("DISK".getBytes(StandardCharsets.UTF_8));
    }
    when(manager.isBlown()).thenReturn(true);

    // Act
    RandomAccessBucket bucket = checker.getBlobBucket();
    RandomAccessBuffer buffer = checker.getBlobBuffer();
    try {
      // Assert
      assertNotNull(bucket);
      assertNotNull(buffer);
      byte[] data = new byte[(int) buffer.size()];
      buffer.pread(0, data, 0, data.length);
      assertEquals("DISK", new String(data, StandardCharsets.UTF_8));
    } finally {
      if (buffer != null) {
        buffer.close();
        buffer.free();
      }
      if (bucket != null) {
        bucket.close();
      }
    }
  }

  @Test
  void persistent_and_realTimeFlag_expectFalse() {
    assertFalse(checker.persistent());
    assertFalse(checker.realTimeFlag());
  }

  @Test
  void getRequestClient_whenCalled_expectSelf() {
    assertEquals(checker, checker.getRequestClient());
  }

  @Test
  void start_whenAggressiveWithExistingGetter_expectReturnsTrue_andResetsDNF_andStartsAgain()
      throws Exception {
    // Arrange: initial start (non-aggressive) creates a getter
    checker.start(false, true);
    // Accumulate a DNF so reset path is exercised
    checker.onFailure(
        new FetchException(FetchExceptionMode.DATA_NOT_FOUND), null, new ArrayBucket());
    assertEquals(1, checker.getRevocationDNFCounter());

    // Act: aggressive start should ignore the old getter and reset the counter
    boolean wasRunning = checker.start(true, true);

    // Assert
    assertTrue(wasRunning);
    assertEquals(0, checker.getRevocationDNFCounter());
    verify(clientContext, times(3)).start(Mockito.<ClientGetter>any());
  }

  @Test
  void onSuccess_whenResultOk_expectHasBlownTrue_blowCalled_andBlobPersisted() throws Exception {
    // Arrange
    when(manager.isBlown()).thenReturn(true); // allow getBlob* to return data post-blow
    String message = "Revoked!";
    byte[] blobBytes = "BLOB".getBytes(StandardCharsets.UTF_8);
    ArrayBucket blob = new ArrayBucket(blobBytes);
    FetchResult result = Mockito.mock(FetchResult.class);
    when(result.asByteArray()).thenReturn(message.getBytes(StandardCharsets.UTF_8));
    when(result.getMimeType()).thenReturn("text/plain");

    // Act
    checker.onSuccess(result, null, blob);

    // Assert state + manager call
    assertTrue(checker.hasBlown());
    ArgumentCaptor<String> msgCap = ArgumentCaptor.forClass(String.class);
    verify(manager, times(1)).blow(msgCap.capture(), eq(false));
    assertEquals(message, msgCap.getValue());

    // Blob file written
    assertEquals(blobBytes.length, checker.getBlobSize());

    // In-memory bucket returned when blown
    RandomAccessBucket rb = checker.getBlobBucket();
    RandomAccessBuffer buf = checker.getBlobBuffer();
    try {
      assertNotNull(rb);
      try (FileBucket onDisk = new FileBucket(blobFile, true, false, false, false)) {
        assertEquals(onDisk.size(), rb.size());
      }

      // Buffer access returns the same bytes
      assertNotNull(buf);
      byte[] roundtrip = new byte[(int) buf.size()];
      buf.pread(0, roundtrip, 0, roundtrip.length);
      assertEquals(
          new String(blobBytes, StandardCharsets.UTF_8),
          new String(roundtrip, StandardCharsets.UTF_8));
    } finally {
      if (buf != null) {
        buf.close();
        buf.free();
      }
      if (rb != null) {
        rb.close();
      }
    }
  }

  @Test
  void onFailure_whenFatalNotDefinitelyFatal_expectBlowMaybeInternalTrue() {
    // Arrange: INTERNAL_ERROR is fatal but not definitely fatal per FetchException
    FetchException ex = new FetchException(FetchExceptionMode.INTERNAL_ERROR, "oops");

    // Act
    checker.onFailure(ex, null, new ArrayBucket());

    // Assert
    verify(manager, times(1)).blow(any(String.class), eq(true));
  }

  @Test
  void onFailure_whenDefinitelyFatal_expectBlowFalse_andBlobMoved() {
    // Arrange: TOO_BIG is fatal and definitely fatal
    byte[] blobBytes = "REVOC".getBytes(StandardCharsets.UTF_8);
    ArrayBucket blob = new ArrayBucket(blobBytes);
    FetchException ex = new FetchException(FetchExceptionMode.TOO_BIG, "too big");

    // Act
    checker.onFailure(ex, null, blob);

    // Assert: manager.blow called with false and file written
    verify(manager, times(1)).blow(any(String.class), eq(false));
    assertEquals(blobBytes.length, checker.getBlobSize());
  }

  @Test
  void onFailure_whenNewUriProvided_expectRedirectBlow_andRetryScheduledForRecentlyFailed()
      throws Exception {
    // Arrange: non-fatal with newURI
    FreenetURI newUri = new FreenetURI("KSK@redirect");
    FetchException ex = new FetchException(FetchExceptionMode.RECENTLY_FAILED, newUri);

    // Act
    checker.onFailure(ex, null, new ArrayBucket());

    // Assert: redirect message delivered and a retry scheduled after 1s
    verify(manager, times(1)).blow(contains("redirecting"), eq(false));
    verify(ticker, times(1)).queueTimedJob(any(Runnable.class), eq(1000L));
  }

  @Test
  void onFailure_afterThreeDNFs_expectCounterReset_lastSucceededSet_andNoRevocationFoundCalled() {
    // Arrange + Act: three DNFs
    checker.onFailure(
        new FetchException(FetchExceptionMode.DATA_NOT_FOUND), null, new ArrayBucket());
    checker.onFailure(
        new FetchException(FetchExceptionMode.DATA_NOT_FOUND), null, new ArrayBucket());
    checker.onFailure(
        new FetchException(FetchExceptionMode.DATA_NOT_FOUND), null, new ArrayBucket());

    // Assert: counter reset and lastSucceeded recent
    assertEquals(0, checker.getRevocationDNFCounter());
    long delta = checker.lastSucceededDelta();
    assertTrue(delta >= 0 && delta < 5000, "lastSucceededDelta should be a recent small value");
    verify(manager, times(1)).noRevocationFound();
  }

  @Test
  void lastSucceededDelta_whenNeverSet_expectMinusOne() {
    // Fresh checker (new instance to avoid previous DNF side effects)
    checker = new RevocationChecker(manager, blobFile);
    assertEquals(-1, checker.lastSucceededDelta());
  }

  @Test
  void start_whenBlobFileAlreadyExists_expectProcessRevocationBlobInvoked() throws Exception {
    // Arrange: write a small existing blob
    try (FileOutputStream fos = new FileOutputStream(blobFile)) {
      fos.write("OLD".getBytes(StandardCharsets.UTF_8));
    }
    UpdateOverMandatoryManager uom = Mockito.mock(UpdateOverMandatoryManager.class);
    when(manager.getUpdateOverMandatory()).thenReturn(uom);

    // Act
    checker.start(false);

    // Assert: disk path processed via UpdateOverMandatory
    ArgumentCaptor<ArrayBucket> cap = ArgumentCaptor.forClass(ArrayBucket.class);
    verify(uom, times(1)).processRevocationBlob(cap.capture(), eq("disk"), eq(true));
    assertEquals(3, cap.getValue().size());
  }
}
