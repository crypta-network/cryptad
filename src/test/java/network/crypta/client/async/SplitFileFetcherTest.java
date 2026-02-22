package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.io.ResumeFailedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SplitFileFetcherTest {

  @Mock
  private ClientGetter parent; // also acts as GetCompletionCallback & FileGetCompletionCallback

  @Mock private ClientContext clientContext;
  @Mock private ClientRequestScheduler scheduler;
  @Mock private SplitFileFetcherGet sendableGetter;

  @BeforeEach
  void setup() {
    // Default stubs used by multiple tests
    lenient().when(parent.realTimeFlag()).thenReturn(false);
    lenient().when(parent.getPriorityClass()).thenReturn((short) 5);
    lenient().when(clientContext.getChkFetchScheduler(false)).thenReturn(scheduler);
  }

  // Helper to set private fields via reflection for test wiring
  @SuppressWarnings({"java:S3011"})
  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field f = SplitFileFetcher.class.getDeclaredField(fieldName);
      f.setAccessible(true);
      f.set(target, value);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @SuppressWarnings({"java:S3011"})
  private static void setParentCtx(ClientGetter parent, FetchContext ctx) {
    try {
      Field f = ClientGetter.class.getDeclaredField("ctx");
      f.setAccessible(true);
      f.set(parent, ctx);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @SuppressWarnings("java:S3011")
  private static void cleanupFetcherTempFile(SplitFileFetcher fetcher, File tmp) {
    try {
      Field rafField = SplitFileFetcher.class.getDeclaredField("raf");
      rafField.setAccessible(true);
      Object raw = rafField.get(fetcher);
      if (raw instanceof LockableRandomAccessBuffer raf) {
        raf.close();
        raf.free();
      }
      rafField.set(fetcher, null);
    } catch (Exception ignored) {
      // Best-effort cleanup to avoid leaking mapped files on Windows.
    }
    if (!tmp.delete() && tmp.exists()) {
      tmp.deleteOnExit();
    }
  }

  private static byte[] resumeRecordForTruncation(File file, long size, long token)
      throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);
    // completeViaTruncation=true, then path, then expected RAF size, then token
    dos.writeBoolean(true);
    dos.writeUTF(file.getAbsolutePath());
    dos.writeLong(size);
    dos.writeLong(token);
    dos.flush();
    return bos.toByteArray();
  }

  private SplitFileFetcher newResumedFetcherWithTruncation(File file, long size, long token)
      throws Exception {
    byte[] rec = resumeRecordForTruncation(file, size, token);
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(rec));
    // Ensure wantBinaryBlob is deterministic
    lenient().when(parent.collectingBinaryBlob()).thenReturn(true);
    return new SplitFileFetcher(parent, dis, clientContext);
  }

  @Test
  void constructor_resumeWithTruncation_missingFile_throwsResumeFailedException() {
    DataInputStream dis; // assigned below
    // Build a proper stream that points to a missing path so resume fails deterministically.
    File nonExistent = new File("/nonexistent-xyz-should-not-exist" + System.nanoTime());
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeBoolean(true);
      dos.writeUTF(nonExistent.getAbsolutePath());
      dos.writeLong(0L);
      dos.writeLong(123L);
      dos.flush();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
    final DataInputStream finalDis = dis;
    assertThrows(
        ResumeFailedException.class, () -> new SplitFileFetcher(parent, finalDis, clientContext));
  }

  @Test
  void getToken_returnsValueFromResumeRecord() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[8]);
    }
    long token = 987654321L;
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), token);
    assertEquals(token, f.getToken());
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void onFetchedBlock_whenGetterHasQueued_expectNotifyFalse() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 1L);
    setField(f, "context", clientContext);
    setField(f, "getter", sendableGetter);
    when(sendableGetter.hasQueued()).thenReturn(true);

    f.onFetchedBlock();

    verify(parent).completedBlock(false, clientContext);
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void onFetchedBlock_whenBelowThresholdAndRecent_expectDontNotifyTrue() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 2L);
    setField(f, "context", clientContext);
    setField(f, "getter", sendableGetter);
    when(sendableGetter.hasQueued()).thenReturn(false);
    // lastNotifiedStoreFetch = now, storeFetchCounter = 0
    setField(f, "lastNotifiedStoreFetch", System.currentTimeMillis());
    setField(f, "storeFetchCounter", 0);

    f.onFetchedBlock();

    verify(parent).completedBlock(true, clientContext);
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void onFetchedBlock_whenCounterReachesThreshold_expectNotifyFalse() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 3L);
    setField(f, "context", clientContext);
    setField(f, "getter", sendableGetter);
    when(sendableGetter.hasQueued()).thenReturn(false);
    // Set counter to threshold so branch triggers
    setField(f, "storeFetchCounter", SplitFileFetcher.STORE_NOTIFY_BLOCKS);

    f.onFetchedBlock();

    verify(parent).completedBlock(false, clientContext);
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void onFetchedBlock_whenTimeElapsed_expectNotifyFalse() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 4L);
    setField(f, "context", clientContext);
    setField(f, "getter", sendableGetter);
    when(sendableGetter.hasQueued()).thenReturn(false);
    // Force elapsed time branch: lastNotifiedStoreFetch way in the past
    setField(f, "lastNotifiedStoreFetch", 0L);
    setField(f, "storeFetchCounter", 0);

    f.onFetchedBlock();

    verify(parent).completedBlock(false, clientContext);
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void onFailedBlock_delegatesToParent() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 5L);
    setField(f, "context", clientContext);

    f.onFailedBlock();

    verify(parent).failedBlock(clientContext);
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void cancel_invokesCallbackWithCancelled() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 6L);
    setField(f, "context", clientContext);

    ArgumentCaptor<FetchException> captor = ArgumentCaptor.forClass(FetchException.class);

    f.cancel(clientContext);

    verify(parent).onFailure(captor.capture(), eq(f), eq(clientContext));
    assertEquals(FetchExceptionMode.CANCELLED, captor.getValue().getMode());
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void onSuccess_withTruncation_callsFileCallbackAndCancelsGetter() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    byte[] content = "abc".getBytes(StandardCharsets.UTF_8);
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(content);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 7L);
    setField(f, "context", clientContext);

    // storage and getter are needed by onSuccess
    SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
    setField(f, "storage", storage);
    setField(f, "getter", sendableGetter);

    // removePendingKeys goes through scheduler; passing null KeyListener is fine on a mock
    f.onSuccess();

    // We avoid directly verifying the overloaded onSuccess(File,...) due to signature ambiguity on
    // the concrete class; instead we verify observable side effects around it.
    verify(sendableGetter).cancel(clientContext);
    // Scheduler invocation to remove pending keys (null keyListener on a mock storage is fine)
    verify(scheduler)
        .removePendingKeys((KeyListener) org.mockito.ArgumentMatchers.isNull(), eq(true));
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void onResume_countsAndCallbacksCorrectly() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[2]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 8L);
    setField(f, "context", clientContext);

    ClientMetadata meta = new ClientMetadata("text/plain");

    f.onResume(3, 2, meta, 123L);

    // completedBlock: (succeededBlocks-1) times with dontNotify=true, then once with
    // dontNotify=false
    verify(parent, times(2)).completedBlock(true, clientContext);
    verify(parent).completedBlock(false, clientContext);
    // failedBlock: (failedBlocks-1) times with dontNotify=true, then once without dontNotify param
    verify(parent).failedBlock(true, clientContext);
    verify(parent).failedBlock(false, clientContext);
    verify(parent).blockSetFinalized(clientContext);
    verify(parent).onExpectedMIME(meta, clientContext);
    verify(parent).onExpectedSize(123L, clientContext);
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void setSplitfileBlocks_delegatesToParentAndNotify() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 9L);
    setField(f, "context", clientContext);

    f.setSplitfileBlocks(4, 7);

    verify(parent).addMustSucceedBlocks(4);
    verify(parent).addBlocks(7);
    verify(parent).notifyClients(clientContext);
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void onSplitfileCompatibilityMode_delegatesToCallback() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 10L);
    setField(f, "context", clientContext);

    byte[] customKey = new byte[] {1, 2, 3};
    f.onSplitfileCompatibilityMode(
        CompatibilityMode.COMPAT_1250,
        CompatibilityMode.COMPAT_UNKNOWN,
        customKey,
        true,
        false,
        true);

    verify(parent)
        .onSplitfileCompatibilityMode(
            CompatibilityMode.COMPAT_1250,
            CompatibilityMode.COMPAT_UNKNOWN,
            customKey,
            true,
            false,
            true,
            clientContext);
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void maybeAddToBinaryBlob_whenParentIsClientGetter_delegatesToParent() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 11L);
    setField(f, "context", clientContext);

    ClientCHKBlock block = mock(ClientCHKBlock.class);
    f.maybeAddToBinaryBlob(block);
    verify(parent).addKeyToBinaryBlob(block, clientContext);
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void getSendableGet_returnsAssignedGetter() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 12L);
    setField(f, "getter", sendableGetter);
    assertEquals(sendableGetter, f.getSendableGet());
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void clearCooldown_and_reduceCooldown_delegateWhenNotFinished() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 13L);
    setField(f, "context", clientContext);
    setField(f, "getter", sendableGetter);

    f.clearCooldown();
    f.reduceCooldown(123L);

    verify(sendableGetter).clearWakeupTime(clientContext);
    verify(sendableGetter).reduceWakeupTime(123L, clientContext);
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void hasFinished_reflectsFailAndSuccess() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 14L);

    assertFalse(f.hasFinished());

    // Mark as failed via cancel()
    setField(f, "context", clientContext);
    f.cancel(clientContext);
    assertTrue(f.hasFinished());
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void writeTrivialProgress_whenDone_returnsFalseAndWritesFalse() throws Exception {
    SplitFileFetcher f = new SplitFileFetcher(); // protected no-arg ctor for tests
    // Mark as finished by setting succeeded=true via reflection
    setField(f, "succeeded", true);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);
    boolean ret = f.writeTrivialProgress(dos);

    assertFalse(ret);
    // First byte should be boolean false
    byte[] data = bos.toByteArray();
    assertEquals(0, data[0]);
  }

  @Test
  void writeTrivialProgress_withTruncation_writesExpectedHeaderAndToken() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[4]);
    }
    long token = 424242L;
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), token);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);
    boolean ret = f.writeTrivialProgress(dos);

    assertTrue(ret);
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
    assertTrue(dis.readBoolean()); // not done
    assertTrue(dis.readBoolean()); // completeViaTruncation
    String path = dis.readUTF();
    long size = dis.readLong();
    long tok = dis.readLong();
    assertEquals(tmp.getAbsolutePath(), path);
    assertEquals(tmp.length(), size);
    assertEquals(token, tok);
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void writeTrivialProgress_withoutTruncation_callsStoreToOnRAF() throws Exception {
    SplitFileFetcher f = new SplitFileFetcher();
    // Ensure not finished
    setField(f, "failed", false);
    setField(f, "succeeded", false);
    // No truncation path
    // Provide an RAF mock that we can verify
    LockableRandomAccessBuffer raf = mock(LockableRandomAccessBuffer.class);
    setField(f, "raf", raf);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);
    // Also need a token write at the end; default token is 0 from the test ctor
    boolean ret = f.writeTrivialProgress(dos);

    assertTrue(ret);
    verify(raf).storeTo(any(DataOutputStream.class));
  }

  @Test
  void getPriorityClass_and_toNetwork_delegateToParent() throws Exception {
    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 15L);
    setField(f, "context", clientContext);

    assertEquals(5, f.getPriorityClass());
    f.toNetwork();
    verify(parent).toNetwork(clientContext);
    cleanupFetcherTempFile(f, tmp);
  }

  @Test
  void localRequestOnly_reflectsFetchContextFromParent() throws Exception {
    // Prepare a FetchContext instance with localRequestOnly=true
    FetchContext fc =
        new FetchContext(
            FetchContextOptions.builder()
                .limits(1L, 1L, 1)
                .archiveLimits(1, 0, 0, true)
                .retryLimits(0, 0, 0)
                .splitfileLimits(true, 0, 0)
                .behavior(true, true, false)
                .clientOptions(new network.crypta.client.events.SimpleEventProducer(), true, true)
                .filterOverrides(null, null, null)
                .build());
    // Set parent.ctx reflectively so resume ctor copies it into blockFetchContext
    setParentCtx(parent, fc);

    File tmp = File.createTempFile("splitfetch-test-", ".tmp");
    try (FileOutputStream fos = new FileOutputStream(tmp)) {
      fos.write(new byte[1]);
    }
    SplitFileFetcher f = newResumedFetcherWithTruncation(tmp, tmp.length(), 16L);
    assertTrue(f.localRequestOnly());
    cleanupFetcherTempFile(f, tmp);
  }
}
