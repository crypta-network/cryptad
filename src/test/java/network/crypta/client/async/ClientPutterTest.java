package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.keys.BaseClientKey;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientPutterTest {

  @Mock private ClientPutCallback clientCallback;

  @Mock private RequestClient requestClient;

  private InsertContext insertContextCurrent;

  private static InsertContext newInsertContext(CompatibilityMode mode) {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(1, 0)
            .splitfileSegmentLimits(128, 128)
            .clientOptions(new SimpleEventProducer(), false, false, false)
            .compressorDescriptor(null)
            .redundancy(0, 0)
            .compatibility(mode)
            .build());
  }

  @BeforeEach
  void setUp() {
    org.mockito.Mockito.lenient().when(requestClient.persistent()).thenReturn(false);
    org.mockito.Mockito.lenient().when(requestClient.realTimeFlag()).thenReturn(false);
    org.mockito.Mockito.lenient().when(clientCallback.getRequestClient()).thenReturn(requestClient);
    insertContextCurrent = newInsertContext(CompatibilityMode.COMPAT_CURRENT);
  }

  @Test
  void start_whenDataNull_expectClientFailureAndFinished() throws Exception {
    ClientPutter putter =
        new ClientPutter(
            clientCallback,
            /*data*/ null,
            FreenetURI.EMPTY_CHK_URI,
            new ClientMetadata("text/plain"),
            insertContextCurrent,
            /*priorityClass*/ (short) 0,
            /*isMetadata*/ false,
            /*targetFilename*/ null,
            /*binaryBlob*/ false,
            /*overrideSplitfileCrypto*/ null,
            /*metadataThreshold*/ 0L);

    boolean result = putter.start(false, mock(ClientContext.class));

    ArgumentCaptor<InsertException> ex = ArgumentCaptor.forClass(InsertException.class);
    verify(clientCallback, times(1)).onFailure(ex.capture(), any());
    assertEquals(InsertExceptionMode.BUCKET_ERROR, ex.getValue().mode);
    assertTrue(putter.isFinished());
    assertTrue(result, "start() returns true even when failing to start");
    assertNull(putter.getURI());
  }

  @Test
  void start_whenOverrideSplitfileCryptoWrongLength_expectInvalidUriFailure() throws Exception {
    RandomAccessBucket data = mock(RandomAccessBucket.class);

    byte[] badOverride = new byte[16];
    ClientPutter putter =
        new ClientPutter(
            clientCallback,
            data,
            FreenetURI.EMPTY_CHK_URI,
            new ClientMetadata(),
            insertContextCurrent,
            (short) 0,
            false,
            null,
            false,
            badOverride,
            0L);

    boolean result = putter.start(false, mock(ClientContext.class));

    ArgumentCaptor<InsertException> ex = ArgumentCaptor.forClass(InsertException.class);
    verify(clientCallback).onFailure(ex.capture(), any());
    assertEquals(InsertExceptionMode.INVALID_URI, ex.getValue().mode);
    assertTrue(putter.isFinished());
    assertTrue(result);
  }

  @Test
  void start_whenCancelledBeforeStart_setsOverrideKeyAndNotSchedule() throws Exception {
    RandomAccessBucket data = mock(RandomAccessBucket.class);
    byte[] override = new byte[32];
    for (int i = 0; i < override.length; i++) override[i] = (byte) i;

    ClientPutter putter = getClientPutter(data, override);

    boolean started = putter.start(false, mock(ClientContext.class));
    assertFalse(started);

    // onFailure(CANCELLED) should be invoked
    ArgumentCaptor<InsertException> ex = ArgumentCaptor.forClass(InsertException.class);
    verify(clientCallback).onFailure(ex.capture(), any());
    assertEquals(InsertExceptionMode.CANCELLED, ex.getValue().mode);

    // The override key is applied and exposed
    assertArrayEquals(override, putter.getSplitfileCryptoKey());
  }

  @Test
  void start_whenGuardRejects_doesNotFireFailure() throws Exception {
    RandomAccessBucket data = mock(RandomAccessBucket.class);
    ClientPutter putter =
        new ClientPutter(
            clientCallback,
            data,
            FreenetURI.EMPTY_CHK_URI,
            new ClientMetadata(),
            insertContextCurrent,
            (short) 0,
            false,
            null,
            false,
            null,
            0L);

    // Simulate a re-entry while a start is already in progress
    Field startedStartingField = ClientPutter.class.getDeclaredField("startedStarting");
    startedStartingField.setAccessible(true);
    startedStartingField.setBoolean(putter, true);

    boolean result = putter.start(false, mock(ClientContext.class));

    assertFalse(result, "start() must return false on guard rejection");
    verify(clientCallback, never()).onFailure(any(), any());
  }

  private @NotNull ClientPutter getClientPutter(RandomAccessBucket data, byte[] override)
      throws NoSuchFieldException, IllegalAccessException {
    ClientPutter putter =
        new ClientPutter(
            clientCallback,
            data,
            new FreenetURI("SSK", "doc"),
            new ClientMetadata(),
            insertContextCurrent,
            (short) 0,
            false,
            null,
            false,
            override,
            0L);

    // Set the protected 'cancelled' flag to true via reflection to simulate pre-cancel state.
    Field cancelledField = ClientRequester.class.getDeclaredField("cancelled");
    cancelledField.setAccessible(true);
    cancelledField.setBoolean(putter, true);
    return putter;
  }

  @Test
  void randomiseSplitfileKeys_variousKeyTypesAndCompat() {
    InsertContext oldCompat = newInsertContext(CompatibilityMode.COMPAT_1251);

    // CHK: never randomises regardless of compat
    assertFalse(
        ClientPutter.randomiseSplitfileKeys(new FreenetURI("CHK", null), insertContextCurrent));
    assertFalse(ClientPutter.randomiseSplitfileKeys(new FreenetURI("CHK", null), oldCompat));

    // SSK/KSK/USK with old compat => false
    assertFalse(ClientPutter.randomiseSplitfileKeys(new FreenetURI("SSK", "doc"), oldCompat));
    assertFalse(ClientPutter.randomiseSplitfileKeys(new FreenetURI("KSK", "name"), oldCompat));
    assertFalse(ClientPutter.randomiseSplitfileKeys(new FreenetURI("USK", "site"), oldCompat));

    // With current compat they randomise
    assertTrue(
        ClientPutter.randomiseSplitfileKeys(new FreenetURI("SSK", "doc"), insertContextCurrent));
    assertTrue(
        ClientPutter.randomiseSplitfileKeys(new FreenetURI("KSK", "name"), insertContextCurrent));
    assertTrue(
        ClientPutter.randomiseSplitfileKeys(new FreenetURI("USK", "site"), insertContextCurrent));
  }

  @Test
  void onEncode_whenTargetFilenamePresent_appendsMetaStringAndNotifies() {
    RandomAccessBucket data = mock(RandomAccessBucket.class);
    ClientPutter putter =
        new ClientPutter(
            clientCallback,
            data,
            FreenetURI.EMPTY_CHK_URI,
            new ClientMetadata(),
            insertContextCurrent,
            (short) 0,
            false,
            "file.txt",
            false,
            null,
            0L);

    FreenetURI base = new FreenetURI("CHK", null, new byte[32], new byte[32], null);
    BaseClientKey key = mock(BaseClientKey.class);
    when(key.getURI()).thenReturn(base);

    putter.onEncode(key, null, mock(ClientContext.class));

    FreenetURI expected = base.pushMetaString("file.txt");
    assertEquals(expected, putter.getURI());
    verify(clientCallback, times(1)).onGeneratedURI(expected, putter);

    // Second call with a different URI should not notify again (already set)
    FreenetURI another = new FreenetURI("CHK", null, new byte[32], new byte[32], null);
    BaseClientKey key2 = mock(BaseClientKey.class);
    when(key2.getURI()).thenReturn(another);
    putter.onEncode(key2, null, mock(ClientContext.class));
    verify(clientCallback, times(1)).onGeneratedURI(any(), any());
  }

  @Test
  void onMetadata_firstCallNotifies_secondCallFreesBucket() {
    RandomAccessBucket data = mock(RandomAccessBucket.class);
    ClientPutter putter =
        new ClientPutter(
            clientCallback,
            data,
            FreenetURI.EMPTY_CHK_URI,
            new ClientMetadata(),
            insertContextCurrent,
            (short) 0,
            false,
            null,
            false,
            null,
            0L);

    Bucket bucket1 = mock(Bucket.class);
    Bucket bucket2 = mock(Bucket.class);

    putter.onMetadata(bucket1, null, mock(ClientContext.class));
    verify(clientCallback, times(1)).onGeneratedMetadata(bucket1, putter);

    putter.onMetadata(bucket2, null, mock(ClientContext.class));
    // Second call should free the bucket and not notify client again
    verify(bucket2, times(1)).free();
    verify(clientCallback, times(1)).onGeneratedMetadata(any(), any());
  }

  @Test
  void cancel_whenActive_propagatesToStateAndNotifiesFailure() {
    RandomAccessBucket data = mock(RandomAccessBucket.class);
    ClientPutter putter =
        new ClientPutter(
            clientCallback,
            data,
            FreenetURI.EMPTY_CHK_URI,
            new ClientMetadata(),
            insertContextCurrent,
            (short) 0,
            false,
            null,
            false,
            null,
            0L);

    ClientPutState state = mock(ClientPutState.class);
    // Set currentState via onTransition(null, state, ...)
    putter.onTransition(null, state, mock(ClientContext.class));

    ClientContext context = mock(ClientContext.class);
    putter.cancel(context);

    verify(state, times(1)).cancel(context);
    ArgumentCaptor<InsertException> ex = ArgumentCaptor.forClass(InsertException.class);
    verify(clientCallback).onFailure(ex.capture(), any());
    assertEquals(InsertExceptionMode.CANCELLED, ex.getValue().mode);
    assertTrue(putter.isFinished());
  }

  @Test
  void canRestart_variesWithStateAndDataPresence() {
    RandomAccessBucket data = mock(RandomAccessBucket.class);
    ClientPutter putter =
        new ClientPutter(
            clientCallback,
            data,
            FreenetURI.EMPTY_CHK_URI,
            new ClientMetadata(),
            insertContextCurrent,
            (short) 0,
            false,
            null,
            false,
            null,
            0L);

    // Initially: no current state, data present
    assertTrue(putter.canRestart());

    // While active (currentState != null and not finished): cannot restart
    ClientPutState state = mock(ClientPutState.class);
    putter.onTransition(null, state, mock(ClientContext.class));
    assertFalse(putter.canRestart());

    // After failure: finished -> can restart (data still present)
    putter.onFailure(
        new InsertException(InsertExceptionMode.CANCELLED), state, mock(ClientContext.class));
    assertTrue(putter.canRestart());
  }

  @Test
  void counters_addBlockAndFriends_affectMinSuccessFetchBlocksOnly() {
    RandomAccessBucket data = mock(RandomAccessBucket.class);
    ClientPutter putter =
        new ClientPutter(
            clientCallback,
            data,
            FreenetURI.EMPTY_CHK_URI,
            new ClientMetadata(),
            insertContextCurrent,
            (short) 0,
            false,
            null,
            false,
            null,
            0L);

    assertEquals(0, putter.getMinSuccessFetchBlocks());
    putter.addBlock();
    putter.addBlocks(2);
    putter.addMustSucceedBlocks(3);
    assertEquals(6, putter.getMinSuccessFetchBlocks());
  }

  @Test
  void onSuccess_marksFinishedAndNotifiesClient() {
    RandomAccessBucket data = mock(RandomAccessBucket.class);
    ClientPutter putter =
        new ClientPutter(
            clientCallback,
            data,
            FreenetURI.EMPTY_CHK_URI,
            new ClientMetadata(),
            insertContextCurrent,
            (short) 0,
            false,
            null,
            false,
            null,
            0L);

    ClientPutState state = mock(ClientPutState.class);
    putter.onSuccess(state, mock(ClientContext.class));
    assertTrue(putter.isFinished());
    verify(clientCallback, times(1)).onSuccess(putter);
  }

  @Test
  void getClientDetail_whenPersistentClient_writesAndReturnsBytes() throws Exception {
    RandomAccessBucket data = mock(RandomAccessBucket.class);

    // Mock a ClientPutCallback that ALSO implements PersistentClientCallback
    ClientPutCallback multiCb =
        org.mockito.Mockito.mock(
            ClientPutCallback.class,
            org.mockito.Mockito.withSettings().extraInterfaces(PersistentClientCallback.class));
    when(multiCb.getRequestClient()).thenReturn(requestClient);

    // Configure the PersistentClientCallback bridge methods
    doAnswer(
            inv -> {
              DataOutputStream dos = inv.getArgument(0);
              dos.writeUTF("hello");
              return null;
            })
        .when((PersistentClientCallback) multiCb)
        .getClientDetail(any(DataOutputStream.class), any(ChecksumChecker.class));

    byte[] detail = getDetail(multiCb, data);
    // The exact encoding uses DataOutputStream.writeUTF → modified UTF-8 of "hello"
    // Verify that something was written and begins with the expected header (length prefix)
    assertNotNull(detail);
    // Minimal sanity check: contains the bytes of the string "hello" somewhere
    String s = new String(detail);
    assertTrue(s.contains("hello"));
  }

  private byte[] getDetail(ClientPutCallback multiCb, RandomAccessBucket data) throws IOException {
    ClientPutter putter =
        new ClientPutter(
            multiCb,
            data,
            FreenetURI.EMPTY_CHK_URI,
            new ClientMetadata(),
            insertContextCurrent,
            (short) 0,
            false,
            null,
            false,
            null,
            0L);

    // Use a minimal ChecksumChecker stub; methods unused in this path
    ChecksumChecker checker =
        new ChecksumChecker() {
          @Override
          public int checksumLength() {
            return 0;
          }

          @Override
          public java.io.OutputStream checksumWriter(java.io.OutputStream os, int skipPrefix) {
            return os;
          }

          @Override
          public byte[] appendChecksum(byte[] data) {
            return data;
          }

          @Override
          public boolean checkChecksum(byte[] data, int offset, int length, byte[] checksum) {
            return true;
          }

          @Override
          public byte[] generateChecksum(byte[] bufToChecksum, int offset, int length) {
            return new byte[0];
          }

          @Override
          public int getChecksumTypeID() {
            return 0;
          }

          @Override
          public void copyAndStripChecksum(
              java.io.InputStream is, java.io.OutputStream os, long length) {
            // Test stub: this method is not exercised by the getClientDetail() path.
            // Throwing clarifies intent and avoids silently swallowing unexpected calls.
            throw new UnsupportedOperationException("Not used in this test stub");
          }

          @Override
          public void readAndChecksum(java.io.DataInput is, byte[] buf, int offset, int length) {
            // Test stub: this method is not exercised by the getClientDetail() path.
            // Throwing clarifies intent and avoids silently swallowing unexpected calls.
            throw new UnsupportedOperationException("Not used in this test stub");
          }
        };

    return putter.getClientDetail(checker);
  }
}
