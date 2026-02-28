package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import network.crypta.client.FetchContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.CompatibilityAnalyser;
import network.crypta.client.events.ClientEventProducer;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.NonClosingOutputStream;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetPersistenceCodecTest {
  private static final long CLIENT_DETAIL_MAGIC = 0x67145b675d2e22f4L;
  private static final int CLIENT_DETAIL_VERSION = 1;

  @Test
  void readBasicRestoreData_whenValidDiskData_returnsParsedBundleAndRegistersListener()
      throws Exception {
    ClientGet request = new ClientGet();
    ClientContext context = mock(ClientContext.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    FetchContext fetchContext = mock(FetchContext.class);
    ClientEventProducer eventProducer = mock(ClientEventProducer.class);
    Bucket initialMetadata = mock(Bucket.class);
    when(fetchContext.getEventProducer()).thenReturn(eventProducer);
    try (DataInputStream input = input(basicRestoreHeaderPayload());
        MockedStatic<ClientGetGetterFactory> mocked =
            Mockito.mockStatic(ClientGetGetterFactory.class)) {
      mocked
          .when(() -> ClientGetGetterFactory.readFetchContextOrDefault(input, context, checker))
          .thenReturn(fetchContext);
      mocked
          .when(() -> ClientGetGetterFactory.readInitialMetadata(input, context, checker))
          .thenReturn(initialMetadata);

      ClientGetPersistenceCodec.BasicRestoreData restored =
          ClientGetPersistenceCodec.readBasicRestoreData(request, input, context, checker);

      assertEquals("KSK@codec-restore", restored.uri().toString());
      assertEquals(ClientGet.ReturnType.DISK, restored.returnType());
      assertEquals("target.bin", restored.targetFile().getPath());
      assertTrue(restored.binaryBlob());
      assertSame(fetchContext, restored.fetchContext());
      assertEquals("txt", restored.extensionCheck());
      assertSame(initialMetadata, restored.initialMetadata());
      verify(eventProducer).addEventListener(any(ClientGetEventHandling.class));
    }
  }

  @Test
  void readBasicRestoreData_whenMagicIsInvalid_throwsStorageFormatException() throws IOException {
    ClientGet request = new ClientGet();
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeLong(123L);
      out.writeInt(CLIENT_DETAIL_VERSION);
    }
    try (DataInputStream input = input(buffer.toByteArray())) {
      StorageFormatException error =
          assertThrows(
              StorageFormatException.class,
              () ->
                  ClientGetPersistenceCodec.readBasicRestoreData(
                      request, input, mock(ClientContext.class), mock(ChecksumChecker.class)));

      assertEquals("Bad magic for request", error.getMessage());
    }
  }

  @Test
  void readBasicRestoreData_whenVersionIsInvalid_throwsStorageFormatException() throws IOException {
    ClientGet request = new ClientGet();
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeLong(CLIENT_DETAIL_MAGIC);
      out.writeInt(CLIENT_DETAIL_VERSION + 1);
    }
    try (DataInputStream input = input(buffer.toByteArray())) {
      StorageFormatException error =
          assertThrows(
              StorageFormatException.class,
              () ->
                  ClientGetPersistenceCodec.readBasicRestoreData(
                      request, input, mock(ClientContext.class), mock(ChecksumChecker.class)));

      assertEquals("Bad version 2", error.getMessage());
    }
  }

  @Test
  void readBasicRestoreData_whenUriIsInvalid_throwsStorageFormatException() throws IOException {
    ClientGet request = new ClientGet();
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeLong(CLIENT_DETAIL_MAGIC);
      out.writeInt(CLIENT_DETAIL_VERSION);
      out.writeUTF("not-a-freenet-uri");
    }
    try (DataInputStream input = input(buffer.toByteArray())) {
      StorageFormatException error =
          assertThrows(
              StorageFormatException.class,
              () ->
                  ClientGetPersistenceCodec.readBasicRestoreData(
                      request, input, mock(ClientContext.class), mock(ChecksumChecker.class)));

      assertEquals("Bad URI", error.getMessage());
    }
  }

  @Test
  void readBasicRestoreData_whenReturnTypeIsInvalid_throwsStorageFormatException()
      throws IOException {
    ClientGet request = new ClientGet();
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeLong(CLIENT_DETAIL_MAGIC);
      out.writeInt(CLIENT_DETAIL_VERSION);
      out.writeUTF("KSK@codec-invalid-type");
      out.writeShort(99);
    }
    try (DataInputStream input = input(buffer.toByteArray())) {
      StorageFormatException error =
          assertThrows(
              StorageFormatException.class,
              () ->
                  ClientGetPersistenceCodec.readBasicRestoreData(
                      request, input, mock(ClientContext.class), mock(ChecksumChecker.class)));

      assertEquals("Bad return type 99", error.getMessage());
    }
  }

  @Test
  void readTransientProgressFields_whenExplicitIdentifier_updatesStateAndExpectedHashes()
      throws Exception {
    ClientGet request = new ClientGet();
    ExpectedHashes expected = new ExpectedHashes(new HashResult[0], "req-explicit", true);
    try (DataInputStream input = input(transientPayload(42L, "text/plain"));
        MockedStatic<ClientGetGetterFactory> mocked =
            Mockito.mockStatic(ClientGetGetterFactory.class)) {
      mocked
          .when(() -> ClientGetGetterFactory.readExpectedHashes(input, "req-explicit", true))
          .thenReturn(expected);

      ClientGetPersistenceCodec.readTransientProgressFields(request, input, "req-explicit", true);

      assertEquals(42L, request.state().getFoundDataLength());
      assertEquals("text/plain", request.state().getFoundDataMimeType());
      assertSame(expected, request.state().getExpectedHashes());
      assertNotNull(request.state().getCompatibilityAnalyser());
    }
  }

  @Test
  void readTransientProgressFields_whenUsingRequestIdentifier_usesRequestScope() throws Exception {
    ClientGet request = new ClientGet();
    setField(request, ClientRequest.class, "identifier", "req-overload");
    setField(request, ClientRequest.class, "global", true);
    try (DataInputStream input = input(transientPayload(7L, null));
        MockedStatic<ClientGetGetterFactory> mocked =
            Mockito.mockStatic(ClientGetGetterFactory.class)) {
      mocked
          .when(() -> ClientGetGetterFactory.readExpectedHashes(input, "req-overload", true))
          .thenReturn(null);

      ClientGetPersistenceCodec.readTransientProgressFields(request, input);

      assertEquals(7L, request.state().getFoundDataLength());
      assertNull(request.state().getFoundDataMimeType());
      mocked.verify(
          () -> ClientGetGetterFactory.readExpectedHashes(input, "req-overload", true), times(1));
    }
  }

  @Test
  void restoreState_whenInProgress_returnsGetterAndDelegatesRestore() throws Exception {
    ClientGet request = Mockito.spy(new ClientGet());
    ClientContext context = mock(ClientContext.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    RequestIdentifier reqID =
        new RequestIdentifier(false, "client", "req-restore", RequestIdentifier.RequestType.GET);
    Bucket bucket = mock(Bucket.class);
    ClientGetter getter = mock(ClientGetter.class);
    //noinspection resource
    doReturn(bucket).when(request).makeBucket(false);
    doReturn(getter).when(request).makeGetterForPersistence(bucket);

    try (DataInputStream input = input(new byte[0]);
        MockedStatic<ClientGetGetterFactory> mocked =
            Mockito.mockStatic(ClientGetGetterFactory.class)) {
      ClientGetter restored =
          ClientGetPersistenceCodec.restoreState(request, input, reqID, context, checker);

      assertSame(getter, restored);
      mocked.verify(
          () ->
              ClientGetGetterFactory.restoreInProgressState(
                  any(DataInputStream.class), eq(context), eq(checker), eq(getter), eq(request)),
          times(1));
    }
  }

  @Test
  void restoreState_whenFinishedDirectAndBucketMissing_marksRequestUnfinished() throws Exception {
    ClientGet request = bareRequest("req-finished-direct");
    setField(request, ClientRequest.class, "finished", true);
    ClientContext context = mock(ClientContext.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    RequestIdentifier reqID =
        new RequestIdentifier(
            false, "client", "req-finished-direct", RequestIdentifier.RequestType.GET);

    try (DataInputStream input = input(finishedPayload(true, transientPayload(55L, null)));
        MockedStatic<ClientGetGetterFactory> mocked =
            Mockito.mockStatic(ClientGetGetterFactory.class)) {
      mocked
          .when(() -> ClientGetGetterFactory.readExpectedHashes(any(), any(), anyBoolean()))
          .thenReturn(null);
      mocked
          .when(
              () ->
                  ClientGetGetterFactory.restoreCompletedDirectBucketOrNull(
                      any(DataInputStream.class), eq(context), eq(checker)))
          .thenReturn(null);

      ClientGetter restored =
          ClientGetPersistenceCodec.restoreState(request, input, reqID, context, checker);

      assertNull(restored);
      assertFalse(request.state().hasSucceeded());
      assertFalse(getClientRequestBooleanField(request, "finished"));
      assertNull(request.state().getReturnBucketDirect());
    }
  }

  @Test
  void restoreState_whenFinishedFailureWithMessage_setsFailedMessageAndStarted() throws Exception {
    ClientGet request = bareRequest("req-finished-failure");
    setField(request, ClientRequest.class, "finished", true);
    ClientContext context = mock(ClientContext.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    RequestIdentifier reqID =
        new RequestIdentifier(
            false, "client", "req-finished-failure", RequestIdentifier.RequestType.GET);
    GetFailedMessage failure = mock(GetFailedMessage.class);

    try (DataInputStream input =
            input(finishedPayload(false, transientPayload(91L, "application/json")));
        MockedStatic<ClientGetGetterFactory> mocked =
            Mockito.mockStatic(ClientGetGetterFactory.class)) {
      mocked
          .when(() -> ClientGetGetterFactory.readExpectedHashes(any(), any(), anyBoolean()))
          .thenReturn(null);
      mocked
          .when(
              () ->
                  ClientGetGetterFactory.restoreFailureMessageOrNull(
                      any(DataInputStream.class),
                      eq(reqID),
                      eq(91L),
                      eq("application/json"),
                      eq(context),
                      eq(checker)))
          .thenReturn(failure);

      ClientGetter restored =
          ClientGetPersistenceCodec.restoreState(request, input, reqID, context, checker);

      assertNull(restored);
      assertSame(failure, request.state().getFailedMessage());
      assertTrue(getClientRequestBooleanField(request, "started"));
    }
  }

  @Test
  void writeClientDetail_whenInProgressAndTrivialProgressTrue_writesCoreFieldsAndTransientState()
      throws Exception {
    ClientGet request = bareRequest("req-write");
    setField(request, ClientRequest.class, "uri", new FreenetURI("KSK@req-write"));
    setField(request, ClientGet.class, "binaryBlob", false);
    setField(request, ClientGet.class, "extensionCheck", "txt");
    setField(request, ClientGet.class, "initialMetadata", null);
    setField(request, ClientRequest.class, "finished", false);
    FetchContext fetchContext = mock(FetchContext.class);
    setField(request, ClientGet.class, "fctx", fetchContext);
    ClientGetter getter = mock(ClientGetter.class);
    when(getter.writeTrivialProgress(any(DataOutputStream.class))).thenReturn(true);
    setField(request, ClientGet.class, "getter", getter);
    request.state().setFoundDataLength(321L);
    request.state().setFoundDataMimeType("text/plain");
    request.state().setCompatibilityAnalyser(new CompatibilityAnalyser());
    request.state().setExpectedHashes(null);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(buffer);

    try (MockedStatic<ClientGetGetterFactory> mocked =
        Mockito.mockStatic(ClientGetGetterFactory.class, Mockito.CALLS_REAL_METHODS)) {
      mocked
          .when(
              () ->
                  ClientGetGetterFactory.checksummedWriter(
                      any(DataOutputStream.class), any(ChecksumChecker.class)))
          .thenAnswer(
              invocation -> {
                DataOutputStream target = invocation.getArgument(0);
                return new DataOutputStream(new NonClosingOutputStream(target));
              });

      ClientGetPersistenceCodec.writeClientDetail(request, out, checker);
    }

    try (DataInputStream in = input(buffer.toByteArray())) {
      assertEquals(CLIENT_DETAIL_MAGIC, in.readLong());
      assertEquals(CLIENT_DETAIL_VERSION, in.readInt());
      assertEquals("KSK@req-write", in.readUTF());
      assertEquals(ClientGet.ReturnType.DIRECT.code, in.readShort());
      assertFalse(in.readBoolean());
      assertTrue(in.readBoolean());
      assertEquals("txt", in.readUTF());
      assertFalse(in.readBoolean());
      assertEquals(321L, in.readLong());
      assertTrue(in.readBoolean());
      assertEquals("text/plain", in.readUTF());
      //noinspection ObviousNullCheck
      assertNotNull(new CompatibilityAnalyser(in));
      assertEquals(0, in.readInt());
    }

    verify(fetchContext).writeTo(any(DataOutputStream.class));
    verify(getter).writeTrivialProgress(any(DataOutputStream.class));
  }

  @Test
  void writeClientDetail_whenFinishedDirectSuccess_writesStoredBucket() throws Exception {
    ClientGet request = bareRequest("req-finished-write");
    setField(request, ClientRequest.class, "uri", new FreenetURI("KSK@req-finished-write"));
    setField(request, ClientGet.class, "binaryBlob", true);
    setField(request, ClientGet.class, "extensionCheck", null);
    setField(request, ClientGet.class, "initialMetadata", null);
    setField(request, ClientRequest.class, "finished", true);
    FetchContext fetchContext = mock(FetchContext.class);
    setField(request, ClientGet.class, "fctx", fetchContext);
    request.state().setSucceeded(true);
    request.state().setFoundDataLength(999L);
    request.state().setFoundDataMimeType(null);
    request.state().setExpectedHashes(null);
    Bucket directBucket = mock(Bucket.class);
    doAnswer(
            invocation -> {
              DataOutputStream stream = invocation.getArgument(0);
              stream.writeInt(777);
              return null;
            })
        .when(directBucket)
        .storeTo(any(DataOutputStream.class));
    request.state().setReturnBucketDirect(directBucket);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(buffer);

    try (MockedStatic<ClientGetGetterFactory> mocked =
        Mockito.mockStatic(ClientGetGetterFactory.class, Mockito.CALLS_REAL_METHODS)) {
      mocked
          .when(
              () ->
                  ClientGetGetterFactory.checksummedWriter(
                      any(DataOutputStream.class), any(ChecksumChecker.class)))
          .thenAnswer(
              invocation -> {
                DataOutputStream target = invocation.getArgument(0);
                return new DataOutputStream(new NonClosingOutputStream(target));
              });

      ClientGetPersistenceCodec.writeClientDetail(request, out, checker);
    }

    try (DataInputStream in = input(buffer.toByteArray())) {
      assertEquals(CLIENT_DETAIL_MAGIC, in.readLong());
      assertEquals(CLIENT_DETAIL_VERSION, in.readInt());
      assertEquals("KSK@req-finished-write", in.readUTF());
      assertEquals(ClientGet.ReturnType.DIRECT.code, in.readShort());
      assertTrue(in.readBoolean());
      assertFalse(in.readBoolean());
      assertFalse(in.readBoolean());
      assertTrue(in.readBoolean());
      assertEquals(999L, in.readLong());
      assertFalse(in.readBoolean());
      //noinspection ObviousNullCheck
      assertNotNull(new CompatibilityAnalyser(in));
      assertEquals(0, in.readInt());
      assertEquals(777, in.readInt());
    }
  }

  private static ClientGet bareRequest(String identifier) throws Exception {
    ClientGet request = new ClientGet();
    setField(request, ClientRequest.class, "identifier", identifier);
    setField(request, ClientRequest.class, "global", false);
    setField(request, ClientGet.class, "returnType", ClientGet.ReturnType.DIRECT);
    return request;
  }

  private static byte[] basicRestoreHeaderPayload() throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeLong(CLIENT_DETAIL_MAGIC);
      out.writeInt(CLIENT_DETAIL_VERSION);
      out.writeUTF("KSK@codec-restore");
      out.writeShort(ClientGet.ReturnType.DISK.code);
      out.writeUTF("target.bin");
      out.writeBoolean(true);
      out.writeBoolean(true);
      out.writeUTF("txt");
    }
    return buffer.toByteArray();
  }

  private static byte[] transientPayload(long foundDataLength, String mimeType) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeLong(foundDataLength);
      if (mimeType != null) {
        out.writeBoolean(true);
        out.writeUTF(mimeType);
      } else {
        out.writeBoolean(false);
      }
      new CompatibilityAnalyser().writeTo(out);
    }
    return buffer.toByteArray();
  }

  private static byte[] finishedPayload(boolean succeeded, byte[] transientPayload)
      throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeBoolean(succeeded);
      out.write(transientPayload);
    }
    return buffer.toByteArray();
  }

  private static DataInputStream input(byte[] bytes) {
    return new DataInputStream(new ByteArrayInputStream(bytes));
  }

  @SuppressWarnings({"java:S3011"})
  private static void setField(Object target, Class<?> owner, String fieldName, Object value)
      throws ReflectiveOperationException {
    Field field = owner.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  @SuppressWarnings({"java:S3011"})
  private static boolean getClientRequestBooleanField(Object target, String fieldName)
      throws ReflectiveOperationException {
    Field field = ClientRequest.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    return field.getBoolean(target);
  }
}
