package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import network.crypta.client.async.CompatibilityAnalyser;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashResult;
import network.crypta.support.api.Bucket;
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
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetPersistenceCodecTest {
  private static final long CLIENT_DETAIL_MAGIC = 0x67145b675d2e22f4L;
  private static final int CLIENT_DETAIL_VERSION = 1;

  @Test
  void readBasicRestoreData_whenValidDiskData_returnsParsedBundle() throws Exception {
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ClientGetFetchConfig fetchConfig = new ClientGetFetchConfig();
    fetchConfig.setFilterData(true);
    Bucket initialMetadata = mock(Bucket.class);
    try (DataInputStream input = input(basicRestoreHeaderPayload());
        MockedStatic<ClientGetPersistenceIO> mocked =
            Mockito.mockStatic(ClientGetPersistenceIO.class)) {
      mocked
          .when(
              () ->
                  ClientGetPersistenceIO.readFetchConfigOrDefault(
                      input, fetchRuntimeSupport, checker))
          .thenReturn(fetchConfig);
      mocked
          .when(
              () -> ClientGetPersistenceIO.readInitialMetadata(input, fetchRuntimeSupport, checker))
          .thenReturn(initialMetadata);

      ClientGetPersistenceCodec.BasicRestoreData restored =
          ClientGetPersistenceCodec.readBasicRestoreData(input, fetchRuntimeSupport, checker);

      assertEquals("KSK@codec-restore", restored.uri().toString());
      assertEquals(ClientGet.ReturnType.DISK, restored.returnType());
      assertEquals("target.bin", restored.targetFile().getPath());
      assertTrue(restored.binaryBlob());
      assertEquals(fetchConfig, restored.fetchConfig());
      assertEquals("txt", restored.extensionCheck());
      assertSame(initialMetadata, restored.initialMetadata());
    }
  }

  @Test
  void readBasicRestoreData_whenMagicIsInvalid_throwsStorageFormatException() throws IOException {
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
                      input, mock(FcpFetchRuntimeSupport.class), mock(ChecksumChecker.class)));

      assertEquals("Bad magic for request", error.getMessage());
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
  void restoreState_whenInProgress_returnsExecutionAndDelegatesRestore() throws Exception {
    ClientGet request = Mockito.spy(new ClientGet());
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    RequestIdentifier reqID =
        new RequestIdentifier(false, "client", "req-restore", RequestIdentifier.RequestType.GET);
    Bucket bucket = mock(Bucket.class);
    ClientGetExecution execution = mock(ClientGetExecution.class);
    //noinspection resource
    doReturn(bucket).when(request).makePersistenceBucket();
    doReturn(execution).when(request).makeExecutionForPersistence(fetchRuntimeSupport, bucket);

    try (DataInputStream input = input(new byte[0]);
        MockedStatic<ClientGetPersistenceIO> mocked =
            Mockito.mockStatic(ClientGetPersistenceIO.class)) {
      ClientGetExecution restored =
          ClientGetPersistenceCodec.restoreState(
              request, input, reqID, fetchRuntimeSupport, checker);

      assertSame(execution, restored);
      mocked.verify(
          () ->
              ClientGetPersistenceIO.restoreInProgressState(
                  any(DataInputStream.class),
                  eq(fetchRuntimeSupport),
                  eq(checker),
                  eq(execution),
                  eq(request)),
          times(1));
    }
  }

  @Test
  void restoreState_whenFinishedDirectAndBucketMissing_marksRequestUnfinished() throws Exception {
    ClientGet request = finishedDirectRequest();
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    RequestIdentifier reqID =
        new RequestIdentifier(
            false, "client", "req-finished-direct", RequestIdentifier.RequestType.GET);

    try (DataInputStream input = input(finishedPayload(transientPayload(55L, null)));
        MockedStatic<ClientGetGetterFactory> mockedGetterFactory =
            Mockito.mockStatic(ClientGetGetterFactory.class);
        MockedStatic<ClientGetPersistenceIO> mockedPersistenceIO =
            Mockito.mockStatic(ClientGetPersistenceIO.class)) {
      mockedGetterFactory
          .when(() -> ClientGetGetterFactory.readExpectedHashes(any(), any(), anyBoolean()))
          .thenReturn(null);
      mockedPersistenceIO
          .when(
              () ->
                  ClientGetPersistenceIO.restoreCompletedDirectBucketOrNull(
                      any(DataInputStream.class), eq(fetchRuntimeSupport), eq(checker)))
          .thenReturn(null);

      ClientGetExecution restored =
          ClientGetPersistenceCodec.restoreState(
              request, input, reqID, fetchRuntimeSupport, checker);

      assertNull(restored);
      assertFalse(isFinished(request));
      assertFalse(request.state().hasSucceeded());
      assertNull(request.state().getReturnBucketDirect());
    }
  }

  private static ClientGet finishedDirectRequest() throws Exception {
    ClientGet request = new ClientGet();
    setField(request, ClientRequest.class, "identifier", "req-finished-direct");
    setField(request, ClientRequest.class, "global", false);
    setField(request, ClientRequest.class, "finished", true);
    setField(request, ClientGet.class, "returnType", ClientGet.ReturnType.DIRECT);
    request.state().setSucceeded(true);
    return request;
  }

  private static DataInputStream input(byte[] payload) {
    return new DataInputStream(new ByteArrayInputStream(payload));
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
      out.writeBoolean(false);
    }
    return buffer.toByteArray();
  }

  private static byte[] transientPayload(long dataLength, String mimeType) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeLong(dataLength);
      out.writeBoolean(mimeType != null);
      if (mimeType != null) {
        out.writeUTF(mimeType);
      }
      new CompatibilityAnalyser().writeTo(out);
      out.writeInt(0);
    }
    return buffer.toByteArray();
  }

  private static byte[] finishedPayload(byte[] transientPayload) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeBoolean(true);
      out.write(transientPayload);
    }
    return buffer.toByteArray();
  }

  private static void setField(Object target, Class<?> owner, String fieldName, Object value)
      throws Exception {
    Field field = owner.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static boolean isFinished(ClientGet request) throws Exception {
    Field field = ClientRequest.class.getDeclaredField("finished");
    field.setAccessible(true);
    return field.getBoolean(request);
  }
}
