package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.client.FetchException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientGetPersistenceIOTest {

  @Test
  void openChecksummed_whenRuntimeSupportProvidesStream_readsPayload()
      throws IOException, StorageFormatException {
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ByteArrayOutputStream payloadBuffer = new ByteArrayOutputStream();
    try (DataOutputStream payloadOut = new DataOutputStream(payloadBuffer)) {
      payloadOut.writeInt(42);
    }
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(fetchRuntimeSupport.openChecksummed(input, checker, 65536L))
        .thenReturn(new DataInputStream(new ByteArrayInputStream(payloadBuffer.toByteArray())));

    DataInputStream result =
        ClientGetPersistenceIO.openChecksummed(input, fetchRuntimeSupport, checker, 65536L);

    assertEquals(42, result.readInt());
    verify(fetchRuntimeSupport).openChecksummed(input, checker, 65536L);
  }

  @Test
  void readFetchConfigOrDefault_whenValidData_returnsRestoredConfig()
      throws IOException, StorageFormatException {
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ClientGetFetchConfig expected = new ClientGetFetchConfig();
    expected.setFilterData(true);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));
    DataInputStream inner = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(fetchRuntimeSupport.openChecksummed(input, checker, 65536L)).thenReturn(inner);
    when(fetchRuntimeSupport.decodeFetchConfig(inner)).thenReturn(expected);

    ClientGetFetchConfig restored =
        ClientGetPersistenceIO.readFetchConfigOrDefault(input, fetchRuntimeSupport, checker);

    assertEquals(expected, restored);
  }

  @Test
  void readFetchConfigOrDefault_whenChecksumFails_returnsDefault()
      throws IOException, StorageFormatException {
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ClientGetFetchConfig fallback = new ClientGetFetchConfig();
    fallback.setIgnoreStore(true);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(fetchRuntimeSupport.openChecksummed(input, checker, 65536L))
        .thenThrow(storageFormatExceptionWithChecksumFailure());
    when(fetchRuntimeSupport.defaultPersistentFetchConfig()).thenReturn(fallback);

    ClientGetFetchConfig restored =
        ClientGetPersistenceIO.readFetchConfigOrDefault(input, fetchRuntimeSupport, checker);

    assertEquals(fallback, restored);
  }

  @Test
  void readInitialMetadata_whenMarkerFalse_returnsNull()
      throws IOException, StorageFormatException, ResumeFailedException {
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ByteArrayOutputStream data = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(data)) {
      out.writeBoolean(false);
    }
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(data.toByteArray()));

    Bucket result = ClientGetPersistenceIO.readInitialMetadata(input, fetchRuntimeSupport, checker);

    assertNull(result);
    verifyNoInteractions(fetchRuntimeSupport, checker);
  }

  @Test
  void readInitialMetadata_whenRestoreSucceeds_returnsBucket()
      throws IOException, StorageFormatException, ResumeFailedException {
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    Bucket expected = mock(Bucket.class);
    ByteArrayOutputStream data = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(data)) {
      out.writeBoolean(true);
    }
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(data.toByteArray()));
    DataInputStream inner = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(fetchRuntimeSupport.openChecksummed(input, checker, 65536L)).thenReturn(inner);
    when(fetchRuntimeSupport.restorePersistentBucket(inner)).thenReturn(expected);

    Bucket restored =
        ClientGetPersistenceIO.readInitialMetadata(input, fetchRuntimeSupport, checker);

    assertEquals(expected, restored);
  }

  @Test
  void restoreCompletedDirectBucketOrNull_whenChecksumFails_returnsNull()
      throws ResumeFailedException, IOException, StorageFormatException {
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(fetchRuntimeSupport.openChecksummed(input, checker, 65536L))
        .thenThrow(storageFormatExceptionWithChecksumFailure());

    Bucket restored =
        ClientGetPersistenceIO.restoreCompletedDirectBucketOrNull(
            input, fetchRuntimeSupport, checker);

    assertNull(restored);
  }

  @Test
  void restoreFailureMessageOrNull_whenValidMessage_returnsMessage()
      throws IOException, StorageFormatException {
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    RequestIdentifier reqID =
        new RequestIdentifier(true, null, "req-1", RequestIdentifier.RequestType.GET);
    byte[] payload =
        serializeFailureMessage(
            new GetFailedMessage(
                new FetchException(FetchException.FetchExceptionMode.DATA_NOT_FOUND, "missing"),
                reqID.identifier,
                reqID.globalQueue));
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));
    DataInputStream inner = new DataInputStream(new ByteArrayInputStream(payload));

    when(fetchRuntimeSupport.openChecksummed(input, checker, 65536L)).thenReturn(inner);

    GetFailedMessage restored =
        ClientGetPersistenceIO.restoreFailureMessageOrNull(
            input, reqID, 123L, "text/plain", fetchRuntimeSupport, checker);

    assertNotNull(restored);
    assertEquals(FetchException.FetchExceptionMode.DATA_NOT_FOUND, restored.failureMode);
    assertEquals(reqID.identifier, restored.requestIdentifier);
    assertEquals(reqID.globalQueue, restored.global);
  }

  @Test
  void restoreInProgressState_whenResumeReturnsTrue_readsTransientFields()
      throws IOException, StorageFormatException {
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ClientGetExecution execution = mock(ClientGetExecution.class);
    ClientGet request = newRequestWithState();
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));
    byte[] payload = serializeTransientProgress();
    DataInputStream inner = new DataInputStream(new ByteArrayInputStream(payload));

    when(fetchRuntimeSupport.openChecksummed(input, checker, 65536L)).thenReturn(inner);
    when(execution.resumeFromTrivialProgress(any(DataInputStream.class))).thenReturn(true);

    ClientGetPersistenceIO.restoreInProgressState(
        input, fetchRuntimeSupport, checker, execution, request);

    verify(execution).resumeFromTrivialProgress(any(DataInputStream.class));
    assertEquals(42L, request.state().getFoundDataLength());
    assertEquals("text/plain", request.state().getFoundDataMimeType());
  }

  @Test
  void restoreInProgressState_whenChecksumFails_skipsResume()
      throws IOException, StorageFormatException {
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ClientGetExecution execution = mock(ClientGetExecution.class);
    ClientGet request = mock(ClientGet.class);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(fetchRuntimeSupport.openChecksummed(input, checker, 65536L))
        .thenThrow(storageFormatExceptionWithChecksumFailure());

    ClientGetPersistenceIO.restoreInProgressState(
        input, fetchRuntimeSupport, checker, execution, request);

    verifyNoInteractions(execution, request);
  }

  private static StorageFormatException storageFormatExceptionWithChecksumFailure() {
    StorageFormatException exception = new StorageFormatException("Checksum failed");
    exception.initCause(new ChecksumFailedException());
    return exception;
  }

  private static ClientGet newRequestWithState() {
    ClientGet request = new ClientGet();
    request.state().setCompatibilityAnalyser(new FcpCompatibilityAnalysis());
    return request;
  }

  private static byte[] serializeFailureMessage(GetFailedMessage message) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(output)) {
      message.writeTo(dos);
    }
    return output.toByteArray();
  }

  private static byte[] serializeTransientProgress() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(output)) {
      dos.writeLong(42L);
      dos.writeBoolean(true);
      dos.writeUTF("text/plain");
      new FcpCompatibilityAnalysis().writeTo(dos);
      dos.writeInt(0);
    }
    return output.toByteArray();
  }
}
