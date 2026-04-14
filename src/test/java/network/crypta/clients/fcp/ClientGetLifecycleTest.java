package network.crypta.clients.fcp;

import java.io.File;
import java.lang.reflect.Field;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ResumeFailedException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetLifecycleTest {

  @Test
  void onSuccess_whenDirectReturn_expectStateUpdatedAndNotifications() throws Exception {
    // Arrange
    ClientGet request = newSpyRequest(ReturnType.DIRECT, false);
    Bucket bucket = Mockito.mock(Bucket.class);
    when(bucket.size()).thenReturn(123L);
    FetchResult result = FetchResult.create(new ClientMetadata("text/plain"), bucket);
    ClientGetExecution execution = Mockito.mock(ClientGetExecution.class);
    PersistentRequestClient client = Mockito.mock(PersistentRequestClient.class);
    setField(request, "client", client);
    doNothing().when(request).trySendDataFoundOrGetFailed(null, null);
    doNothing().when(request).trySendAllDataMessage(null, null);
    doNothing().when(request).finish();
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    // Act
    lifecycle.onSuccess(result, execution);

    // Assert
    assertTrue(getBooleanField(request, "started"));
    assertTrue(getBooleanField(request, "finished"));
    assertTrue(request.state().hasSucceeded());
    assertEquals(123L, request.state().getFoundDataLength());
    assertEquals("text/plain", request.state().getFoundDataMimeType());
    assertEquals(bucket, request.state().getReturnBucketDirect());
    verify(request).trySendDataFoundOrGetFailed(null, null);
    verify(request).trySendAllDataMessage(null, null);
    verify(request).finish();
    verify(client).notifySuccess(request);
  }

  @Test
  void onSuccess_whenBinaryBlob_expectBlobMimeTypeAndBlobBucketSize() throws Exception {
    // Arrange
    ClientGet request = newSpyRequest(ReturnType.DIRECT, true);
    Bucket resultBucket = Mockito.mock(Bucket.class);
    Bucket blobBucket = Mockito.mock(Bucket.class);
    when(blobBucket.size()).thenReturn(50L);
    FetchResult result = FetchResult.create(new ClientMetadata("text/plain"), resultBucket);
    ClientGetExecution execution = Mockito.mock(ClientGetExecution.class);
    when(execution.blobBucket()).thenReturn(blobBucket);
    doNothing().when(request).trySendDataFoundOrGetFailed(null, null);
    doNothing().when(request).trySendAllDataMessage(null, null);
    doNothing().when(request).finish();
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    // Act
    lifecycle.onSuccess(result, execution);

    // Assert
    assertEquals(50L, request.state().getFoundDataLength());
    assertEquals(
        ClientGetGetterFactory.binaryBlobMimeType(), request.state().getFoundDataMimeType());
  }

  @Test
  void setSuccessForMigration_whenDirectMismatch_expectResumeFailedExceptionAndBucketStored()
      throws Exception {
    // Arrange
    ClientGet request = new ClientGet();
    Bucket bucket = Mockito.mock(Bucket.class);
    when(bucket.size()).thenReturn(7L);
    ClientGetTestProfiles.setReturnType(request, ReturnType.DIRECT);
    request.state().setFoundDataLength(5L);
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    // Act + Assert
    assertThrows(ResumeFailedException.class, () -> lifecycle.setSuccessForMigration(10L, bucket));
    assertEquals(bucket, request.state().getReturnBucketDirect());
  }

  @Test
  void setSuccessForMigration_whenChunked_expectResumeFailedException() throws Exception {
    // Arrange
    ClientGet request = new ClientGet();
    //noinspection resource
    Bucket bucket = Mockito.mock(Bucket.class);
    ClientGetTestProfiles.setReturnType(request, ReturnType.CHUNKED);
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    // Act + Assert
    assertThrows(ResumeFailedException.class, () -> lifecycle.setSuccessForMigration(10L, bucket));
  }

  @Test
  void onFailure_whenExpectedSizeAndMime_expectFailureRecordedAndNotified() throws Exception {
    // Arrange
    ClientGet request = newSpyRequest(ReturnType.NONE, false);
    PersistentRequestClient client = Mockito.mock(PersistentRequestClient.class);
    setField(request, "client", client);
    FetchException failure =
        new FetchException(FetchExceptionMode.INTERNAL_ERROR, 256L, true, "text/plain");
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    // Act
    lifecycle.onFailure(failure);

    // Assert
    assertTrue(getBooleanField(request, "finished"));
    assertTrue(getBooleanField(request, "started"));
    assertEquals(256L, request.state().getFoundDataLength());
    assertEquals("text/plain", request.state().getFoundDataMimeType());
    assertNotNull(request.state().getFailedMessage());
    verify(request).trySendDataFoundOrGetFailed(null, null);
    verify(request).finish();
    verify(client).notifyFailure(request);
  }

  @Test
  void requestWasRemoved_whenNotFinished_expectCancelledAndQueuedRemovalMessage() throws Exception {
    // Arrange
    ClientGet request = newSpyRequest(ReturnType.NONE, false);
    PersistentRequestClient client = Mockito.mock(PersistentRequestClient.class);
    setField(request, "client", client);
    setField(request, "persistence", Persistence.REBOOT);
    setField(request, "identifier", "req-7");
    setField(request, "global", true);
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    // Act
    lifecycle.requestWasRemoved();

    // Assert
    verify(request).trySendDataFoundOrGetFailed(null, null);
    verify(client).queueClientRequestMessage(any(PersistentRequestRemovedMessage.class), eq(0));
    verify(request).freeData();
    assertTrue(getBooleanField(request, "finished"));
  }

  private static ClientGet newSpyRequest(ReturnType returnType, boolean binaryBlob)
      throws Exception {
    ClientGet request = Mockito.spy(new ClientGet());
    ClientGetTestProfiles.setReturnType(request, returnType);
    ClientGetTestProfiles.setBinaryBlob(request, binaryBlob);
    setField(request, "identifier", "req-1");
    setField(request, "global", false);
    setField(request, "started", false);
    setField(request, "finished", false);
    request.state().setSucceeded(false);
    request.state().setFoundDataLength(-1L);
    ClientGetTestProfiles.setTargetFile(request, new File("target.bin"));
    return request;
  }

  private static boolean getBooleanField(Object target, String fieldName) throws Exception {
    Field field = findField(target, fieldName);
    return field.getBoolean(target);
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception {
    Field field = findField(target, fieldName);
    field.set(target, value);
  }

  private static Field findField(Object target, String fieldName) throws Exception {
    Field field = null;
    Class<?> type = target.getClass();
    while (type != null && field == null) {
      try {
        field = type.getDeclaredField(fieldName);
      } catch (NoSuchFieldException _) {
        type = type.getSuperclass();
      }
    }
    if (field == null) {
      throw new NoSuchFieldException(fieldName);
    }
    field.setAccessible(true);
    return field;
  }
}
