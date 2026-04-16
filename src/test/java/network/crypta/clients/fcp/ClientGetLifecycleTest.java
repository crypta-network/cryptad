package network.crypta.clients.fcp;

import java.io.File;
import java.lang.reflect.Field;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ResumeFailedException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetLifecycleTest {

  @Test
  void register_whenPersistentAndTagsEnabled_expectRegisterAndQueueTag() throws Exception {
    ClientGet request = newSpyRequest(ReturnType.DIRECT, false);
    PersistentRequestClient client = Mockito.mock(PersistentRequestClient.class);
    FCPMessage tagMessage = Mockito.mock(FCPMessage.class);
    setField(request, "client", client);
    setField(request, "persistence", Persistence.REBOOT);
    doReturn(tagMessage).when(request).persistentTagMessage();
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    lifecycle.register(false);

    verify(client).register(request);
    verify(client).queueClientRequestMessage(tagMessage, 0);
  }

  @Test
  void register_whenNoTags_expectRegisterWithoutQueueingTag() throws Exception {
    ClientGet request = newSpyRequest(ReturnType.DIRECT, false);
    PersistentRequestClient client = Mockito.mock(PersistentRequestClient.class);
    setField(request, "client", client);
    setField(request, "persistence", Persistence.REBOOT);
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    lifecycle.register(true);

    verify(client).register(request);
    verify(client, never()).queueClientRequestMessage(any(FCPMessage.class), eq(0));
  }

  @Test
  void register_whenConnectionPersistence_expectNoRegistration() throws Exception {
    ClientGet request = newSpyRequest(ReturnType.DIRECT, false);
    PersistentRequestClient client = Mockito.mock(PersistentRequestClient.class);
    setField(request, "client", client);
    setField(request, "persistence", Persistence.CONNECTION);
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    lifecycle.register(false);

    verify(client, never()).register(any(ClientRequest.class));
    verify(client, never()).queueClientRequestMessage(any(FCPMessage.class), eq(0));
  }

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
  void setSuccessForMigration_whenDirectMismatch_expectResumeFailedExceptionAndBucketStored() {
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
  void setSuccessForMigration_whenChunked_expectResumeFailedException() {
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
  void start_whenExecutionSucceeds_expectStartedCacheUpdateAndPersistentTag() throws Exception {
    ClientGet request = newSpyRequest(ReturnType.NONE, false);
    ClientGetExecution execution = Mockito.mock(ClientGetExecution.class);
    PersistentRequestClient client = Mockito.mock(PersistentRequestClient.class);
    RequestStatusCache cache = Mockito.mock(RequestStatusCache.class);
    FCPMessage tagMessage = Mockito.mock(FCPMessage.class);
    request.setExecution(execution);
    setField(request, "client", client);
    setField(request, "persistence", Persistence.REBOOT);
    when(client.getRequestStatusCache()).thenReturn(cache);
    doReturn(tagMessage).when(request).persistentTagMessage();
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    lifecycle.start();

    verify(execution).start();
    verify(client).queueClientRequestMessage(tagMessage, 0);
    verify(cache).updateStarted("req-1", true);
    assertTrue(getBooleanField(request, "started"));
  }

  @Test
  void start_whenExecutionThrowsFetchException_expectStartedAndFailureDelegation()
      throws Exception {
    ClientGet request = newSpyRequest(ReturnType.NONE, false);
    ClientGetExecution execution = Mockito.mock(ClientGetExecution.class);
    FetchException failure = new FetchException(FetchExceptionMode.INTERNAL_ERROR, "boom");
    request.setExecution(execution);
    doThrow(failure).when(execution).start();
    doNothing().when(request).onFailure(failure);
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    lifecycle.start();

    verify(request).onFailure(failure);
    assertTrue(getBooleanField(request, "started"));
  }

  @Test
  void start_whenExecutionThrowsRuntimeException_expectInternalErrorFailure() throws Exception {
    ClientGet request = newSpyRequest(ReturnType.NONE, false);
    ClientGetExecution execution = Mockito.mock(ClientGetExecution.class);
    RuntimeException failure = new RuntimeException("boom");
    request.setExecution(execution);
    doThrow(failure).when(execution).start();
    doNothing().when(request).onFailure(any(FetchException.class));
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    lifecycle.start();

    ArgumentCaptor<FetchException> captor = ArgumentCaptor.forClass(FetchException.class);
    verify(request).onFailure(captor.capture());
    assertEquals(FetchExceptionMode.INTERNAL_ERROR, captor.getValue().getMode());
    assertSame(failure, captor.getValue().getCause());
    assertTrue(getBooleanField(request, "started"));
  }

  @Test
  void onLostConnection_whenConnectionPersistence_expectCancel() throws Exception {
    ClientGet request = newSpyRequest(ReturnType.NONE, false);
    PersistentRequestRuntimeContext context = Mockito.mock(PersistentRequestRuntimeContext.class);
    setField(request, "persistence", Persistence.CONNECTION);
    doNothing().when(request).cancel(context);
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    lifecycle.onLostConnection(context);

    verify(request).cancel(context);
  }

  @Test
  void onLostConnection_whenPersistent_expectNoCancellation() throws Exception {
    ClientGet request = newSpyRequest(ReturnType.NONE, false);
    PersistentRequestRuntimeContext context = Mockito.mock(PersistentRequestRuntimeContext.class);
    setField(request, "persistence", Persistence.REBOOT);
    ClientGetLifecycle lifecycle = new ClientGetLifecycle(request);

    lifecycle.onLostConnection(context);

    verify(request, never()).cancel(any(PersistentRequestRuntimeContext.class));
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
