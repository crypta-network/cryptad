package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.async.BaseClientPutter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NullClientCallbackTest {

  @Mock private RequestClient requestClient;

  @Mock private Bucket bucket;

  @Mock private Bucket metadataBucket;

  @Mock private ClientGetter clientGetter;

  @Mock private BaseClientPutter baseClientPutter;

  @Mock private ClientContext clientContext;

  @Test
  void getRequestClient_whenConstructed_expectSameInstanceReturned() {
    // Arrange
    NullClientCallback callback = new NullClientCallback(requestClient);

    // Act
    RequestClient result = callback.getRequestClient();

    // Assert
    assertSame(requestClient, result);
  }

  @Test
  void onSuccess_whenFetchResultProvided_expectBucketFreed() {
    // Arrange
    NullClientCallback callback = new NullClientCallback(requestClient);
    ClientMetadata metadata = new ClientMetadata("text/plain");
    FetchResult fetchResult = new FetchResult(metadata, bucket);

    // Act
    callback.onSuccess(fetchResult, clientGetter);

    // Assert
    verify(bucket).free();
  }

  @Test
  void onSuccess_whenBucketFreeThrowsRuntimeException_expectExceptionPropagated() {
    // Arrange
    NullClientCallback callback = new NullClientCallback(requestClient);
    ClientMetadata metadata = new ClientMetadata("text/plain");
    FetchResult fetchResult = new FetchResult(metadata, bucket);
    RuntimeException failure = new RuntimeException("free failed");
    doThrow(failure).when(bucket).free();

    // Act & Assert
    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> callback.onSuccess(fetchResult, clientGetter));
    assertSame(failure, thrown);
  }

  @Test
  void onGeneratedMetadata_whenBucketProvided_expectMetadataBucketFreed() {
    // Arrange
    NullClientCallback callback = new NullClientCallback(requestClient);

    // Act
    callback.onGeneratedMetadata(metadataBucket, baseClientPutter);

    // Assert
    verify(metadataBucket).free();
  }

  @Test
  void onGeneratedMetadata_whenFreeThrowsRuntimeException_expectExceptionPropagated() {
    // Arrange
    NullClientCallback callback = new NullClientCallback(requestClient);
    RuntimeException failure = new RuntimeException("free failed");
    doThrow(failure).when(metadataBucket).free();

    // Act & Assert
    RuntimeException thrown =
        assertThrows(
            RuntimeException.class,
            () -> callback.onGeneratedMetadata(metadataBucket, baseClientPutter));
    assertSame(failure, thrown);
  }

  @Test
  void onFailureFetch_whenCalled_expectNoException() {
    // Arrange
    NullClientCallback callback = new NullClientCallback(requestClient);
    FetchException exception = new FetchException(FetchExceptionMode.INTERNAL_ERROR);

    // Act & Assert
    assertDoesNotThrow(() -> callback.onFailure(exception));
  }

  @Test
  void onFailureInsert_whenCalled_expectNoException() {
    // Arrange
    NullClientCallback callback = new NullClientCallback(requestClient);
    InsertException exception = new InsertException(InsertExceptionMode.INTERNAL_ERROR);

    // Act & Assert
    assertDoesNotThrow(() -> callback.onFailure(exception, baseClientPutter));
  }

  @Test
  void onFetchable_whenCalled_expectNoException() {
    // Arrange
    NullClientCallback callback = new NullClientCallback(requestClient);

    // Act & Assert
    assertDoesNotThrow(() -> callback.onFetchable(baseClientPutter));
  }

  @Test
  void onGeneratedURI_whenCalled_expectNoException() {
    // Arrange
    NullClientCallback callback = new NullClientCallback(requestClient);
    FreenetURI uri = new FreenetURI("CHK", null);

    // Act & Assert
    assertDoesNotThrow(() -> callback.onGeneratedURI(uri, baseClientPutter));
  }

  @Test
  void onSuccessPutter_whenCalled_expectNoException() {
    // Arrange
    NullClientCallback callback = new NullClientCallback(requestClient);

    // Act & Assert
    assertDoesNotThrow(() -> callback.onSuccess(baseClientPutter));
  }

  @Test
  void onResume_whenCalled_expectNoException() {
    // Arrange
    NullClientCallback callback = new NullClientCallback(requestClient);

    // Act & Assert
    assertDoesNotThrow(() -> callback.onResume(clientContext));
  }
}
