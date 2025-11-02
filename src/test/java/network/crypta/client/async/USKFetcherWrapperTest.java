package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.RequestClient;
import network.crypta.support.compress.Compressor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKFetcherWrapperTest {

  @Mock private RequestClient requestClient;

  @Mock private ClientContext clientContext;

  @Test
  void getURI_whenDelegates_returnsUSKURI() {
    // Arrange
    USK usk = Mockito.mock(USK.class);
    FreenetURI uri = new FreenetURI("USK", "mysite", null, null, null, null, 42L);
    Mockito.when(usk.getURI()).thenReturn(uri);
    Mockito.when(requestClient.persistent()).thenReturn(false);
    Mockito.when(requestClient.realTimeFlag()).thenReturn(false);
    USKFetcherWrapper wrapper = new USKFetcherWrapper(usk, (short) 5, requestClient);

    // Act
    FreenetURI result = wrapper.getURI();

    // Assert
    assertNotNull(result);
    assertEquals(uri, result);
  }

  @Test
  void isFinished_whenCalled_returnsFalse() {
    // Arrange
    USK usk = Mockito.mock(USK.class);
    Mockito.when(requestClient.persistent()).thenReturn(false);
    Mockito.when(requestClient.realTimeFlag()).thenReturn(false);
    USKFetcherWrapper wrapper = new USKFetcherWrapper(usk, (short) 1, requestClient);

    // Act / Assert
    assertFalse(wrapper.isFinished());
  }

  @Test
  void cancel_whenCalled_setsCancelledTrue() {
    // Arrange
    USK usk = Mockito.mock(USK.class);
    Mockito.when(requestClient.persistent()).thenReturn(false);
    Mockito.when(requestClient.realTimeFlag()).thenReturn(false);
    USKFetcherWrapper wrapper = new USKFetcherWrapper(usk, (short) 1, requestClient);
    assertFalse(wrapper.isCancelled());

    // Act
    wrapper.cancel(clientContext);

    // Assert
    assertTrue(wrapper.isCancelled());
  }

  @Test
  void toString_whenCalled_containsClassAndUSK() {
    // Arrange
    USK usk = Mockito.mock(USK.class);
    Mockito.when(usk.toString()).thenReturn("USK:mysite/42");
    Mockito.when(requestClient.persistent()).thenReturn(false);
    Mockito.when(requestClient.realTimeFlag()).thenReturn(false);
    USKFetcherWrapper wrapper = new USKFetcherWrapper(usk, (short) 7, requestClient);

    // Act
    String s = wrapper.toString();

    // Assert
    assertNotNull(s);
    assertTrue(s.startsWith(USKFetcherWrapper.class.getName() + "@"));
    assertTrue(s.endsWith(":" + usk));
  }

  @Test
  void getURI_whenUSKIsNull_throwsNPE() {
    // Arrange
    Mockito.when(requestClient.persistent()).thenReturn(false);
    Mockito.when(requestClient.realTimeFlag()).thenReturn(false);
    USKFetcherWrapper wrapper = new USKFetcherWrapper(null, (short) 0, requestClient);

    // Act / Assert
    assertThrows(NullPointerException.class, wrapper::getURI);
  }

  @Test
  void lifecycleCallbacks_whenInvoked_areNoOps() {
    // Arrange
    USK usk = Mockito.mock(USK.class);
    Mockito.when(requestClient.persistent()).thenReturn(false);
    Mockito.when(requestClient.realTimeFlag()).thenReturn(false);
    USKFetcherWrapper wrapper = new USKFetcherWrapper(usk, (short) 3, requestClient);

    ClientMetadata meta = Mockito.mock(ClientMetadata.class);
    ClientGetState state = Mockito.mock(ClientGetState.class);
    @SuppressWarnings({"unchecked", "RedundantCast"})
    List<Compressor> decompressors = (List<Compressor>) (List<?>) List.of();
    FetchException fetchEx = Mockito.mock(FetchException.class);
    HashResult[] hashes = new HashResult[0];

    // Act + Assert (no exceptions thrown)
    assertDoesNotThrow(
        () ->
            wrapper.onSuccess(
                Mockito.mock(StreamGenerator.class), meta, decompressors, state, clientContext));
    assertDoesNotThrow(() -> wrapper.onFailure(fetchEx, state, clientContext));
    assertDoesNotThrow(() -> wrapper.onBlockSetFinished(state, clientContext));
    assertDoesNotThrow(() -> wrapper.onTransition(state, state, clientContext));
    assertDoesNotThrow(() -> wrapper.onExpectedMIME(meta, clientContext));
    assertDoesNotThrow(() -> wrapper.onExpectedSize(123L, clientContext));
    assertDoesNotThrow(wrapper::onFinalizedMetadata);
    assertDoesNotThrow(() -> wrapper.onExpectedTopSize(10L, 8L, 1, 1, clientContext));
    assertDoesNotThrow(
        () ->
            wrapper.onSplitfileCompatibilityMode(
                CompatibilityMode.COMPAT_1250,
                CompatibilityMode.COMPAT_1468,
                new byte[0],
                true,
                false,
                false,
                clientContext));
    assertDoesNotThrow(() -> wrapper.onHashes(hashes, clientContext));
  }

  @Test
  void toNetwork_whenCalledTwice_isIdempotentAndNoop() {
    // Arrange
    USK usk = Mockito.mock(USK.class);
    Mockito.when(requestClient.persistent()).thenReturn(false);
    Mockito.when(requestClient.realTimeFlag()).thenReturn(false);
    USKFetcherWrapper wrapper = new USKFetcherWrapper(usk, (short) 2, requestClient);

    // Act + Assert
    assertDoesNotThrow(() -> wrapper.toNetwork(clientContext));
    assertDoesNotThrow(() -> wrapper.toNetwork(clientContext)); // idempotent
  }

  @Test
  void onResume_whenCallbackMissing_throwsNullPointerException() {
    // Arrange
    USK usk = Mockito.mock(USK.class);
    Mockito.when(requestClient.persistent()).thenReturn(false);
    Mockito.when(requestClient.realTimeFlag()).thenReturn(false);
    USKFetcherWrapper wrapper = new USKFetcherWrapper(usk, (short) 9, requestClient);

    // Act / Assert: getCallback() is null → NPE inside super.innerOnResume()
    assertThrows(NullPointerException.class, () -> wrapper.onResume(clientContext));
  }
}
