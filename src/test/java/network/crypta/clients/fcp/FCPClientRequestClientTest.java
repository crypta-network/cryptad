package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FCPClientRequestClientTest {

  @Mock private PersistentRequestClient persistentRequestClient;

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void persistent_whenForeverSet_returnsMatchingValue(boolean forever) {
    FCPClientRequestClient requestClient =
        new FCPClientRequestClient(persistentRequestClient, forever, false);

    assertEquals(forever, requestClient.persistent());
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void realTimeFlag_whenRealTimeFlagSet_returnsMatchingValue(boolean realTimeFlag) {
    FCPClientRequestClient requestClient =
        new FCPClientRequestClient(persistentRequestClient, false, realTimeFlag);

    assertEquals(realTimeFlag, requestClient.realTimeFlag());
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void constructor_whenCalled_preservesClientReference(boolean forever) {
    FCPClientRequestClient requestClient =
        new FCPClientRequestClient(persistentRequestClient, forever, true);

    assertSame(persistentRequestClient, requestClient.client);
  }
}
