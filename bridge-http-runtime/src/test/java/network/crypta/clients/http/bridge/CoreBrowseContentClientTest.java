package network.crypta.clients.http.bridge;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100")
class CoreBrowseContentClientTest {

  @Test
  void constructor_whenClientIsNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new CoreBrowseContentClient(null));
  }

  @Test
  void prefetch_whenAllowedMimeTypesIsNull_delegatesWithNullAllowlist() {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    CoreBrowseContentClient browseContentClient = new CoreBrowseContentClient(client);
    FreenetURI uri = mock(FreenetURI.class);

    browseContentClient.prefetch(uri, 1_500L, 4_096L, null);

    verify(client).prefetch(uri, 1_500L, 4_096L, null);
  }
}
