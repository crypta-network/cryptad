package network.crypta.clients.http;

import java.net.URI;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ContentToadletTest {

  @Test
  void constructor_whenClientNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new TestContentToadlet(null));
  }

  @Test
  void getFetchContext_whenInvoked_delegatesToClient() {
    BrowseContentClient client = mock(BrowseContentClient.class);
    FetchContext expectedContext = mock(FetchContext.class);
    when(client.getFetchContext(2048L, "http://127.0.0.1:8888")).thenReturn(expectedContext);
    TestContentToadlet toadlet = new TestContentToadlet(client);

    FetchContext actualContext = toadlet.fetchContext();

    assertSame(expectedContext, actualContext);
  }

  @Test
  void fetch_whenMaxSizePositive_updatesContextAndReturnsCompletedResult() throws Exception {
    BrowseContentClient client = mock(BrowseContentClient.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RequestClient requestClient = mock(RequestClient.class);
    FreenetURI uri = new FreenetURI("KSK", "content-toadlet-fetch");
    FetchResult expectedResult =
        FetchResult.create(mock(ClientMetadata.class), mock(RandomAccessBucket.class));
    when(client.fetch(eq(uri), same(requestClient), same(fetchContext))).thenReturn(expectedResult);
    TestContentToadlet toadlet = new TestContentToadlet(client);

    FetchResult actualResult = toadlet.fetch(uri, 2048L, requestClient, fetchContext);

    assertSame(expectedResult, actualResult);
    verify(fetchContext).setMaxOutputLength(2048L);
    verify(fetchContext).setMaxTempLength(2048L);
  }

  @Test
  void insert_whenDesiredUriPresent_delegatesToClient() throws Exception {
    BrowseContentClient client = mock(BrowseContentClient.class);
    TestContentToadlet toadlet = new TestContentToadlet(client);
    InsertBlock insertBlock =
        new InsertBlock(mock(RandomAccessBucket.class), null, new FreenetURI("KSK", "insert-src"));
    FreenetURI insertedUri = new FreenetURI("KSK", "insert-result");
    when(client.insert(insertBlock, false, "result.txt")).thenReturn(insertedUri);

    FreenetURI actualUri = toadlet.insert(insertBlock, "result.txt");

    assertSame(insertedUri, actualUri);
    verify(client).insert(insertBlock, false, "result.txt");
  }

  private static final class TestContentToadlet extends ContentToadlet {
    private TestContentToadlet(BrowseContentClient client) {
      super(client);
    }

    @Override
    public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx) {
      throw new UnsupportedOperationException();
    }

    @Override
    public String path() {
      return "/content-toadlet-test/";
    }

    private FetchContext fetchContext() {
      return getFetchContext(2048L, "http://127.0.0.1:8888");
    }
  }
}
