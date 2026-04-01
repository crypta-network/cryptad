package network.crypta.clients.fcp.bridge;

import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.async.ClientContext;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.keys.FreenetURI;
import network.crypta.runtime.endpoints.fcp.FcpEndpointHandle;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class FcpEndpointHandlesTest {

  @Test
  void wrap_whenServerProvided_delegatesToWrappedServer() {
    // Arrange
    FCPServer server = mock(FCPServer.class);
    FcpEndpointHandle handle = FcpEndpointHandles.wrap(server);
    FreenetURI key = mock(FreenetURI.class);
    ClientContext context = mock(ClientContext.class);
    Bucket preferred = mock(Bucket.class);
    CacheFetchResult instantResult = mock(CacheFetchResult.class);
    CacheFetchResult lookupResult = mock(CacheFetchResult.class);
    when(server.lookupInstant(key, true, false, preferred)).thenReturn(instantResult);
    when(server.lookup(key, false, context, true, preferred)).thenReturn(lookupResult);

    // Act
    handle.load();
    handle.maybeStart();
    CacheFetchResult actualInstant = handle.lookupInstant(key, true, false, preferred);
    CacheFetchResult actualLookup = handle.lookup(key, false, context, true, preferred);

    // Assert
    assertSame(server, FcpEndpointHandles.unwrap(handle));
    assertSame(server, FcpEndpointHandles.serverOrNull(handle));
    assertSame(server, FcpEndpointHandles.requireServer(handle));
    assertSame(instantResult, actualInstant);
    assertSame(lookupResult, actualLookup);
    verify(server).load();
    verify(server).maybeStart();
    verify(server).lookupInstant(key, true, false, preferred);
    verify(server).lookup(key, false, context, true, preferred);
  }

  @Test
  void serverOrNull_whenHandleMissing_returnsNull() {
    // Act + Assert
    assertNull(FcpEndpointHandles.serverOrNull(null));
  }

  @Test
  void requireServer_whenHandleMissing_throwsIllegalStateException() {
    // Act
    IllegalStateException thrown =
        assertThrows(IllegalStateException.class, () -> FcpEndpointHandles.requireServer(null));

    // Assert
    assertTrue(thrown.getMessage().contains("FCP server unavailable"));
  }

  @Test
  void unwrap_whenHandleNotCreatedByBridge_throwsIllegalArgumentException() {
    // Arrange
    FcpEndpointHandle unsupportedHandle = new UnsupportedEndpointHandle();

    // Act
    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class, () -> FcpEndpointHandles.unwrap(unsupportedHandle));

    // Assert
    assertTrue(thrown.getMessage().contains(UnsupportedEndpointHandle.class.getName()));
  }

  private static final class UnsupportedEndpointHandle implements FcpEndpointHandle {

    @Override
    public void load() {
      // No-op: test double exists only to hit the unsupported unwrapping path.
    }

    @Override
    public void maybeStart() {
      // No-op: test double exists only to hit the unsupported unwrapping path.
    }

    @Override
    public CacheFetchResult lookupInstant(
        FreenetURI key, boolean noFilter, boolean mustCopy, Bucket preferred) {
      return null;
    }

    @Override
    public CacheFetchResult lookup(
        FreenetURI key,
        boolean noFilter,
        ClientContext context,
        boolean mustCopy,
        Bucket preferred) {
      return null;
    }
  }
}
