package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class FcpPeerLookupResultTest {

  private static final FcpDarknetPeerHandle DARKNET_PEER_HANDLE =
      new FcpDarknetPeerHandle() {
        @Override
        public int sendTextFeed(String message) {
          return 0;
        }

        @Override
        public int sendDownloadFeed(FreenetURI uri, String description) {
          return 0;
        }

        @Override
        public int sendBookmarkFeed(
            FreenetURI uri, String name, String description, boolean hasActiveLink) {
          return 0;
        }
      };

  @Test
  void unknown_whenCalled_returnsSharedUnknownSingleton() {
    FcpPeerLookupResult first = FcpPeerLookupResult.unknown();
    FcpPeerLookupResult second = FcpPeerLookupResult.unknown();

    assertSame(first, second);
    assertEquals(FcpPeerLookupResult.Kind.UNKNOWN, first.kind());
    assertTrue(first.isUnknown());
    assertFalse(first.isNonDarknet());
    assertFalse(first.isDarknet());
  }

  @Test
  void unknown_whenDarknetHandleRequired_throwsIllegalStateException() {
    FcpPeerLookupResult result = FcpPeerLookupResult.unknown();

    IllegalStateException exception =
        assertThrows(IllegalStateException.class, result::requireDarknetPeerHandle);

    assertEquals("Lookup result does not contain a darknet peer handle", exception.getMessage());
  }

  @Test
  void nonDarknet_whenCalled_returnsSharedNonDarknetSingleton() {
    FcpPeerLookupResult first = FcpPeerLookupResult.nonDarknet();
    FcpPeerLookupResult second = FcpPeerLookupResult.nonDarknet();

    assertSame(first, second);
    assertEquals(FcpPeerLookupResult.Kind.NON_DARKNET, first.kind());
    assertFalse(first.isUnknown());
    assertTrue(first.isNonDarknet());
    assertFalse(first.isDarknet());
  }

  @Test
  void nonDarknet_whenDarknetHandleRequired_throwsIllegalStateException() {
    FcpPeerLookupResult result = FcpPeerLookupResult.nonDarknet();

    IllegalStateException exception =
        assertThrows(IllegalStateException.class, result::requireDarknetPeerHandle);

    assertEquals("Lookup result does not contain a darknet peer handle", exception.getMessage());
  }

  @Test
  void darknet_whenHandleProvided_returnsDarknetResultWithHandle() {
    FcpPeerLookupResult result = FcpPeerLookupResult.darknet(DARKNET_PEER_HANDLE);

    assertEquals(FcpPeerLookupResult.Kind.DARKNET, result.kind());
    assertFalse(result.isUnknown());
    assertFalse(result.isNonDarknet());
    assertTrue(result.isDarknet());
    assertSame(DARKNET_PEER_HANDLE, result.requireDarknetPeerHandle());
  }

  @Test
  void darknet_whenHandleNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> FcpPeerLookupResult.darknet(null));
  }
}
