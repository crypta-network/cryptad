package network.crypta.runtime.spi;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class BoundedContentFetchResultTest {
  @Test
  void constructor_whenBytesMutatedAfterConstruction_expectStoredCopyUnaffected() {
    byte[] bytes = {1, 2, 3};
    BoundedContentFetchResult result =
        new BoundedContentFetchResult(bytes, "CHK@requested", "CHK@resolved", "ok");

    bytes[0] = 9;

    assertArrayEquals(new byte[] {1, 2, 3}, result.bytes());
  }

  @Test
  void bytes_whenReturnedArrayMutated_expectStoredCopyUnaffected() {
    BoundedContentFetchResult result =
        new BoundedContentFetchResult(new byte[] {4, 5, 6}, "CHK@requested", null, null);

    byte[] firstRead = result.bytes();
    firstRead[0] = 9;

    assertArrayEquals(new byte[] {4, 5, 6}, result.bytes());
  }

  @Test
  void constructor_whenOptionalValuesAreNull_expectAccepted() {
    BoundedContentFetchResult result =
        new BoundedContentFetchResult(new byte[] {7}, "CHK@requested", null, null);

    assertEquals("CHK@requested", result.requestedUri());
    assertNull(result.resolvedUri());
    assertNull(result.statusMessage());
  }

  @Test
  void constructor_whenRequestedUriIsBlank_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new BoundedContentFetchResult(new byte[] {1}, " ", null, null));
  }

  @Test
  void constructor_whenResolvedUriIsMultiline_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new BoundedContentFetchResult(new byte[] {1}, "CHK@requested", "CHK@x\n", null));
  }

  @Test
  void constructor_whenStatusMessageIsBlank_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new BoundedContentFetchResult(new byte[] {1}, "CHK@requested", null, " "));
  }

  @Test
  void constructor_whenStatusMessageIsMultiline_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new BoundedContentFetchResult(new byte[] {1}, "CHK@requested", null, "ok\nbad"));
  }
}
