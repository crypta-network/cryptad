package network.crypta.runtime.spi;

import java.time.Duration;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class BoundedContentFetchRequestTest {
  private static final String VALID_URI = "CHK@example";
  private static final long VALID_MAX_BYTES = 1L;
  private static final Duration VALID_TIMEOUT = Duration.ofSeconds(1);
  private static final String VALID_PURPOSE = "catalog";

  @Test
  void constructor_whenValuesAreValid_expectFieldsPreserved() {
    Duration timeout = Duration.ofSeconds(5);

    BoundedContentFetchRequest request =
        new BoundedContentFetchRequest(VALID_URI, 4096L, timeout, "catalog refresh");

    assertEquals(VALID_URI, request.uri());
    assertEquals(4096L, request.maxBytes());
    assertEquals(timeout, request.timeout());
    assertEquals("catalog refresh", request.purpose());
  }

  @Test
  void constructor_whenUriIsBlank_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new BoundedContentFetchRequest(" ", VALID_MAX_BYTES, VALID_TIMEOUT, VALID_PURPOSE));
  }

  @Test
  void constructor_whenPurposeIsMultiline_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new BoundedContentFetchRequest(VALID_URI, VALID_MAX_BYTES, VALID_TIMEOUT, "cat\nalog"));
  }

  @Test
  void constructor_whenMaxBytesIsNotPositive_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new BoundedContentFetchRequest(VALID_URI, 0L, VALID_TIMEOUT, VALID_PURPOSE));
  }

  @Test
  void constructor_whenTimeoutIsNotPositive_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new BoundedContentFetchRequest(
                VALID_URI, VALID_MAX_BYTES, Duration.ZERO, VALID_PURPOSE));
  }

  @Test
  void toString_whenUriAndPurposeContainSensitiveText_expectValuesRedacted() {
    BoundedContentFetchRequest request =
        new BoundedContentFetchRequest(
            "CHK@example/private/path", 4096L, Duration.ofSeconds(5), "preview-token-value");

    String text = request.toString();

    assertFalse(text.contains("CHK@example"));
    assertFalse(text.contains("private/path"));
    assertFalse(text.contains("preview-token-value"));
  }
}
