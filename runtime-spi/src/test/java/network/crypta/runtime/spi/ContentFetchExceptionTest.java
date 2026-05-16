package network.crypta.runtime.spi;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class ContentFetchExceptionTest {
  private static final String FAILURE_MESSAGE = "failed";

  @Test
  void constructor_whenErrorCodeSupplied_expectStableCodeReturned() {
    ContentFetchException exception =
        new ContentFetchException(ContentFetchException.CATALOG_FETCH_FAILED, FAILURE_MESSAGE);

    assertEquals(ContentFetchException.CATALOG_FETCH_FAILED, exception.errorCode());
    assertEquals(FAILURE_MESSAGE, exception.getMessage());
  }

  @Test
  void constructor_whenCauseSupplied_expectCausePreserved() {
    RuntimeException cause = new RuntimeException("source");
    ContentFetchException exception =
        new ContentFetchException(ContentFetchException.CATALOG_FETCH_TIMEOUT, "timeout", cause);

    assertEquals(ContentFetchException.CATALOG_FETCH_TIMEOUT, exception.errorCode());
    assertSame(cause, exception.getCause());
  }

  @Test
  void constructor_whenTooLargeCodeSupplied_expectStableCodeReturned() {
    ContentFetchException exception =
        new ContentFetchException(ContentFetchException.CATALOG_FETCH_TOO_LARGE, "too large");

    assertEquals(ContentFetchException.CATALOG_FETCH_TOO_LARGE, exception.errorCode());
  }

  @Test
  void constructor_whenErrorCodeIsBlank_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> throwExceptionWithErrorCode(" "));
  }

  @Test
  void constructor_whenErrorCodeIsMultiline_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class, () -> throwExceptionWithErrorCode("catalog\nfailed"));
  }

  private static void throwExceptionWithErrorCode(String errorCode) throws ContentFetchException {
    throw new ContentFetchException(errorCode, FAILURE_MESSAGE);
  }
}
