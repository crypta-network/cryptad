package network.crypta.platform.api.content;

import java.util.List;
import network.crypta.platform.api.PlatformApiException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class ContentFetchPolicyTest {
  @Test
  void normalizeForegroundSource_whenSupportedContentKeyFamiliesProvided_expectNormalizedSource() {
    List<SourceCase> cases =
        List.of(
            new SourceCase("CHK@example", "CHK@example", ContentFetchPolicy.ContentKeyKind.CHK),
            new SourceCase("ssk@example", "ssk@example", ContentFetchPolicy.ContentKeyKind.SSK),
            new SourceCase(
                "crypta:USK@example/feed/42/feed.json",
                "USK@example/feed/42/feed.json",
                ContentFetchPolicy.ContentKeyKind.USK),
            new SourceCase("KSK@example", "KSK@example", ContentFetchPolicy.ContentKeyKind.KSK));

    for (SourceCase sourceCase : cases) {
      ContentFetchPolicy.NormalizedContentSource source =
          ContentFetchPolicy.normalizeForegroundSource(sourceCase.requestedUri());

      assertEquals(sourceCase.requestedUri(), source.requestedUri(), sourceCase.requestedUri());
      assertEquals(sourceCase.runtimeUri(), source.runtimeUri(), sourceCase.requestedUri());
      assertEquals(sourceCase.kind(), source.kind(), sourceCase.requestedUri());
    }
  }

  @Test
  void normalizeForegroundSource_whenUriIsUnsafe_expectRejectedWithStableRedactedError() {
    for (String unsafeUri :
        List.of(
            "http://example.invalid/feed?token=SECRET",
            "https://example.invalid/feed",
            "file:///tmp/private",
            "//example.invalid/feed",
            "/var/lib/cryptad/feed",
            "C:\\Users\\Alice\\Crypta\\feed",
            "CHK@valid\\confused",
            "CHK@valid?token=SECRET",
            "CHK@valid#fragment",
            "CHK@valid\nSSK@other",
            "relative/content")) {
      PlatformApiException failure =
          assertThrows(
              PlatformApiException.class,
              () -> ContentFetchPolicy.normalizeForegroundSource(unsafeUri),
              unsafeUri);

      assertEquals(400, failure.statusCode(), unsafeUri);
      assertEquals("unsupported_content_source", failure.errorCode(), unsafeUri);
      assertEquals(
          "Content fetch URI must be a CHK@, SSK@, USK@, KSK@, or crypta: content key.",
          failure.getMessage(),
          unsafeUri);
    }
  }

  @Test
  void normalizeSubscriptionSource_whenSourceIsNotUsk_expectRejected() {
    for (String unsupportedSource : List.of("CHK@example", "SSK@example/feed", "KSK@example")) {
      PlatformApiException failure =
          assertThrows(
              PlatformApiException.class,
              () -> ContentFetchPolicy.normalizeSubscriptionSource(unsupportedSource),
              unsupportedSource);

      assertEquals(400, failure.statusCode(), unsupportedSource);
      assertEquals(
          "unsupported_content_subscription_source", failure.errorCode(), unsupportedSource);
    }
  }

  @Test
  void sanitizeForegroundResolvedUri_whenResolvedUriIsUnsafe_expectNull() {
    assertNull(ContentFetchPolicy.sanitizeForegroundResolvedUri(null));
    assertNull(ContentFetchPolicy.sanitizeForegroundResolvedUri(" "));
    assertNull(ContentFetchPolicy.sanitizeForegroundResolvedUri("CHK@example?token=SECRET"));
    assertNull(ContentFetchPolicy.sanitizeForegroundResolvedUri("http://example.invalid"));
    assertNull(ContentFetchPolicy.sanitizeForegroundResolvedUri("/tmp/private"));
  }

  @Test
  void resolvedUskEdition_whenResolvedUriIsSafeUsk_expectParsedEdition() {
    assertEquals(
        42L, ContentFetchPolicy.resolvedUskEdition("crypta:USK@example/feed/42/feed.json"));
    assertEquals(0L, ContentFetchPolicy.resolvedUskEdition("USK@example/feed/0/feed.json"));
  }

  @Test
  void resolvedUskEdition_whenResolvedUriIsUnsafeOrMalformed_expectNull() {
    assertNull(ContentFetchPolicy.resolvedUskEdition("CHK@example"));
    assertNull(ContentFetchPolicy.resolvedUskEdition("USK@example/feed/not-number/feed.json"));
    assertNull(ContentFetchPolicy.resolvedUskEdition("USK@example/feed/42/feed.json?token=SECRET"));
    assertNull(ContentFetchPolicy.resolvedUskEdition("USK@example/feed"));
  }

  private record SourceCase(
      String requestedUri, String runtimeUri, ContentFetchPolicy.ContentKeyKind kind) {}
}
