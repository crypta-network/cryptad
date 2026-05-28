package network.crypta.platform.api.appvault;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class SocialMessageRequestTest {
  private static final Clock FIXED_CLOCK =
      Clock.fixed(Instant.parse("2026-05-26T00:00:00Z"), ZoneOffset.UTC);

  @Test
  void canonicalBytes_whenCalledRepeatedly_expectStablePayloadAndMessageId() {
    SocialMessageRequest first = validRequest();
    SocialMessageRequest second = validRequest();

    assertArrayEquals(first.canonicalBytes(), second.canonicalBytes());
    assertEquals(first.message().get("messageId"), second.message().get("messageId"));
    String canonical = new String(first.canonicalBytes(), java.nio.charset.StandardCharsets.UTF_8);
    assertTrue(canonical.startsWith("crypta.social.message.v1\n{"));
    assertTrue(canonical.contains("\"type\":\"crypta.social.message.v1\""));
    assertTrue(canonical.contains("\"createdAt\":\"2026-05-26T00:00:00Z\""));
    assertTrue(canonical.contains("\"format\":\"text/plain\""));
  }

  @Test
  void message_whenOptionalFieldsBlank_expectDefaultsAndOmittedOptionals() {
    SocialMessageRequest request =
        SocialMessageRequest.fromQuery(
            "social-inbox",
            "id-author",
            "fingerprint",
            Map.of(
                "authorLabel",
                List.of("  "),
                "profileUri",
                List.of("  "),
                "channel",
                List.of("  "),
                "subject",
                List.of("  "),
                "body",
                List.of("hello"),
                "replyTo",
                List.of("  "),
                "recipientFingerprint",
                List.of("  "),
                "tags",
                List.of("  "),
                "format",
                List.of("  ")),
            FIXED_CLOCK);

    Map<String, Object> message = request.message();

    assertEquals("general", message.get("channel"));
    assertEquals("", message.get("subject"));
    assertEquals("hello", message.get("body"));
    assertEquals("text/plain", message.get("format"));
    assertTrue(message.containsKey("messageId"));
    assertFalse(message.containsKey("authorLabel"));
    assertFalse(message.containsKey("profileUri"));
    assertFalse(message.containsKey("replyTo"));
    assertFalse(message.containsKey("recipientFingerprint"));
    assertFalse(message.containsKey("tags"));
  }

  @Test
  void fromQuery_whenBodyMissing_expectBadRequest() {
    Map<String, List<String>> queryParameters = Map.of();

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> fromQuery(queryParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_query_parameter", exception.errorCode());
    assertTrue(exception.getMessage().contains("body"));
  }

  @Test
  void fromQuery_whenBodyTooLarge_expectBadRequest() {
    Map<String, List<String>> queryParameters = Map.of("body", List.of("x".repeat(4097)));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> fromQuery(queryParameters));

    assertEquals(400, exception.statusCode());
    assertTrue(exception.getMessage().contains("body"));
  }

  @Test
  void fromQuery_whenSubjectTooLarge_expectBadRequest() {
    Map<String, List<String>> queryParameters =
        Map.of("subject", List.of("x".repeat(161)), "body", List.of("hello"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> fromQuery(queryParameters));

    assertEquals(400, exception.statusCode());
    assertTrue(exception.getMessage().contains("subject"));
  }

  @Test
  void fromQuery_whenTagsInvalid_expectBadRequest() {
    Map<String, List<String>> queryParameters =
        Map.of("tags", List.of("valid,,empty"), "body", List.of("hello"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> fromQuery(queryParameters));

    assertEquals(400, exception.statusCode());
    assertTrue(exception.getMessage().contains("tags"));
  }

  @Test
  void fromQuery_whenTagsExceedBoundsOrContainControls_expectBadRequest() {
    Map<String, List<String>> tooManyParameters =
        Map.of(
            "tags",
            List.of("one,two,three,four,five,six,seven,eight,nine,ten,eleven,twelve," + "thirteen"),
            "body",
            List.of("hello"));
    Map<String, List<String>> tooLongParameters =
        Map.of("tags", List.of("x".repeat(33)), "body", List.of("hello"));
    Map<String, List<String>> controlParameters =
        Map.of("tags", List.of("ba" + (char) 0 + "d"), "body", List.of("hello"));

    PlatformApiException tooMany =
        assertThrows(PlatformApiException.class, () -> fromQuery(tooManyParameters));
    PlatformApiException tooLong =
        assertThrows(PlatformApiException.class, () -> fromQuery(tooLongParameters));
    PlatformApiException control =
        assertThrows(PlatformApiException.class, () -> fromQuery(controlParameters));

    assertEquals(400, tooMany.statusCode());
    assertTrue(tooMany.getMessage().contains("too many tags"));
    assertEquals(400, tooLong.statusCode());
    assertTrue(tooLong.getMessage().contains("too long"));
    assertEquals(400, control.statusCode());
    assertTrue(control.getMessage().contains("control characters"));
  }

  @Test
  void fromQuery_whenBodyContainsUnsafeControl_expectBadRequest() {
    Map<String, List<String>> queryParameters =
        Map.of("body", List.of("hello" + (char) 0 + "world"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> fromQuery(queryParameters));

    assertEquals(400, exception.statusCode());
    assertTrue(exception.getMessage().contains("normal whitespace"));
  }

  @Test
  void fromQuery_whenFormatUnsupported_expectBadRequest() {
    Map<String, List<String>> queryParameters =
        Map.of("format", List.of("text/html"), "body", List.of("hello"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> fromQuery(queryParameters));

    assertEquals(400, exception.statusCode());
    assertTrue(exception.getMessage().contains("text/plain"));
  }

  @Test
  void fromQuery_whenCallerSuppliesPurposePayloadOrDomain_expectRejected() {
    Map<String, List<String>> purposeParameters =
        Map.of("purpose", List.of("anything"), "body", List.of("hello"));
    Map<String, List<String>> payloadParameters =
        Map.of("payloadBase64", List.of("e30="), "body", List.of("hello"));
    Map<String, List<String>> domainParameters =
        Map.of("domain", List.of("crypta.other.domain"), "body", List.of("hello"));

    PlatformApiException purpose =
        assertThrows(PlatformApiException.class, () -> fromQuery(purposeParameters));
    PlatformApiException payload =
        assertThrows(PlatformApiException.class, () -> fromQuery(payloadParameters));
    PlatformApiException domain =
        assertThrows(PlatformApiException.class, () -> fromQuery(domainParameters));

    assertEquals(400, purpose.statusCode());
    assertTrue(purpose.getMessage().contains("purpose"));
    assertEquals(400, payload.statusCode());
    assertTrue(payload.getMessage().contains("payloadBase64"));
    assertEquals(400, domain.statusCode());
    assertTrue(domain.getMessage().contains("domain"));
  }

  @Test
  void message_whenConstructedWithMutableTags_expectDefensiveCopy() {
    ArrayList<String> tags = new ArrayList<>(List.of("first"));
    SocialMessageRequest request =
        new SocialMessageRequest(
            "social-inbox",
            "id-author",
            "fingerprint",
            null,
            null,
            "msg-fixed",
            Instant.parse("2026-05-26T00:00:00Z"),
            "general",
            "",
            "hello",
            null,
            null,
            tags);

    tags.add("mutated");
    Map<String, Object> message = request.message();

    assertEquals(List.of("first"), message.get("tags"));
  }

  private static SocialMessageRequest validRequest() {
    return fromQuery(
        Map.of(
            "authorLabel",
            List.of("Ada"),
            "profileUri",
            List.of("USK@example/profile/1/profile.json"),
            "channel",
            List.of("general"),
            "subject",
            List.of("Hello"),
            "body",
            List.of("Line one\nLine two"),
            "replyTo",
            List.of("msg-parent"),
            "recipientFingerprint",
            List.of("recipient"),
            "tags",
            List.of("crypta,preview")));
  }

  private static SocialMessageRequest fromQuery(Map<String, List<String>> queryParameters) {
    return SocialMessageRequest.fromQuery(
        "social-inbox", "id-author", "fingerprint", queryParameters, FIXED_CLOCK);
  }
}
