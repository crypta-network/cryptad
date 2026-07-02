package network.crypta.platform.api.appvault;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.contentformats.ContentFormatProfileRegistry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class ProfileDocumentRequestTest {
  @Test
  void fromQuery_whenAllFieldsPresent_expectCanonicalPayloadAndTrimmedValues() {
    ProfileDocumentRequest request =
        ProfileDocumentRequest.fromQuery(
            "profile-publisher",
            "identity-one",
            Map.of(
                "displayName", List.of(" Ada Example "),
                "bio", List.of("Line one\nLine two\r\n"),
                "website", List.of("USK@example/profile/1/"),
                "avatarUri", List.of("CHK@example-avatar"),
                "contactUri", List.of("KSK@example-contact"),
                "tags", List.of("crypta, profile")));

    assertEquals("Ada Example", request.displayName());
    assertEquals("Line one\nLine two", request.bio());
    assertEquals(List.of("crypta", "profile"), request.tags());
    assertEquals(
        "{\"schema\":\""
            + ContentFormatProfileRegistry.PROFILE_DOCUMENT_ID
            + "\","
            + "\"appId\":\"profile-publisher\","
            + "\"identityId\":\"identity-one\","
            + "\"displayName\":\"Ada Example\","
            + "\"bio\":\"Line one\\nLine two\","
            + "\"website\":\"USK@example/profile/1/\","
            + "\"avatarUri\":\"CHK@example-avatar\","
            + "\"contactUri\":\"KSK@example-contact\","
            + "\"tags\":[\"crypta\",\"profile\"]}",
        new String(request.canonicalBytes(), StandardCharsets.UTF_8));
  }

  @Test
  void fromQuery_whenDisplayNameBlank_expectInvalidQuery() {
    Map<String, List<String>> queryParameters = Map.of("displayName", List.of("   "));

    PlatformApiException error =
        assertThrows(
            PlatformApiException.class,
            () ->
                ProfileDocumentRequest.fromQuery(
                    "profile-publisher", "identity-one", queryParameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals("Missing required query parameter 'displayName'.", error.getMessage());
  }

  @Test
  void fromQuery_whenUriContainsLineBreak_expectInvalidQuery() {
    Map<String, List<String>> queryParameters =
        Map.of(
            "displayName", List.of("Ada Example"), "website", List.of("USK@example\n/profile/1/"));

    PlatformApiException error =
        assertThrows(
            PlatformApiException.class,
            () ->
                ProfileDocumentRequest.fromQuery(
                    "profile-publisher", "identity-one", queryParameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals(
        "Query parameter 'website' must not contain control characters.", error.getMessage());
  }

  @Test
  void fromQuery_whenBioContainsNonLineBreakControl_expectInvalidQuery() {
    Map<String, List<String>> queryParameters =
        Map.of(
            "displayName",
            List.of("Ada Example"),
            "bio",
            List.of("Line one" + (char) 0 + "Line two"));

    PlatformApiException error =
        assertThrows(
            PlatformApiException.class,
            () ->
                ProfileDocumentRequest.fromQuery(
                    "profile-publisher", "identity-one", queryParameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals(
        "Query parameter 'bio' must not contain control characters other than line breaks.",
        error.getMessage());
  }

  @Test
  void fromQuery_whenTagsContainEmptySegment_expectInvalidQuery() {
    Map<String, List<String>> queryParameters =
        Map.of("displayName", List.of("Ada Example"), "tags", List.of("crypta,,profile"));

    PlatformApiException error =
        assertThrows(
            PlatformApiException.class,
            () ->
                ProfileDocumentRequest.fromQuery(
                    "profile-publisher", "identity-one", queryParameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals("Query parameter 'tags' must not contain empty tags.", error.getMessage());
  }

  @Test
  void fromQuery_whenCallerSuppliesUnknownSigningField_expectRejectedBeforeSigning() {
    Map<String, List<String>> queryParameters = new LinkedHashMap<>();
    queryParameters.put("displayName", List.of("Ada Example"));
    queryParameters.put("purpose", List.of("generic.signing"));
    queryParameters.put("payloadBase64", List.of("e30="));

    PlatformApiException error =
        assertThrows(
            PlatformApiException.class,
            () ->
                ProfileDocumentRequest.fromQuery(
                    "profile-publisher", "identity-one", queryParameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals("Query parameter 'purpose' is not supported.", error.getMessage());
  }
}
