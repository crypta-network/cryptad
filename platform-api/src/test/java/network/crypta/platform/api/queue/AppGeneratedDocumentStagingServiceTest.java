package network.crypta.platform.api.queue;

import java.nio.charset.StandardCharsets;
import network.crypta.platform.api.PlatformApiException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class AppGeneratedDocumentStagingServiceTest {
  @Test
  void stage_whenCalled_expectSanitizedMetadataAndDetachedDocumentBytes() throws Exception {
    AppGeneratedDocumentStagingService service = new AppGeneratedDocumentStagingService();
    byte[] document = "{\"schema\":\"crypta.profile.v1\"}".getBytes(StandardCharsets.UTF_8);

    AppGeneratedDocumentStagingResult result =
        service.stage(
            "profile-publisher",
            "\nprofile.json  ",
            "application/vnd.crypta.profile+json",
            document);
    document[1] = 'X';

    assertEquals("<redacted>", result.publicSourcePath());
    assertEquals("profile.json", result.upload().filename());
    assertEquals("application/vnd.crypta.profile+json", result.upload().contentType());
    assertEquals("{\"schema\":\"crypta.profile.v1\"}".length(), result.upload().size());
    try (var input = result.upload().openStream()) {
      assertEquals(
          "{\"schema\":\"crypta.profile.v1\"}",
          new String(input.readAllBytes(), StandardCharsets.UTF_8));
    }
  }

  @Test
  void stage_whenTargetFilenameIsPath_expectInvalidQuery() {
    AppGeneratedDocumentStagingService service = new AppGeneratedDocumentStagingService();
    byte[] document = "{}".getBytes(StandardCharsets.UTF_8);

    PlatformApiException error =
        assertThrows(
            PlatformApiException.class,
            () ->
                service.stage(
                    "profile-publisher", "../profile.json", "application/json", document));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals(
        "Query parameter 'targetFilename' must be a filename, not a path.", error.getMessage());
  }
}
