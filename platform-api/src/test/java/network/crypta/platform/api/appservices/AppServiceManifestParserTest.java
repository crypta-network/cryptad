package network.crypta.platform.api.appservices;

import java.util.List;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppServiceManifestParserTest {
  @Test
  void parseProvidedServices_whenManifestDeclaresTrustScore_expectDescriptor() throws Exception {
    List<AppServiceDescriptor> services =
        AppServiceManifestParser.parseProvidedServicesContent(
            manifest("trust-graph", "Trust Graph Preview"),
            """
            app.services.provides=trust-score
            app.service.trust-score.id=trust.score
            app.service.trust-score.name=Trust Score Service
            app.service.trust-score.version=1
            app.service.trust-score.kind=platform-adapter
            app.service.trust-score.adapter=trust-graph.score
            app.service.trust-score.scopes=score.read
            app.service.trust-score.contexts=message-author,profile
            app.service.trust-score.description=Returns a local redacted score summary.
            """);

    assertEquals(1, services.size());
    AppServiceDescriptor service = services.getFirst();
    assertEquals("trust-graph", service.providerAppId());
    assertEquals("trust.score", service.serviceId());
    assertEquals("trust-graph.score", service.adapter());
    assertEquals(List.of("score.read"), service.scopes());
    assertEquals(List.of("message-author", "profile"), service.contexts());
    assertEquals("preview", service.stability());
    assertTrue(service.available());
  }

  @Test
  void parseServiceRequests_whenManifestDeclaresSocialInboxRequest_expectDescriptor()
      throws Exception {
    List<AppServiceRequestDescriptor> requests =
        AppServiceManifestParser.parseServiceRequestsContent(
            manifest("social-inbox", "Social Inbox Preview"),
            """
            app.services.requests=trust-score
            app.service-request.trust-score.provider=trust-graph
            app.service-request.trust-score.service=trust.score
            app.service-request.trust-score.scopes=score.read
            app.service-request.trust-score.contexts=message-author
            app.service-request.trust-score.purpose=Annotate message authors.
            ignored.property=ignored
            """);

    assertEquals(1, requests.size());
    AppServiceRequestDescriptor request = requests.getFirst();
    assertEquals("social-inbox", request.consumerAppId());
    assertEquals("trust-graph", request.providerAppId());
    assertEquals("trust.score", request.serviceId());
    assertEquals(List.of("score.read"), request.scopes());
    assertEquals(List.of("message-author"), request.contexts());
    assertEquals("Annotate message authors.", request.purpose());
  }

  @Test
  void parseProvidedServices_whenServiceIdInvalid_expectManifestError() {
    AppManifest trustGraphManifest = manifest("trust-graph", "Trust Graph Preview");
    String providerMetadata =
        """
        app.services.provides=trust-score
        app.service.trust-score.id=Trust Score
        app.service.trust-score.name=Trust Score Service
        app.service.trust-score.version=1
        app.service.trust-score.kind=platform-adapter
        app.service.trust-score.adapter=trust-graph.score
        app.service.trust-score.scopes=score.read
        """;

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                AppServiceManifestParser.parseProvidedServicesContent(
                    trustGraphManifest, providerMetadata));

    assertEquals("invalid_app_service_manifest", exception.errorCode());
  }

  @Test
  void parseServiceRequests_whenPurposeTooLong_expectManifestError() {
    AppManifest socialInboxManifest = manifest("social-inbox", "Social Inbox Preview");
    String longPurpose = "x".repeat(513);
    String requestMetadata =
        """
        app.services.requests=trust-score
        app.service-request.trust-score.provider=trust-graph
        app.service-request.trust-score.service=trust.score
        app.service-request.trust-score.scopes=score.read
        app.service-request.trust-score.purpose=%s
        """
            .formatted(longPurpose);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                AppServiceManifestParser.parseServiceRequestsContent(
                    socialInboxManifest, requestMetadata));

    assertEquals("invalid_app_service_manifest", exception.errorCode());
  }

  @Test
  void parseProvidedServices_whenNoServiceKeys_expectEmptyList() throws Exception {
    assertTrue(
        AppServiceManifestParser.parseProvidedServicesContent(
                manifest("trust-graph", "Trust Graph Preview"), "app.name=Trust Graph Preview\n")
            .isEmpty());
  }

  private static AppManifest manifest(String appId, String name) {
    return new AppManifest(
        1, appId, name, "1.0.0", "bin/app.sh", AppUiMode.NONE, null, List.of(), null, null);
  }
}
