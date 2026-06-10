package network.crypta.platform.api.appservices;

import java.util.List;
import java.util.stream.Stream;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppServiceManifestParserTest {
  private static final String INVALID_APP_SERVICE_MANIFEST = "invalid_app_service_manifest";
  private static final String SOCIAL_INBOX_APP_ID = "social-inbox";
  private static final String SOCIAL_INBOX_NAME = "Social Inbox Preview";
  private static final String TRUST_GRAPH_APP_ID = "trust-graph";
  private static final String TRUST_GRAPH_NAME = "Trust Graph Preview";

  @Test
  void parseProvidedServices_whenManifestDeclaresTrustScore_expectDescriptor() throws Exception {
    List<AppServiceDescriptor> services =
        AppServiceManifestParser.parseProvidedServicesContent(
            trustGraphManifest(),
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
    assertEquals(TRUST_GRAPH_APP_ID, service.providerAppId());
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
            socialInboxManifest(),
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
    assertEquals(SOCIAL_INBOX_APP_ID, request.consumerAppId());
    assertEquals(TRUST_GRAPH_APP_ID, request.providerAppId());
    assertEquals("trust.score", request.serviceId());
    assertEquals(List.of("score.read"), request.scopes());
    assertEquals(List.of("message-author"), request.contexts());
    assertEquals("Annotate message authors.", request.purpose());
    assertEquals("trust-score", request.alias());
    assertEquals(AppServiceDependencyKind.OPTIONAL, request.dependency().kind());
  }

  @Test
  void parseServiceRequests_whenOptionalDependencyFieldsPresent_expectDependencyDescriptor()
      throws Exception {
    List<AppServiceRequestDescriptor> requests =
        AppServiceManifestParser.parseServiceRequestsContent(
            socialInboxManifest(),
            """
            app.services.requests=trust-score
            app.service-request.trust-score.provider=trust-graph
            app.service-request.trust-score.service=trust.score
            app.service-request.trust-score.scopes=score.read
            app.service-request.trust-score.contexts=message-author
            app.service-request.trust-score.purpose=Annotate message authors.
            app.service-request.trust-score.dependency.kind=optional
            app.service-request.trust-score.dependency.required=false
            app.service-request.trust-score.dependency.featureId=trust-score-annotations
            app.service-request.trust-score.dependency.featureName=Trust score annotations
            app.service-request.trust-score.dependency.reason=Annotates message authors when approved.
            app.service-request.trust-score.dependency.degradeBehavior=disable-feature
            app.service-request.trust-score.dependency.minServiceVersion=1
            app.service-request.trust-score.dependency.maxServiceVersion=1
            app.service-request.trust-score.dependency.grantBundle=trust-annotations
            app.service-request.trust-score.dependency.grantExpiresAfter=PT720H
            """);

    AppServiceDependencyDescriptor dependency = requests.getFirst().dependency();

    assertEquals(AppServiceDependencyKind.OPTIONAL, dependency.kind());
    assertFalse(dependency.required());
    assertEquals("trust-score-annotations", dependency.featureId());
    assertEquals("Trust score annotations", dependency.featureName());
    assertEquals("trust-annotations", dependency.grantBundle());
    assertEquals("PT720H", dependency.grantExpiresAfter().toString());
    assertEquals("1", dependency.versionRange().min());
    assertEquals("1", dependency.versionRange().max());
  }

  @Test
  void parseServiceRequests_whenRequiredDependencyFieldsPresent_expectRequiredDescriptor()
      throws Exception {
    List<AppServiceRequestDescriptor> requests =
        AppServiceManifestParser.parseServiceRequestsContent(
            socialInboxManifest(),
            """
            app.services.requests=trust-score
            app.service-request.trust-score.provider=trust-graph
            app.service-request.trust-score.service=trust.score
            app.service-request.trust-score.scopes=score.read
            app.service-request.trust-score.purpose=Annotate message authors.
            app.service-request.trust-score.dependency.kind=required
            app.service-request.trust-score.dependency.required=true
            app.service-request.trust-score.dependency.degradeBehavior=block-app-start
            """);

    AppServiceDependencyDescriptor dependency = requests.getFirst().dependency();

    assertEquals(AppServiceDependencyKind.REQUIRED, dependency.kind());
    assertTrue(dependency.required());
    assertEquals(AppServiceDegradeBehavior.BLOCK_APP_START, dependency.degradeBehavior());
  }

  @ParameterizedTest
  @MethodSource("invalidServiceRequestMetadata")
  void parseServiceRequests_whenRequestMetadataInvalid_expectManifestError(String requestMetadata) {
    AppManifest socialInboxManifest = socialInboxManifest();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                AppServiceManifestParser.parseServiceRequestsContent(
                    socialInboxManifest, requestMetadata));

    assertEquals(INVALID_APP_SERVICE_MANIFEST, exception.errorCode());
  }

  @Test
  void parseProvidedServices_whenServiceIdInvalid_expectManifestError() {
    AppManifest trustGraphManifest = trustGraphManifest();
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

    assertEquals(INVALID_APP_SERVICE_MANIFEST, exception.errorCode());
  }

  @Test
  void parseServiceRequests_whenPurposeTooLong_expectManifestError() {
    AppManifest socialInboxManifest = socialInboxManifest();
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

    assertEquals(INVALID_APP_SERVICE_MANIFEST, exception.errorCode());
  }

  @Test
  void parseServiceRequests_whenPurposeContainsUppercaseUsersPath_expectManifestError() {
    AppManifest socialInboxManifest = socialInboxManifest();
    String requestMetadata =
        """
        app.services.requests=trust-score
        app.service-request.trust-score.provider=trust-graph
        app.service-request.trust-score.service=trust.score
        app.service-request.trust-score.scopes=score.read
        app.service-request.trust-score.purpose=Read /Users/alice/secret for setup.
        """;

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                AppServiceManifestParser.parseServiceRequestsContent(
                    socialInboxManifest, requestMetadata));

    assertEquals(INVALID_APP_SERVICE_MANIFEST, exception.errorCode());
  }

  @Test
  void parseServiceRequests_whenPurposeContainsPathAfterPunctuation_expectManifestError() {
    for (String purpose :
        List.of("Read path=/home/alice/app for setup.", "Read C:/Users/Alice/app for setup.")) {
      assertPurposeRejected(purpose);
    }
  }

  @Test
  void parseProvidedServices_whenNoServiceKeys_expectEmptyList() throws Exception {
    assertTrue(
        AppServiceManifestParser.parseProvidedServicesContent(
                trustGraphManifest(), "app.name=Trust Graph Preview\n")
            .isEmpty());
  }

  private static Stream<String> invalidServiceRequestMetadata() {
    return Stream.of(
        """
        app.services.requests=trust-score
        app.service-request.trust-score.provider=trust-graph
        app.service-request.trust-score.service=trust.score
        app.service-request.trust-score.scopes=score.read
        app.service-request.trust-score.purpose=Annotate message authors.
        app.service-request.trust-score.dependency.minServiceVersion=2
        app.service-request.trust-score.dependency.maxServiceVersion=1
        """,
        """
        app.services.requests=trust-score
        app.service-request.trust-score.provider=trust-graph
        app.service-request.trust-score.service=trust.score
        app.service-request.trust-score.scopes=score.read
        app.service-request.trust-score.purpose=Annotate message authors.
        app.service-request.trust-score.dependency.grantExpiresAfter=soon
        """,
        """
        app.services.requests=trust-score,trust-score
        app.service-request.trust-score.provider=trust-graph
        app.service-request.trust-score.service=trust.score
        app.service-request.trust-score.scopes=score.read
        app.service-request.trust-score.purpose=Annotate message authors.
        """);
  }

  private static void assertPurposeRejected(String purpose) {
    AppManifest socialInboxManifest = socialInboxManifest();
    String requestMetadata =
        """
        app.services.requests=trust-score
        app.service-request.trust-score.provider=trust-graph
        app.service-request.trust-score.service=trust.score
        app.service-request.trust-score.scopes=score.read
        app.service-request.trust-score.purpose=%s
        """
            .formatted(purpose);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                AppServiceManifestParser.parseServiceRequestsContent(
                    socialInboxManifest, requestMetadata));

    assertEquals(INVALID_APP_SERVICE_MANIFEST, exception.errorCode());
  }

  private static AppManifest socialInboxManifest() {
    return manifest(SOCIAL_INBOX_APP_ID, SOCIAL_INBOX_NAME);
  }

  private static AppManifest trustGraphManifest() {
    return manifest(TRUST_GRAPH_APP_ID, TRUST_GRAPH_NAME);
  }

  private static AppManifest manifest(String appId, String name) {
    return new AppManifest(
        1, appId, name, "1.0.0", "bin/app.sh", AppUiMode.NONE, null, List.of(), null, null);
  }
}
