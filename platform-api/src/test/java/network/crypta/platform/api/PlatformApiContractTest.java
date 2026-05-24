package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PlatformApiContractTest {
  @Test
  void writeEnvelope_whenCalledRepeatedly_expectDeterministicContractJson() {
    String first = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());
    String second = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());

    assertEquals(first, second);
    assertTrue(first.startsWith("{\"contract\":{\"apiVersion\":\"v1\",\"contractVersion\":8"));
    assertFalse(first.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(first.contains("browserSessionToken"));
    assertFalse(first.contains("password"));
    assertFalse(first.contains("privateKey"));
  }

  @Test
  void parse_whenReadingOwnSnapshot_expectRoundTripPreservesJson() {
    String json = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());

    PlatformApiContract parsed = PlatformApiContractJson.parse(json);

    assertEquals(json, PlatformApiContractJson.writeEnvelope(parsed));
  }

  @Test
  void current_whenReadingVersion_expectTypedApiAndContractVersion() {
    PlatformApiContractVersion version = PlatformApiContract.current().version();

    assertEquals("v1", version.apiVersion());
    assertEquals(8, version.contractVersion());
  }

  @Test
  void current_whenInspectingCapabilities_expectRegistryMatchesDescriptors() {
    Set<String> descriptorNames = PlatformApiContract.current().capabilityNames();

    assertEquals(PlatformApiCapabilityRegistry.knownCapabilities(), descriptorNames);
    assertTrue(descriptorNames.contains("platform.contract.read"));
    assertEquals(new TreeSet<>(descriptorNames), descriptorNames);
    PlatformApiCapabilityDescriptor appDocumentInsertCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals("content.insert.app-document"))
            .findFirst()
            .orElseThrow();
    assertEquals(5, appDocumentInsertCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor contentFetchCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals("content.fetch"))
            .findFirst()
            .orElseThrow();
    assertEquals(6, contentFetchCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor contentSubscribeCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals("content.subscribe"))
            .findFirst()
            .orElseThrow();
    assertEquals(8, contentSubscribeCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor trustReadCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals("trust.read"))
            .findFirst()
            .orElseThrow();
    assertEquals(7, trustReadCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor trustWriteCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals("trust.write"))
            .findFirst()
            .orElseThrow();
    assertEquals(7, trustWriteCapability.sinceContractVersion());
  }

  @Test
  void current_whenInspectingEndpoints_expectDescriptorsReferenceKnownCapabilities() {
    Set<String> knownCapabilities = PlatformApiContract.current().capabilityNames();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      assertFalse(endpoint.requiredCapabilities().isEmpty(), endpoint.routeTemplate());
      assertTrue(
          knownCapabilities.containsAll(endpoint.requiredCapabilities()), endpoint.routeTemplate());
      assertEquals(expectedSinceContractVersion(endpoint), endpoint.sinceContractVersion());
      assertEquals(expectedStability(endpoint), endpoint.stability(), endpoint.routeTemplate());
    }
  }

  @Test
  void current_whenAuthorizingEndpointSamples_expectAuthorizationUsesContractDescriptors() {
    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      PlatformApiRequest processRequest =
          appRequest(
              endpoint.method(),
              sampleSegments(endpoint.routeTemplate()),
              endpoint.requiredCapabilities());
      PlatformApiAuthorizationDecision processDecision =
          PlatformApiCapabilities.authorize(processRequest);
      PlatformApiRequest browserRequest =
          browserRequest(
              endpoint.method(),
              sampleSegments(endpoint.routeTemplate()),
              endpoint.requiredCapabilities());
      PlatformApiAuthorizationDecision browserDecision =
          PlatformApiCapabilities.authorize(browserRequest);

      assertEndpointAuthorization(endpoint, processDecision, endpoint.appProcessAllowed());
      assertEndpointAuthorization(endpoint, browserDecision, endpoint.appBrowserAllowed());
    }
  }

  @Test
  void current_whenInspectingIdentityCreateEndpoint_expectAppVaultSinceVersionAndBrowserAccess() {
    PlatformApiEndpointDescriptor endpoint =
        PlatformApiContract.current().endpoints().stream()
            .filter(
                descriptor ->
                    descriptor.method().equals("POST")
                        && descriptor.routeTemplate().equals("/app-vault/identities"))
            .findFirst()
            .orElseThrow();

    assertEquals(3, endpoint.sinceContractVersion());
    assertTrue(endpoint.appProcessAllowed());
    assertTrue(endpoint.appBrowserAllowed());
    assertEquals(List.of("vault.identities.create"), endpoint.requiredCapabilities());
  }

  @Test
  void current_whenInspectingContentFetchEndpoint_expectContractVersionAndBrowserAccess() {
    PlatformApiEndpointDescriptor endpoint =
        PlatformApiContract.current().endpoints().stream()
            .filter(
                descriptor ->
                    descriptor.method().equals("POST")
                        && descriptor.routeTemplate().equals("/content/fetch"))
            .findFirst()
            .orElseThrow();

    assertEquals(6, endpoint.sinceContractVersion());
    assertEquals("content", endpoint.routeFamily());
    assertEquals("content.fetch", endpoint.actionLabel());
    assertTrue(endpoint.hostOperatorBypassAllowed());
    assertTrue(endpoint.appProcessAllowed());
    assertTrue(endpoint.appBrowserAllowed());
    assertEquals(List.of("content.fetch"), endpoint.requiredCapabilities());
  }

  @Test
  void current_whenInspectingContentSubscriptionEndpoints_expectContractV8AppScopedCapabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.of(
            "GET /content/subscriptions",
            List.of("content.subscribe"),
            "POST /content/subscriptions",
            List.of("content.fetch", "content.subscribe"),
            "GET /content/subscriptions/{subscriptionId}",
            List.of("content.subscribe"),
            "POST /content/subscriptions/{subscriptionId}/refresh",
            List.of("content.fetch", "content.subscribe"),
            "POST /content/subscriptions/{subscriptionId}/pause",
            List.of("content.subscribe"),
            "POST /content/subscriptions/{subscriptionId}/resume",
            List.of("content.subscribe"),
            "DELETE /content/subscriptions/{subscriptionId}",
            List.of("content.subscribe"));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(8, endpoint.sinceContractVersion(), key);
      assertEquals("content", endpoint.routeFamily(), key);
      assertFalse(endpoint.hostOperatorBypassAllowed(), key);
      assertTrue(endpoint.appProcessAllowed(), key);
      assertTrue(endpoint.appBrowserAllowed(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void current_whenInspectingTrustGraphEndpoints_expectContractV7Capabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.of(
            "GET /trust-graph/status",
            List.of("trust.read"),
            "GET /trust-graph/anchors",
            List.of("trust.read"),
            "POST /trust-graph/anchors",
            List.of("trust.write"),
            "DELETE /trust-graph/anchors/{fingerprint}",
            List.of("trust.write"),
            "POST /trust-graph/import",
            List.of("trust.write"),
            "GET /trust-graph/subjects",
            List.of("trust.read"),
            "GET /trust-graph/statements",
            List.of("trust.read"),
            "GET /trust-graph/score",
            List.of("trust.read"));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(7, endpoint.sinceContractVersion(), key);
      assertEquals("trust-graph", endpoint.routeFamily(), key);
      assertEquals(PlatformApiStabilityLevel.EXPERIMENTAL, endpoint.stability(), key);
      assertTrue(endpoint.appProcessAllowed(), key);
      assertTrue(endpoint.appBrowserAllowed(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void current_whenInspectingTrustStatementEndpoint_expectBoundedVaultCapabilities() {
    PlatformApiEndpointDescriptor endpoint =
        PlatformApiContract.current().endpoints().stream()
            .filter(
                descriptor ->
                    descriptor.method().equals("POST")
                        && descriptor
                            .routeTemplate()
                            .equals("/app-vault/identities/{identityId}/trust-statement"))
            .findFirst()
            .orElseThrow();

    assertEquals(7, endpoint.sinceContractVersion());
    assertEquals("app-vault", endpoint.routeFamily());
    assertEquals("app-vault.identities.trust-statement", endpoint.actionLabel());
    assertTrue(endpoint.appProcessAllowed());
    assertTrue(endpoint.appBrowserAllowed());
    assertEquals(
        List.of("trust.write", "vault.identities.read", "vault.identities.use"),
        endpoint.requiredCapabilities());
  }

  private static void assertEndpointAuthorization(
      PlatformApiEndpointDescriptor endpoint,
      PlatformApiAuthorizationDecision decision,
      boolean principalAllowed) {
    if (principalAllowed) {
      assertTrue(decision.allowed(), endpoint.routeTemplate());
      assertEquals(endpoint.toAction(), decision.action(), endpoint.routeTemplate());
      return;
    }
    assertFalse(decision.allowed(), endpoint.routeTemplate());
    assertEquals("unmapped_route", decision.reasonCode(), endpoint.routeTemplate());
  }

  private static int expectedSinceContractVersion(PlatformApiEndpointDescriptor endpoint) {
    if (endpoint.routeTemplate().startsWith("/trust-graph")
        || endpoint.routeTemplate().equals("/app-vault/identities/{identityId}/trust-statement")) {
      return 7;
    }
    if (endpoint.routeTemplate().startsWith("/content/subscriptions")) {
      return 8;
    }
    if (endpoint.routeTemplate().equals("/queue/inserts/app-document")
        || endpoint.routeTemplate().equals("/app-vault/identities/{identityId}/profile-document")) {
      return 5;
    }
    if (endpoint.routeTemplate().equals("/content/fetch")) {
      return 6;
    }
    if (endpoint.routeTemplate().startsWith("/app-vault")
        || endpoint.routeTemplate().startsWith("/identity-vault")) {
      return 3;
    }
    if (endpoint.routeTemplate().startsWith("/app-catalogs/recommended")) {
      return 4;
    }
    return endpoint.routeTemplate().startsWith("/apps/{appId}/updates") ? 2 : 1;
  }

  private static PlatformApiStabilityLevel expectedStability(
      PlatformApiEndpointDescriptor endpoint) {
    if (endpoint.routeTemplate().startsWith("/trust-graph")
        || endpoint.routeTemplate().startsWith("/app-vault")
        || endpoint.routeTemplate().startsWith("/identity-vault")) {
      return PlatformApiStabilityLevel.EXPERIMENTAL;
    }
    return PlatformApiStabilityLevel.STABLE;
  }

  private static PlatformApiRequest appRequest(
      String method, List<String> segments, List<String> permissions) {
    return new PlatformApiRequest(
        method, segments, Map.of(), PlatformApiPrincipal.appToken("contract-test", permissions));
  }

  private static PlatformApiRequest browserRequest(
      String method, List<String> segments, List<String> permissions) {
    return new PlatformApiRequest(
        method,
        segments,
        Map.of(),
        PlatformApiPrincipal.appBrowserSession("contract-test", permissions));
  }

  private static List<String> sampleSegments(String routeTemplate) {
    String relative = routeTemplate.substring(1);
    if (relative.isEmpty()) {
      return List.of();
    }
    return Stream.of(relative.split("/", -1))
        .map(segment -> segment.startsWith("{") && segment.endsWith("}") ? "sample" : segment)
        .toList();
  }
}
