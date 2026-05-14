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
    assertTrue(first.startsWith("{\"contract\":{\"apiVersion\":\"v1\",\"contractVersion\":4"));
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
    assertEquals(4, version.contractVersion());
  }

  @Test
  void current_whenInspectingCapabilities_expectRegistryMatchesDescriptors() {
    Set<String> descriptorNames = PlatformApiContract.current().capabilityNames();

    assertEquals(PlatformApiCapabilityRegistry.knownCapabilities(), descriptorNames);
    assertTrue(descriptorNames.contains("platform.contract.read"));
    assertEquals(new TreeSet<>(descriptorNames), descriptorNames);
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
    if (endpoint.routeTemplate().startsWith("/app-vault")
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
