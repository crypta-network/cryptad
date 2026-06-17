package network.crypta.platform.api;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PlatformApiContractTest {
  @Test
  void writeEnvelope_whenCalledRepeatedly_expectDeterministicContractJson() {
    String first = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());
    String second = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());

    assertEquals(first, second);
    assertTrue(
        first.startsWith(
            "{\"contract\":{\"apiVersion\":\"v1\",\"contractVersion\":"
                + PlatformApiContract.CURRENT_CONTRACT_VERSION));
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
  void parse_whenStableBaselineMetadataChanges_expectSnapshotRejected() {
    String json = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());
    String baselineVersion =
        "\"stableBaseline\":{\"name\":\"1.0\",\"contractVersion\":"
            + PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION;
    assertTrue(json.contains(baselineVersion));
    String staleJson =
        json.replace(
            baselineVersion,
            "\"stableBaseline\":{\"name\":\"1.0\",\"contractVersion\":"
                + (PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION - 1));

    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class, () -> PlatformApiContractJson.parse(staleJson));

    assertTrue(thrown.getMessage().contains("stableBaseline"), thrown.getMessage());
  }

  @Test
  void parse_whenStableBaselineMissingFromFutureSnapshot_expectSnapshotRejected() {
    String json =
        contractJsonWithoutStableBaseline(
            PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION + 1);

    IllegalArgumentException thrown =
        assertThrows(IllegalArgumentException.class, () -> PlatformApiContractJson.parse(json));

    assertTrue(thrown.getMessage().contains("stableBaseline"), thrown.getMessage());
  }

  @Test
  void parse_whenStableBaselineMissingFromBaselineVersionSnapshot_expectSnapshotRemainsReadable() {
    int baselineContractVersion = PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION;
    String json = contractJsonWithoutStableBaseline(baselineContractVersion);

    PlatformApiContract parsed = PlatformApiContractJson.parse(json);

    assertEquals(baselineContractVersion, parsed.contractVersion());
    assertEquals(
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
        parsed.stableBaseline().contractVersion());
  }

  @Test
  void parse_whenStableBaselineMissingFromLegacySnapshot_expectSnapshotRemainsReadable() {
    int legacyContractVersion =
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION - 1;
    String json = contractJsonWithoutStableBaseline(legacyContractVersion);

    PlatformApiContract parsed = PlatformApiContractJson.parse(json);

    assertEquals(legacyContractVersion, parsed.contractVersion());
    assertEquals(
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
        parsed.stableBaseline().contractVersion());
  }

  @Test
  void current_whenReadingVersion_expectTypedApiAndContractVersion() {
    PlatformApiContractVersion version = PlatformApiContract.current().version();

    assertEquals("v1", version.apiVersion());
    assertEquals(PlatformApiContract.CURRENT_CONTRACT_VERSION, version.contractVersion());
  }

  @Test
  void current_whenInspectingStableBaseline_expectDeterministicAppFacingStableMetadata() {
    PlatformApiContract.StableBaseline baseline = PlatformApiContract.current().stableBaseline();

    assertEquals("1.0", baseline.name());
    assertEquals(
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
        baseline.contractVersion());
    assertEquals(baseline.capabilities().size(), baseline.capabilityCount());
    assertEquals(baseline.endpoints().size(), baseline.endpointCount());
    assertEquals(
        List.of(
            "app.data.read",
            "app.data.write",
            "content.fetch",
            "content.insert",
            "content.insert.app-document",
            "content.subscribe",
            "platform.contract.read",
            "queue.read",
            "queue.write"),
        baseline.capabilities());
    assertFalse(baseline.capabilities().contains("trust.read"));
    assertFalse(baseline.capabilities().contains("app.services.read"));
    assertTrue(baseline.endpoints().contains("POST /content/fetch"));
    assertTrue(baseline.endpoints().contains("POST /queue/inserts/app-document"));
    assertTrue(baseline.endpoints().contains("GET /platform/contract"));
    assertTrue(baseline.endpoints().contains("POST /queue/inserts/file"));
    assertFalse(baseline.endpoints().stream().anyMatch(endpoint -> endpoint.contains("app-vault")));
    assertFalse(baseline.endpoints().stream().anyMatch(endpoint -> endpoint.contains("operator")));
  }

  @Test
  void constructor_whenContractVersionBumps_expectStableBaselineRemainsAnchoredToFrozenVersion() {
    PlatformApiContract contract =
        new PlatformApiContract(
            "v1",
            PlatformApiContract.CURRENT_CONTRACT_VERSION + 1,
            "test",
            "test policy",
            PlatformApiContract.current().capabilities(),
            PlatformApiContract.current().endpoints());

    assertEquals(PlatformApiContract.CURRENT_CONTRACT_VERSION + 1, contract.contractVersion());
    assertEquals(
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
        contract.stableBaseline().contractVersion());
  }

  @Test
  void constructor_whenFutureStableEndpointExists_expectBaselineMembershipFrozen() {
    List<PlatformApiEndpointDescriptor> endpoints = endpointsWithFutureStableQueueView();

    PlatformApiContract contract =
        new PlatformApiContract(
            "v1",
            PlatformApiContract.CURRENT_CONTRACT_VERSION + 1,
            "test",
            "test policy",
            PlatformApiContract.current().capabilities(),
            endpoints);

    assertFalse(contract.stableBaseline().endpoints().contains("GET /queue/future"));
    assertEquals(
        PlatformApiContract.current().stableBaseline().endpoints(),
        contract.stableBaseline().endpoints());
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
    PlatformApiCapabilityDescriptor appDataReadCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals("app.data.read"))
            .findFirst()
            .orElseThrow();
    assertEquals(9, appDataReadCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor appDataWriteCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals("app.data.write"))
            .findFirst()
            .orElseThrow();
    assertEquals(9, appDataWriteCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor appServicesReadCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals("app.services.read"))
            .findFirst()
            .orElseThrow();
    assertEquals(12, appServicesReadCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor appServicesCallCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals("app.services.call"))
            .findFirst()
            .orElseThrow();
    assertEquals(12, appServicesCallCapability.sinceContractVersion());
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
      if (endpoint.appProcessAllowed() || endpoint.appBrowserAllowed()) {
        assertFalse(endpoint.requiredCapabilities().isEmpty(), endpoint.routeTemplate());
      }
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
  void current_whenInspectingAppDataEndpoints_expectContractV9AppScopedCapabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.ofEntries(
            Map.entry("GET /app-data/status", List.of("app.data.read")),
            Map.entry("GET /app-data/namespaces", List.of("app.data.read")),
            Map.entry("GET /app-data/namespaces/{namespace}", List.of("app.data.read")),
            Map.entry("POST /app-data/namespaces/{namespace}/schema", List.of("app.data.write")),
            Map.entry("DELETE /app-data/namespaces/{namespace}", List.of("app.data.write")),
            Map.entry("GET /app-data/records", List.of("app.data.read")),
            Map.entry("GET /app-data/records/{namespace}/{key}", List.of("app.data.read")),
            Map.entry("POST /app-data/records", List.of("app.data.write")),
            Map.entry("DELETE /app-data/records/{namespace}/{key}", List.of("app.data.write")),
            Map.entry("GET /app-data/export", List.of("app.data.read")),
            Map.entry("POST /app-data/import", List.of("app.data.write")));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(9, endpoint.sinceContractVersion(), key);
      assertEquals("app-data", endpoint.routeFamily(), key);
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
      PlatformApiStabilityLevel expectedStability =
          expectedCapabilities.get(key).isEmpty()
              ? PlatformApiStabilityLevel.OPERATOR_ONLY
              : PlatformApiStabilityLevel.EXPERIMENTAL;
      assertEquals(expectedStability, endpoint.stability(), key);
      assertTrue(endpoint.appProcessAllowed(), key);
      assertTrue(endpoint.appBrowserAllowed(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void current_whenInspectingAppServiceEndpoints_expectContractV12AndV16Capabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.ofEntries(
            Map.entry("GET /app-services", List.of("app.services.read")),
            Map.entry("GET /app-services/audit", List.of()),
            Map.entry("GET /app-services/grants", List.of("app.services.read")),
            Map.entry("GET /app-services/dependencies", List.of("app.services.read")),
            Map.entry(
                "GET /app-services/dependencies/consumers/{consumerAppId}",
                List.of("app.services.read")),
            Map.entry("GET /app-services/grant-bundles", List.of("app.services.read")),
            Map.entry("POST /app-services/grant-bundles", List.of("app.services.call")),
            Map.entry("POST /app-services/grant-bundles/{bundleId}/approve", List.of()),
            Map.entry("POST /app-services/grant-bundles/{bundleId}/reject", List.of()),
            Map.entry("POST /app-services/grant-bundles/{bundleId}/renew", List.of()),
            Map.entry("POST /app-services/grants", List.of("app.services.call")),
            Map.entry("POST /app-services/grants/{grantId}/approve", List.of()),
            Map.entry("POST /app-services/grants/{grantId}/revoke", List.of("app.services.call")),
            Map.entry("GET /app-services/{providerAppId}/services", List.of("app.services.read")),
            Map.entry(
                "GET /app-services/{providerAppId}/services/{serviceId}",
                List.of("app.services.read")),
            Map.entry(
                "POST /app-services/{providerAppId}/services/{serviceId}/invoke",
                List.of("app.services.call")));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(
          key.contains("dependencies") || key.contains("grant-bundles") ? 16 : 12,
          endpoint.sinceContractVersion(),
          key);
      assertEquals("app-services", endpoint.routeFamily(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
      if (key.endsWith("/approve")
          || key.endsWith("/reject")
          || key.endsWith("/renew")
          || key.equals("GET /app-services/audit")) {
        assertEquals(PlatformApiStabilityLevel.OPERATOR_ONLY, endpoint.stability(), key);
        assertTrue(endpoint.hostOperatorBypassAllowed(), key);
        assertFalse(endpoint.appProcessAllowed(), key);
        assertFalse(endpoint.appBrowserAllowed(), key);
      } else if (key.equals("POST /app-services/grants")
          || key.equals("POST /app-services/grant-bundles")
          || key.equals("POST /app-services/{providerAppId}/services/{serviceId}/invoke")) {
        assertEquals(PlatformApiStabilityLevel.EXPERIMENTAL, endpoint.stability(), key);
        assertEquals(
            key.equals("POST /app-services/grant-bundles"),
            endpoint.hostOperatorBypassAllowed(),
            key);
        assertTrue(endpoint.appProcessAllowed(), key);
        assertTrue(endpoint.appBrowserAllowed(), key);
      } else {
        assertEquals(PlatformApiStabilityLevel.EXPERIMENTAL, endpoint.stability(), key);
      }
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void endpointFor_whenDependencyConsumerIdIsServices_expectDisambiguatedContractRoute() {
    PlatformApiContract contract = PlatformApiContract.current();

    PlatformApiEndpointDescriptor dependencyRead =
        contract.endpointFor(
            "GET",
            List.of("app-services", "dependencies", "consumers", "services"),
            PlatformApiPrincipalType.APP_BROWSER);
    PlatformApiEndpointDescriptor providerList =
        contract.endpointFor(
            "GET",
            List.of("app-services", "dependencies", "services"),
            PlatformApiPrincipalType.APP_BROWSER);

    assertNotNull(dependencyRead);
    assertNotNull(providerList);
    assertEquals(
        "/app-services/dependencies/consumers/{consumerAppId}", dependencyRead.routeTemplate());
    assertEquals("app-services.dependencies.read", dependencyRead.actionLabel());
    assertEquals(List.of("app.services.read"), dependencyRead.requiredCapabilities());
    assertEquals("/app-services/{providerAppId}/services", providerList.routeTemplate());
    assertEquals("app-services.provider.list", providerList.actionLabel());
    assertEquals(List.of("app.services.read"), providerList.requiredCapabilities());
  }

  @Test
  void current_whenInspectingTrustGraphExchangeEndpoints_expectContractV10Capabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.of(
            "POST /trust-graph/import-uri",
            List.of("content.fetch", "trust.write"),
            "GET /trust-graph/audit",
            List.of("trust.read"));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(10, endpoint.sinceContractVersion(), key);
      assertEquals("trust-graph", endpoint.routeFamily(), key);
      assertEquals(PlatformApiStabilityLevel.EXPERIMENTAL, endpoint.stability(), key);
      assertTrue(endpoint.appProcessAllowed(), key);
      assertTrue(endpoint.appBrowserAllowed(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void current_whenInspectingTrustGraphRcLifecycleEndpoints_expectContractV15Capabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.of(
            "GET /trust-graph/statements/{fingerprint}",
            List.of("trust.read"),
            "POST /trust-graph/statements/{fingerprint}/deprecate",
            List.of("trust.write"),
            "POST /trust-graph/statements/{fingerprint}/revoke",
            List.of("trust.write"),
            "POST /trust-graph/statements/{fingerprint}/reactivate",
            List.of("trust.write"));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(15, endpoint.sinceContractVersion(), key);
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

  @Test
  void current_whenInspectingSocialMessageEndpoint_expectBoundedVaultCapabilities() {
    PlatformApiEndpointDescriptor endpoint =
        PlatformApiContract.current().endpoints().stream()
            .filter(
                descriptor ->
                    descriptor.method().equals("POST")
                        && descriptor
                            .routeTemplate()
                            .equals("/app-vault/identities/{identityId}/social-message"))
            .findFirst()
            .orElseThrow();

    assertEquals(11, endpoint.sinceContractVersion());
    assertEquals("app-vault", endpoint.routeFamily());
    assertEquals("app-vault.identities.social-message", endpoint.actionLabel());
    assertTrue(endpoint.appProcessAllowed());
    assertTrue(endpoint.appBrowserAllowed());
    assertEquals(
        List.of("vault.identities.read", "vault.identities.use"), endpoint.requiredCapabilities());
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
    if (endpoint.routeTemplate().equals("/trust-graph/statements/{fingerprint}")
        || endpoint.routeTemplate().startsWith("/trust-graph/statements/{fingerprint}/")) {
      return 15;
    }
    if (endpoint.routeTemplate().equals("/trust-graph/import-uri")
        || endpoint.routeTemplate().equals("/trust-graph/audit")) {
      return 10;
    }
    if (endpoint.routeTemplate().equals("/app-vault/identities/{identityId}/social-message")) {
      return 11;
    }
    if (endpoint.routeTemplate().startsWith("/app-services/dependencies")
        || endpoint.routeTemplate().startsWith("/app-services/grant-bundles")) {
      return 16;
    }
    if (endpoint.routeTemplate().startsWith("/app-services")) {
      return 12;
    }
    if (endpoint.routeTemplate().startsWith("/trust-graph")
        || endpoint.routeTemplate().equals("/app-vault/identities/{identityId}/trust-statement")) {
      return 7;
    }
    if (endpoint.routeTemplate().startsWith("/content/subscriptions")) {
      return 8;
    }
    if (endpoint.routeTemplate().startsWith("/app-data")) {
      return 9;
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
        || endpoint.routeTemplate().startsWith("/app-services")) {
      if (!endpoint.appProcessAllowed() && !endpoint.appBrowserAllowed()) {
        return PlatformApiStabilityLevel.OPERATOR_ONLY;
      }
      return PlatformApiStabilityLevel.EXPERIMENTAL;
    }
    if (endpoint.routeTemplate().startsWith("/identity-vault")) {
      return PlatformApiStabilityLevel.OPERATOR_ONLY;
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

  private static List<PlatformApiEndpointDescriptor> endpointsWithFutureStableQueueView() {
    java.util.ArrayList<PlatformApiEndpointDescriptor> endpoints =
        new java.util.ArrayList<>(PlatformApiContract.current().endpoints());
    endpoints.add(
        new PlatformApiEndpointDescriptor(
            "queue",
            "GET",
            "/queue/future",
            "queue.future",
            List.of(PlatformApiCapabilities.QUEUE_READ),
            true,
            true,
            true,
            PlatformApiStabilityLevel.STABLE,
            PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION + 1,
            null,
            "Read a future queue view."));
    return endpoints;
  }

  private static String contractJsonWithoutStableBaseline(int contractVersion) {
    LinkedHashMap<String, Object> contract =
        new LinkedHashMap<>(PlatformApiContractJson.toJsonValue(PlatformApiContract.current()));
    contract.put("contractVersion", contractVersion);
    contract.remove("stableBaseline");
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put("contract", contract);
    return PlatformApiJsonWriter.write(envelope);
  }
}
