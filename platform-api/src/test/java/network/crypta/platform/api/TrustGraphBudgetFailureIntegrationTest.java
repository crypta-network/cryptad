package network.crypta.platform.api;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetConfig;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetOperation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetScope;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetUsage;
import network.crypta.platform.api.networkbudget.FileAppNetworkBudgetStore;
import network.crypta.platform.api.networkbudget.RuntimeWorkObservation;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.trustgraph.FileTrustGraphStore;
import network.crypta.platform.trustgraph.TrustAnchor;
import network.crypta.platform.trustgraph.TrustDocumentTypes;
import network.crypta.platform.trustgraph.TrustGraphException;
import network.crypta.platform.trustgraph.TrustGraphQuery;
import network.crypta.platform.trustgraph.TrustGraphScorer;
import network.crypta.platform.trustgraph.TrustGraphStore;
import network.crypta.platform.trustgraph.TrustIssuer;
import network.crypta.platform.trustgraph.TrustSignatureEnvelope;
import network.crypta.platform.trustgraph.TrustStatementDocument;
import network.crypta.platform.trustgraph.TrustStatementFingerprint;
import network.crypta.platform.trustgraph.TrustStatementPayload;
import network.crypta.platform.trustgraph.TrustSubject;
import network.crypta.platform.trustgraph.TrustSubjectKind;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.runtime.spi.ContentFetchPort;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalAnswers.delegatesTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

/** Native handler/port seam tests; app session authentication is covered by the router tests. */
class TrustGraphBudgetFailureIntegrationTest {
  private static final String APP = "budget-importer";
  private static final String OTHER = "budget-control";
  private static final String URI = "CHK@PR309_PRIVATE_SOURCE_CANARY";
  private static final Instant NOW = Instant.parse("2026-09-14T00:00:00Z");
  private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void exhaustedImportScopeDeniesBeforeChildFetchAndPreservesOtherAppGraph(
      boolean global, @TempDir Path root) throws Exception {
    var fixture = fixture(root, limits(global ? 10 : 1, global ? 1 : 10, 10));
    String existingApp = global ? OTHER : APP;
    fixture.handler().importStatement(Map.of("document", List.of(document())), existingApp);
    long priorSequence = fixture.budget().observation().snapshot().lastSequence();
    var calls = new AtomicInteger();
    var handler = fixture.handler();
    var parameters = uriParameters();
    var fetch = bytesPort(new byte[0], calls);

    var failure =
        assertThrows(PlatformApiException.class, () -> handler.importUri(parameters, fetch, APP));

    assertEquals("trust_graph_import_budget_exhausted", failure.errorCode());
    assertEquals(0, calls.get());
    assertEquals(1, new FileTrustGraphStore(root.resolve("graph")).statementCount());
    assertEquals(1, count(root, existingApp, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
    assertEquals(0, count(root, APP, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
    var segment =
        fixture.budget().observation().snapshot().events().stream()
            .filter(event -> event.sequence() > priorSequence)
            .toList();
    assertTrue(
        segment.stream()
            .anyMatch(event -> event.kind() == RuntimeWorkObservation.Kind.BUDGET_RATE_DENIED));
    assertFalse(
        segment.stream()
            .anyMatch(event -> event.kind() == RuntimeWorkObservation.Kind.FETCH_INVOKED));
    assertReleased(fixture);
  }

  @Test
  void anotherAppsGlobalFetchChargeDeniesChildAndReleasesReservedImport(@TempDir Path root)
      throws Exception {
    var fixture = fixture(root, limits(10, 10, 1));
    try (var lease =
        fixture
            .budget()
            .acquire(OTHER, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH)
            .lease()) {
      assertTrue(lease.active());
    }
    var calls = new AtomicInteger();
    var handler = fixture.handler();
    var parameters = uriParameters();
    var fetch = bytesPort(new byte[0], calls);

    var failure =
        assertThrows(PlatformApiException.class, () -> handler.importUri(parameters, fetch, APP));

    assertEquals("content_fetch_budget_exhausted", failure.errorCode());
    assertEquals(0, calls.get());
    assertEquals(0, count(root, APP, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
    assertEquals(0, count(root, APP, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
    assertEquals(1, count(root, OTHER, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
    assertEquals(
        1,
        count(root, AppNetworkBudgetScope.GLOBAL, AppNetworkBudgetOperation.CONTENT_FETCH_GLOBAL));
    assertEquals(0, fixture.graph().statementCount());
    assertKind(fixture, RuntimeWorkObservation.Kind.RATE_RESERVATION_RELEASED);
    assertReleased(fixture);
  }

  @Test
  void slowUriFetchHoldsImportWhileAnotherAppCanImport(@TempDir Path root) throws Exception {
    var fixture = fixture(root, limits(10, 10, 10));
    String body = document();
    var entered = new CountDownLatch(1);
    var finish = new CountDownLatch(1);
    ContentFetchPort slow =
        request -> {
          entered.countDown();
          try {
            if (!finish.await(10, TimeUnit.SECONDS)) {
              throw new ContentFetchException(
                  ContentFetchException.CATALOG_FETCH_TIMEOUT, "bounded test timeout");
            }
          } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
            throw new ContentFetchException(
                ContentFetchException.CATALOG_FETCH_FAILED, "bounded test interrupted");
          }
          return new BoundedContentFetchResult(
              body.getBytes(StandardCharsets.UTF_8), request.uri(), null, null);
        };

    try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
      var request = executor.submit(() -> fixture.handler().importUri(uriParameters(), slow, APP));
      try {
        assertTrue(entered.await(10, TimeUnit.SECONDS));
        assertEquals(4, fixture.budget().diagnostics().activeFamilyLeases());
        assertEquals(2, fixture.budget().diagnostics().reservedFamilyRates());
        var handler = fixture.handler();
        var parameters = Map.of("document", List.of(body));
        var denied =
            assertThrows(
                PlatformApiException.class, () -> handler.importStatement(parameters, APP));
        assertEquals("trust_graph_import_concurrency_limited", denied.errorCode());
        fixture.handler().importStatement(Map.of("document", List.of(body)), OTHER);
        assertEquals(1, fixture.graph().statementCount());
        assertEquals(0, count(root, OTHER, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
      } finally {
        finish.countDown();
      }
      request.get(10, TimeUnit.SECONDS);
    }

    assertEquals(1, count(root, APP, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
    assertEquals(1, count(root, OTHER, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
    assertEquals(
        2, count(root, AppNetworkBudgetScope.GLOBAL, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
    assertKind(fixture, RuntimeWorkObservation.Kind.GRAPH_STORE_DUPLICATE);
    assertReleased(fixture);
  }

  @ParameterizedTest
  @ValueSource(strings = {"invalid-uri", "invalid-utf8", "oversized"})
  void rejectedInputChargesOnlyAdmittedFetchAndNeverCommitsImport(
      String scenario, @TempDir Path root) throws Exception {
    var fixture = fixture(root, limits(10, 10, 10));
    var calls = new AtomicInteger();
    byte[] body = scenario.equals("invalid-utf8") ? new byte[] {(byte) 0xc3, 0x28} : new byte[65];
    var parameters =
        Map.of(
            "uri",
            List.of(scenario.equals("invalid-uri") ? "file:/private-canary" : URI),
            "maxBytes",
            List.of("64"));
    var handler = fixture.handler();
    var fetch = bytesPort(body, calls);

    assertThrows(PlatformApiException.class, () -> handler.importUri(parameters, fetch, APP));

    int expectedFetch = scenario.equals("invalid-uri") ? 0 : 1;
    assertEquals(expectedFetch, calls.get());
    assertEquals(
        expectedFetch, count(root, APP, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
    assertEquals(
        expectedFetch,
        count(root, AppNetworkBudgetScope.GLOBAL, AppNetworkBudgetOperation.CONTENT_FETCH_GLOBAL));
    assertEquals(0, count(root, APP, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
    assertEquals(
        0, count(root, AppNetworkBudgetScope.GLOBAL, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
    assertEquals(0, new FileTrustGraphStore(root.resolve("graph")).statementCount());
    assertFalse(kinds(fixture).contains(RuntimeWorkObservation.Kind.GRAPH_STORE_ATTEMPT));
    assertFalse(
        fixture.budget().observation().snapshot().toString().contains("PRIVATE_SOURCE_CANARY"));
    assertReleased(fixture);
  }

  @Test
  void staleFingerprintRetainsBothChargesWithoutStoreAttempt(@TempDir Path root) throws Exception {
    var fixture = fixture(root, limits(10, 10, 10));
    var parameters =
        Map.of("uri", List.of(URI), "expectedDocumentFingerprint", List.of("0".repeat(64)));
    var handler = fixture.handler();
    var fetch = bytesPort(document().getBytes(StandardCharsets.UTF_8), new AtomicInteger());

    assertThrows(PlatformApiException.class, () -> handler.importUri(parameters, fetch, APP));

    assertComposedCharges(root);
    assertEquals(0, fixture.graph().statementCount());
    assertKind(fixture, RuntimeWorkObservation.Kind.FINGERPRINT_REJECTED);
    assertFalse(kinds(fixture).contains(RuntimeWorkObservation.Kind.GRAPH_STORE_ATTEMPT));
    assertReleased(fixture);
  }

  @Test
  void invalidSignatureIsDurablyRetainedButCannotScoreEvenWithAnchor(@TempDir Path root)
      throws Exception {
    var fixture = fixture(root, limits(10, 10, 10));
    fixture
        .handler()
        .importUri(
            uriParameters(),
            bytesPort(document().getBytes(StandardCharsets.UTF_8), new AtomicInteger()),
            APP);
    var restarted = new FileTrustGraphStore(root.resolve("graph"));
    var stored = restarted.statements().getFirst();
    restarted.addAnchor(
        new TrustAnchor(
            stored.document().payload().issuer().publicKeyFingerprint(),
            "synthetic",
            "manual",
            NOW));

    var score =
        new TrustGraphScorer(restarted, CLOCK)
            .score(
                new TrustGraphQuery(
                    TrustSubjectKind.PROFILE, "PR309_PRIVATE_SUBJECT_CANARY", "profile"));

    assertEquals(1, restarted.statementCount());
    assertFalse(stored.signatureVerified());
    assertEquals(1, score.evidenceCount());
    assertEquals(0, score.contributingEvidenceCount());
    assertEquals("unknown", score.status());
    assertKind(fixture, RuntimeWorkObservation.Kind.GRAPH_STORE_UNVERIFIED);
    assertComposedCharges(root);
    assertReleased(fixture);
  }

  @Test
  void unavailableGraphWriteRetainsChargesAndReleasesHolds(@TempDir Path root) throws Exception {
    var fixture = fixture(root, limits(10, 10, 10));
    Files.delete(root.resolve("graph/statements"));
    Files.writeString(root.resolve("graph/statements"), "owned-test-path-blocker");
    var handler = fixture.handler();
    var parameters = uriParameters();
    var fetch = bytesPort(document().getBytes(StandardCharsets.UTF_8), new AtomicInteger());

    assertThrows(PlatformApiException.class, () -> handler.importUri(parameters, fetch, APP));

    assertComposedCharges(root);
    assertEquals(0, fixture.graph().statementCount());
    assertKind(fixture, RuntimeWorkObservation.Kind.GRAPH_STORE_ATTEMPT);
    assertKind(fixture, RuntimeWorkObservation.Kind.GRAPH_STORE_UNKNOWN);
    assertFalse(kinds(fixture).contains(RuntimeWorkObservation.Kind.REQUEST_SUCCEEDED));
    assertReleased(fixture);
  }

  @Test
  void lostStoreAcknowledgmentPreservesDurableStatementAndChargesRetry(@TempDir Path root)
      throws Exception {
    var fixture = fixture(root, limits(10, 10, 10));
    var store = mock(TrustGraphStore.class, delegatesTo(fixture.graph()));
    var failAfterWrite = new AtomicBoolean(true);
    doAnswer(
            invocation -> {
              var result =
                  fixture
                      .graph()
                      .importStatement(
                          invocation.getArgument(0),
                          invocation.getArgument(1),
                          invocation.getArgument(2),
                          invocation.getArgument(3),
                          invocation.getArgument(4));
              if (failAfterWrite.getAndSet(false)) {
                throw new TrustGraphException(
                    "trust_graph_unavailable", "Synthetic store acknowledgment unavailable.");
              }
              return result;
            })
        .when(store)
        .importStatement(any(), any(), any(), any(), any());
    var handler = new TrustGraphApiHandler(store, CLOCK, fixture.budget());
    byte[] bytes = document().getBytes(StandardCharsets.UTF_8);
    var parameters = uriParameters();
    var fetch = bytesPort(bytes, new AtomicInteger());

    assertThrows(PlatformApiException.class, () -> handler.importUri(parameters, fetch, APP));

    assertEquals(1, new FileTrustGraphStore(root.resolve("graph")).statementCount());
    assertComposedCharges(root);
    assertKind(fixture, RuntimeWorkObservation.Kind.GRAPH_STORE_UNKNOWN);
    assertFalse(kinds(fixture).contains(RuntimeWorkObservation.Kind.GRAPH_STORE_IMPORTED));
    assertFalse(kinds(fixture).contains(RuntimeWorkObservation.Kind.REQUEST_SUCCEEDED));
    assertReleased(fixture);

    handler.importUri(uriParameters(), bytesPort(bytes, new AtomicInteger()), APP);

    assertEquals(1, new FileTrustGraphStore(root.resolve("graph")).statementCount());
    assertEquals(2, count(root, APP, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
    assertEquals(2, count(root, APP, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
    assertKind(fixture, RuntimeWorkObservation.Kind.GRAPH_STORE_DUPLICATE);
    assertReleased(fixture);
  }

  private static Fixture fixture(Path root, AppNetworkBudgetConfig config) {
    var budget =
        new AppNetworkBudgetService(
            new FileAppNetworkBudgetStore(root.resolve("budget")), config, CLOCK);
    var graph = new FileTrustGraphStore(root.resolve("graph"));
    return new Fixture(budget, graph, new TrustGraphApiHandler(graph, CLOCK, budget));
  }

  private static AppNetworkBudgetConfig limits(int appImport, int globalImport, int globalFetch) {
    return new AppNetworkBudgetConfig(
        10, globalFetch, 2, 8, 10, 20, 1, 4, appImport, globalImport, 1, 4);
  }

  private static ContentFetchPort bytesPort(byte[] bytes, AtomicInteger calls) {
    return request -> {
      calls.incrementAndGet();
      return new BoundedContentFetchResult(bytes, request.uri(), null, null);
    };
  }

  private static Map<String, List<String>> uriParameters() {
    return Map.of("uri", List.of(URI));
  }

  private static int count(Path root, String scope, AppNetworkBudgetOperation operation)
      throws Exception {
    return new FileAppNetworkBudgetStore(root.resolve("budget"))
        .read(scope, operation)
        .map(AppNetworkBudgetUsage::count)
        .orElse(0);
  }

  private static void assertComposedCharges(Path root) throws Exception {
    assertEquals(1, count(root, APP, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
    assertEquals(
        1,
        count(root, AppNetworkBudgetScope.GLOBAL, AppNetworkBudgetOperation.CONTENT_FETCH_GLOBAL));
    assertEquals(1, count(root, APP, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
    assertEquals(
        1, count(root, AppNetworkBudgetScope.GLOBAL, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
  }

  private static List<RuntimeWorkObservation.Kind> kinds(Fixture fixture) {
    return fixture.budget().observation().snapshot().events().stream()
        .map(RuntimeWorkObservation.Event::kind)
        .toList();
  }

  private static void assertKind(Fixture fixture, RuntimeWorkObservation.Kind kind) {
    assertTrue(kinds(fixture).contains(kind));
  }

  private static void assertReleased(Fixture fixture) {
    assertTrue(fixture.budget().diagnostics().valid());
    assertEquals(0, fixture.budget().diagnostics().activeFamilyLeases());
    assertEquals(0, fixture.budget().diagnostics().reservedFamilyRates());
  }

  private static String document() throws Exception {
    var key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var issuer =
        new TrustIssuer(
            "PR309_PRIVATE_ISSUER_CANARY",
            TrustStatementFingerprint.sha256Hex(key.getPublic().getEncoded()),
            Base64.getEncoder().encodeToString(key.getPublic().getEncoded()),
            null);
    var payload =
        new TrustStatementPayload(
            issuer,
            new TrustSubject(TrustSubjectKind.PROFILE, "PR309_PRIVATE_SUBJECT_CANARY", null),
            "profile",
            50,
            80,
            "PR309_PRIVATE_BODY_CANARY",
            List.of(),
            NOW.minusSeconds(60),
            null);
    var document =
        new TrustStatementDocument(
            TrustDocumentTypes.TRUST_STATEMENT_V1,
            payload,
            new TrustSignatureEnvelope(
                TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
                TrustDocumentTypes.TRUST_STATEMENT_V1,
                Base64.getEncoder().encodeToString(new byte[64])));
    return PlatformApiJsonWriter.write(document.toJson());
  }

  private record Fixture(
      AppNetworkBudgetService budget, FileTrustGraphStore graph, TrustGraphApiHandler handler) {}
}
