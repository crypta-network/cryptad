package network.crypta.platform.api;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetConfig;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetOperation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetScope;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetStore;
import network.crypta.platform.api.networkbudget.FileAppNetworkBudgetStore;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.trustgraph.FileTrustGraphStore;
import network.crypta.platform.trustgraph.TrustDocumentTypes;
import network.crypta.platform.trustgraph.TrustGraphException;
import network.crypta.platform.trustgraph.TrustGraphStore;
import network.crypta.platform.trustgraph.TrustGraphStoreConfig;
import network.crypta.platform.trustgraph.TrustIssuer;
import network.crypta.platform.trustgraph.TrustSignatureEnvelope;
import network.crypta.platform.trustgraph.TrustStatementCanonicalizer;
import network.crypta.platform.trustgraph.TrustStatementDocument;
import network.crypta.platform.trustgraph.TrustStatementFingerprint;
import network.crypta.platform.trustgraph.TrustStatementPayload;
import network.crypta.platform.trustgraph.TrustSubject;
import network.crypta.platform.trustgraph.TrustSubjectKind;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchPort;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.AdditionalAnswers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Controlled file-backed tests; advancing the service clock is not installed elapsed-time evidence.
 */
class TrustGraphStorageBudgetTest {
  private static final String APP = "storage-fixture";
  private static final String SOURCE_MANUAL = "manual";
  private static final String BUDGET_DIRECTORY = "budget";
  private static final String SELECTED_FINGERPRINT = "selectedFingerprint";
  private static final String GRAPH_STORE_ATTEMPT = "GRAPH_STORE_ATTEMPT";
  private static final String GRAPH_STORE_UNKNOWN = "GRAPH_STORE_UNKNOWN";
  private static final String GRAPH_STORE_IMPORTED = "GRAPH_STORE_IMPORTED";
  private static final String AFTER = "after";
  private static final String SELECTED_SUBSCRIPTION = "selected-subscription";
  private static final String GRAPH_AFTER = "graphAfter";
  private static final String REQUEST_STATUS = "requestStatus";
  private static final String IMPORTED = "imported";
  private static final String FIXTURE_URI = "CHK@fixture";
  private static final String SOURCE_LABEL = "sourceLabel";
  private static final String SUBSCRIPTION_ID = "subscriptionId";

  private static final Instant START = Instant.parse("2026-05-17T00:59:59Z");
  @TempDir Path root;

  @ParameterizedTest
  @CsvSource({
    "false,false,false", "false,false,true", "false,true,false", "false,true,true",
    "true,false,false", "true,false,true", "true,true,false", "true,true,true"
  })
  void graphFaultPreservesChargesAndReconcilesSelectedMetadata(
      boolean uri, boolean afterWrite, boolean duplicate) throws Exception {
    var clock = new MutableClock(START);
    var graph = graph(clock);
    var selected = signedStatement(50);
    var unrelated = signedStatement(25);
    graph.importStatement(unrelated, SOURCE_MANUAL, null, "unrelated");
    if (duplicate) {
      graph.importStatement(selected, SOURCE_MANUAL, null, "before");
    }
    var before = graph.statements();
    clock.now = START.plusSeconds(10);
    var faultEnabled = new AtomicBoolean(true);
    var attempts = new AtomicInteger();
    TrustGraphStore fault = graphFault(graph, faultEnabled, attempts, afterWrite);
    var budgets = budgets(clock, new FileAppNetworkBudgetStore(root.resolve(BUDGET_DIRECTORY)), 10);
    var handler = new TrustGraphApiHandler(fault, clock, budgets);
    var evidence = evidence("graph-store-unavailable", budgets);
    evidence.put(SELECTED_FINGERPRINT, TrustStatementFingerprint.documentFingerprint(selected));
    evidence.put("graphBefore", graphView(before));
    evidence.put("cutPoint", afterWrite ? "after-delegate" : "before-delegate");

    var failure = assertThrows(PlatformApiException.class, () -> invoke(handler, uri, selected));

    assertGraphFaultFailure(failure, attempts, budgets, uri);
    var reopened = graph(clock);
    assertEquals(find(before, unrelated), find(reopened.statements(), unrelated));
    if (afterWrite) {
      var persisted = find(reopened.statements(), selected);
      assertNotNull(persisted);
      assertTrue(persisted.signatureVerified());
      assertEquals(selected, persisted.document());
      assertEquals(AFTER, persisted.sourceLabel());
      assertEquals(uri ? "content-fetch" : SOURCE_MANUAL, persisted.source());
      assertEquals(clock.instant(), persisted.updatedAt());
      assertEquals(duplicate ? START : clock.instant(), persisted.importedAt());
      assertEquals(SELECTED_SUBSCRIPTION, persisted.subscriptionId());
    } else {
      assertEquals(java.util.Set.copyOf(before), java.util.Set.copyOf(reopened.statements()));
    }
    assertEquals(
        java.util.Set.copyOf(reopened.statements()), java.util.Set.copyOf(graph.statements()));

    evidence.put(AFTER, rateView(budgets));
    evidence.put(GRAPH_AFTER, graphView(reopened.statements()));
    evidence.put("failedLastSequence", budgets.observation().snapshot().lastSequence());
    evidence.put(REQUEST_STATUS, failure.statusCode());
    faultEnabled.set(false);
    clock.now = clock.now.plusSeconds(1);
    var recovered = invoke(handler, uri, selected);

    assertEquals(!(afterWrite || duplicate), recovered.get(IMPORTED));
    assertEquals(true, recovered.get("signatureVerified"));
    assertEquals(2, attempts.get());
    assertRates(uri, 2);
    assertReleased(budgets);
    assertEquals("REQUEST_SUCCEEDED", kinds(budgets).getLast());
    assertEquals(find(before, unrelated), find(graph(clock).statements(), unrelated));
    evidence.put("recoveryAfter", rateView(budgets));
    evidence.put("graphRecovery", graphView(graph(clock).statements()));
    evidence.put("recoveryStatus", 200);
    export("graph-" + uri + "-" + afterWrite + "-" + duplicate, evidence, budgets);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void auditFailureAfterReturnedImportKeepsKnownGraphVerdict(boolean rejectAuditAlsoFails)
      throws Exception {
    var clock = new MutableClock(START);
    var graph = graph(clock);
    var audits = new AtomicInteger();
    TrustGraphStore fault =
        mock(
            TrustGraphStore.class,
            invocation -> {
              if (invocation.getMethod().getName().equals("appendAuditEvent")
                  && (audits.incrementAndGet() == 1 || rejectAuditAlsoFails)) {
                throw unavailable();
              }
              return AdditionalAnswers.delegatesTo(graph).answer(invocation);
            });
    var budgets = budgets(clock, new FileAppNetworkBudgetStore(root.resolve(BUDGET_DIRECTORY)), 10);
    var handler = new TrustGraphApiHandler(fault, clock, budgets);
    var statement = signedStatement(50);

    if (rejectAuditAlsoFails) {
      // The second audit exception escapes the handler's mapping catch; do not hide this behavior.
      assertThrows(TrustGraphException.class, () -> invoke(handler, false, statement));
    } else {
      assertEquals(
          503,
          assertThrows(PlatformApiException.class, () -> invoke(handler, false, statement))
              .statusCode());
    }

    assertEquals(2, audits.get());
    assertTrue(kinds(budgets).contains(GRAPH_STORE_IMPORTED));
    assertFalse(kinds(budgets).contains(GRAPH_STORE_UNKNOWN));
    assertEquals("REQUEST_FAILED", kinds(budgets).getLast());
    assertTrue(find(graph(clock).statements(), statement).signatureVerified());
    assertEquals(rejectAuditAlsoFails ? 0 : 1, graph(clock).auditEvents(10).size());
    assertRates(false, 1);
    assertReleased(budgets);
  }

  @ParameterizedTest
  @CsvSource({
    "false,1,false", "false,1,true", "false,2,false", "false,2,true",
    "true,1,false", "true,1,true", "true,2,false", "true,2,true",
    "true,3,false", "true,3,true", "true,4,false", "true,4,true"
  })
  void budgetWriteFailureNeverReachesGraphAndRetainsActualPrefix(
      boolean uri, int failedWrite, boolean afterWrite) throws Exception {
    var clock = new MutableClock(START);
    var delegate = new FileAppNetworkBudgetStore(root.resolve(BUDGET_DIRECTORY));
    var writes = new AtomicInteger();
    AppNetworkBudgetStore fault =
        mock(
            AppNetworkBudgetStore.class,
            invocation -> {
              if (invocation.getMethod().getName().equals("write")
                  && writes.incrementAndGet() == failedWrite) {
                if (afterWrite) {
                  AdditionalAnswers.delegatesTo(delegate).answer(invocation);
                }
                throw new IOException("controlled write failure");
              }
              return AdditionalAnswers.delegatesTo(delegate).answer(invocation);
            });
    var budgets = budgets(clock, fault, 10);
    var graph = graph(clock);
    var handler = new TrustGraphApiHandler(graph, clock, budgets);
    var selected = signedStatement(50);
    var evidence = evidence("partial-rate-write", budgets);
    evidence.put(SELECTED_FINGERPRINT, TrustStatementFingerprint.documentFingerprint(selected));
    evidence.put("cutPoint", afterWrite ? "after-delegate" : "before-delegate");
    evidence.put("failedWrite", failedWrite);

    var failure = assertThrows(PlatformApiException.class, () -> invoke(handler, uri, selected));

    assertEquals(failedWrite, writes.get());
    assertFalse(kinds(budgets).contains(GRAPH_STORE_ATTEMPT));
    assertFalse(kinds(budgets).contains(GRAPH_STORE_UNKNOWN));
    assertEquals(uri && failedWrite > 2, kinds(budgets).contains("FETCH_INVOKED"));
    assertFalse(kinds(budgets).contains("PARSE_SUCCEEDED"));
    assertFalse(kinds(budgets).contains("PARSE_FAILED"));
    assertEquals(0, graph(clock).statementCount());
    assertEquals(failedWrite - (afterWrite ? 0 : 1), delegate.observe(100).size());
    assertTrue(delegate.observe(100).stream().allMatch(row -> row.count() == 1));
    assertEquals(failedWrite - 1, kinds(budgets).stream().filter("RATE_CHARGED"::equals).count());
    assertFalse(
        budgets.observation().snapshot().events().stream()
            .anyMatch(
                event ->
                    event.kind().name().equals("BUDGET_COMMITTED")
                        && event.operation() == AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
    assertReleased(budgets);
    evidence.put(AFTER, rateView(budgets));
    evidence.put(REQUEST_STATUS, failure.statusCode());
    evidence.put("failedLastSequence", budgets.observation().snapshot().lastSequence());
    evidence.put(GRAPH_AFTER, graphView(graph.statements()));
    assertEquals(true, invoke(handler, uri, selected).get(IMPORTED));
    assertReleased(budgets);
    evidence.put("recoveryAfter", rateView(budgets));
    evidence.put("graphRecovery", graphView(graph(clock).statements()));
    evidence.put("recoveryStatus", 200);
    export("rate-" + uri + "-" + failedWrite + "-" + afterWrite, evidence, budgets);
  }

  @ParameterizedTest
  @CsvSource({
    "2026-05-17T00:59:59Z,2026-05-17T01:00:00Z,false",
    "2026-05-17T00:59:59Z,2026-05-17T01:00:00Z,true",
    "2026-05-17T00:59:59Z,2026-05-17T03:00:01Z,false",
    "2026-05-17T00:58:59Z,2026-05-17T00:59:01Z,false",
    "2026-05-17T00:58:10Z,2026-05-17T00:58:11Z,false",
    "2026-05-17T01:00:01Z,2026-05-17T00:59:59Z,false"
  })
  void uriCommitUsesItsOwnCurrentHourAfterRealFetchComposition(
      String reservedAt, String committedAt, boolean contested) throws Exception {
    var before = Instant.parse(reservedAt);
    var after = Instant.parse(committedAt);
    var clock = new MutableClock(before);
    var store = new FileAppNetworkBudgetStore(root.resolve(BUDGET_DIRECTORY));
    var budgets = budgets(clock, store, 1);
    var graph = graph(clock);
    var handler = new TrustGraphApiHandler(graph, clock, budgets);
    var selected = signedStatement(50);
    var fetches = new AtomicInteger();
    var evidence = evidence("window-crossing", budgets);
    evidence.put(SELECTED_FINGERPRINT, TrustStatementFingerprint.documentFingerprint(selected));
    evidence.put("reservedAt", before.toString());
    evidence.put("committedAt", after.toString());
    evidence.put("contested", contested);
    ContentFetchPort fetch =
        request -> {
          fetches.incrementAndGet();
          assertEquals(2, budgets.diagnostics().reservedFamilyRates());
          assertTrue(budgets.diagnostics().activeFamilyLeases() >= 2);
          evidence.put("during", rateView(budgets));
          evidence.put("duringLastSequence", budgets.observation().snapshot().lastSequence());
          clock.now = after;
          if (contested) {
            var competitor = budgets.acquire(APP, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);
            assertTrue(competitor.allowed());
            competitor.lease().close();
          }
          return content(selected, request.uri());
        };

    if (contested) {
      assertEquals(
          429,
          assertThrows(
                  PlatformApiException.class,
                  () -> handler.importUri(Map.of("uri", List.of(FIXTURE_URI)), fetch, APP))
              .statusCode());
      assertFalse(kinds(budgets).contains(GRAPH_STORE_ATTEMPT));
      assertEquals(0, graph.statementCount());
    } else {
      assertEquals(
          true, handler.importUri(Map.of("uri", List.of(FIXTURE_URI)), fetch, APP).get(IMPORTED));
      assertEquals(1, graph(clock).statementCount());
    }

    assertEquals(1, fetches.get());
    assertReleased(budgets);
    var reopened = new FileAppNetworkBudgetStore(root.resolve(BUDGET_DIRECTORY));
    assertEquals(4, reopened.observe(100).size());
    for (var row : reopened.observe(100)) {
      boolean imported = row.operation() == AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT;
      assertEquals(1, row.count());
      assertEquals(
          imported ? after.truncatedTo(ChronoUnit.HOURS) : before.truncatedTo(ChronoUnit.MINUTES),
          row.windowStart());
      assertEquals(imported ? 3600 : 60, row.window().toSeconds());
    }
    // Recorder wall time was never rewritten to resemble this controlled clock.
    assertTrue(
        budgets.observation().snapshot().events().stream()
            .noneMatch(event -> event.observedAt().equals(before)));
    evidence.put(AFTER, rateView(budgets));
    evidence.put(GRAPH_AFTER, graphView(graph(clock).statements()));
    evidence.put(REQUEST_STATUS, contested ? 429 : 200);
    export(
        "window-" + before.getEpochSecond() + "-" + after.getEpochSecond() + "-" + contested,
        evidence,
        budgets);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void actualStatementDirectoryFailureRetainsChargesAndRecovers(boolean uri) throws Exception {
    var clock = new MutableClock(START);
    var graph = graph(clock);
    var budgets = budgets(clock, new FileAppNetworkBudgetStore(root.resolve(BUDGET_DIRECTORY)), 10);
    var handler = new TrustGraphApiHandler(graph, clock, budgets);
    var selected = signedStatement(50);
    var directory = root.resolve("graph").resolve("statements");
    java.nio.file.Files.delete(directory);
    java.nio.file.Files.writeString(directory, "owned test obstruction");

    try {
      assertEquals(
          503,
          assertThrows(PlatformApiException.class, () -> invoke(handler, uri, selected))
              .statusCode());
      assertEquals(0, graph.statementCount());
      assertTrue(kinds(budgets).contains(GRAPH_STORE_UNKNOWN));
      assertFalse(kinds(budgets).contains(GRAPH_STORE_IMPORTED));
      assertRates(uri, 1);
      assertReleased(budgets);
    } finally {
      java.nio.file.Files.delete(directory);
      java.nio.file.Files.createDirectory(directory);
    }

    assertEquals(0, graph(clock).statementCount());
    assertEquals(true, invoke(handler, uri, selected).get(IMPORTED));
    assertTrue(find(graph(clock).statements(), selected).signatureVerified());
    assertRates(uri, 2);
    assertReleased(budgets);
  }

  private static Map<String, Object> evidence(String caseId, AppNetworkBudgetService budgets) {
    var result = new java.util.LinkedHashMap<String, Object>();
    result.put("caseId", caseId);
    result.put("evidenceClass", "controlled-native-file-backed");
    result.put("timeDomain", "service-clock-controlled-recorder-realtime");
    result.put("before", rateView(budgets));
    result.put("beforeLastSequence", budgets.observation().snapshot().lastSequence());
    return result;
  }

  private static List<Map<String, Object>> rateView(AppNetworkBudgetService budgets) {
    var diagnostics = budgets.diagnostics();
    assertTrue(diagnostics.valid());
    return diagnostics.usage().stream()
        .map(
            row -> {
              Map<String, Object> value = new java.util.LinkedHashMap<>();
              value.put("scope", budgets.observation().scope(row.appId()));
              value.put("family", row.operation().name());
              value.put("windowStart", row.windowStart().toString());
              value.put("windowSeconds", row.windowSeconds());
              value.put("count", row.count());
              value.put("lastDecision", row.lastDecision());
              value.put(
                  "lastDecisionAt",
                  row.lastDecisionAt() == null ? null : row.lastDecisionAt().toString());
              return value;
            })
        .toList();
  }

  private static List<Map<String, Object>> graphView(
      List<TrustGraphStore.StoredTrustStatement> rows) {
    return rows.stream()
        .map(
            row -> {
              Map<String, Object> value = new java.util.LinkedHashMap<>();
              value.put("documentFingerprint", row.documentFingerprint());
              value.put("payloadHash", row.payloadHash());
              value.put("signatureVerified", row.signatureVerified());
              value.put("source", row.source());
              value.put(SOURCE_LABEL, row.sourceLabel());
              value.put("sourceUriHash", row.sourceUriHash());
              value.put(SUBSCRIPTION_ID, row.subscriptionId());
              value.put("importedAt", row.importedAt().toString());
              value.put("updatedAt", row.updatedAt().toString());
              return value;
            })
        .toList();
  }

  private static void export(
      String variant, Map<String, Object> evidence, AppNetworkBudgetService budgets)
      throws Exception {
    evidence.put("variant", variant);
    evidence.put("nativeSnapshot", jsonValue(budgets.observation().snapshot()));
    evidence.put("activeFamilyLeases", budgets.diagnostics().activeFamilyLeases());
    evidence.put("reservedFamilyRates", budgets.diagnostics().reservedFamilyRates());
    Path directory = Path.of("build", "test-results", "pr318-native");
    Path output = directory.resolve(variant + ".json");
    if (directory.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      var directoryPermissions =
          java.nio.file.attribute.PosixFilePermissions.fromString("rwx------");
      var filePermissions = java.nio.file.attribute.PosixFilePermissions.fromString("rw-------");
      java.nio.file.Files.createDirectories(
          directory,
          java.nio.file.attribute.PosixFilePermissions.asFileAttribute(directoryPermissions));
      java.nio.file.Files.setPosixFilePermissions(directory, directoryPermissions);
      if (!java.nio.file.Files.exists(output)) {
        java.nio.file.Files.createFile(
            output, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(filePermissions));
      }
      java.nio.file.Files.setPosixFilePermissions(output, filePermissions);
    } else {
      java.nio.file.Files.createDirectories(directory);
    }
    java.nio.file.Files.writeString(output, PlatformApiJsonWriter.write(evidence));
  }

  private static Object jsonValue(Object value) throws Exception {
    if (value == null
        || value instanceof Number
        || value instanceof Boolean
        || value instanceof String) {
      return value;
    }
    if (value instanceof Instant || value instanceof Enum<?>) {
      return value.toString();
    }
    if (value instanceof List<?> list) {
      var converted = new java.util.ArrayList<>();
      for (var item : list) {
        converted.add(jsonValue(item));
      }
      return converted;
    }
    if (value.getClass().isRecord()) {
      var converted = new java.util.LinkedHashMap<String, Object>();
      for (var component : value.getClass().getRecordComponents()) {
        converted.put(component.getName(), jsonValue(component.getAccessor().invoke(value)));
      }
      return converted;
    }
    throw new IllegalArgumentException("Unsupported native fixture field");
  }

  private void assertGraphFaultFailure(
      PlatformApiException failure,
      AtomicInteger attempts,
      AppNetworkBudgetService budgets,
      boolean uri)
      throws IOException {
    assertEquals(503, failure.statusCode());
    assertEquals(1, attempts.get());
    var failedKinds = kinds(budgets);
    assertTrue(failedKinds.contains(GRAPH_STORE_ATTEMPT));
    assertTrue(failedKinds.contains(GRAPH_STORE_UNKNOWN));
    assertFalse(failedKinds.contains(GRAPH_STORE_IMPORTED));
    assertFalse(failedKinds.contains("GRAPH_STORE_DUPLICATE"));
    assertEquals("REQUEST_FAILED", failedKinds.getLast());
    assertRates(uri, 1);
    assertReleased(budgets);
  }

  private FileTrustGraphStore graph(Clock clock) {
    return new FileTrustGraphStore(root.resolve("graph"), TrustGraphStoreConfig.defaults(), clock);
  }

  private static AppNetworkBudgetService budgets(
      Clock clock, AppNetworkBudgetStore store, int importLimit) {
    return new AppNetworkBudgetService(
        store,
        new AppNetworkBudgetConfig(20, 100, 4, 16, 48, 1024, 2, 8, importLimit, 100, 3, 8),
        clock);
  }

  private static Map<String, Object> invoke(
      TrustGraphApiHandler handler, boolean uri, TrustStatementDocument statement) {
    if (uri) {
      return handler.importUri(
          Map.of(
              "uri",
              List.of(FIXTURE_URI),
              SOURCE_LABEL,
              List.of(AFTER),
              SUBSCRIPTION_ID,
              List.of(SELECTED_SUBSCRIPTION)),
          request -> content(statement, request.uri()),
          APP);
    }
    return handler.importStatement(
        Map.of(
            "document",
            List.of(PlatformApiJsonWriter.write(statement.toJson())),
            "source",
            List.of(SOURCE_MANUAL),
            SOURCE_LABEL,
            List.of(AFTER),
            SUBSCRIPTION_ID,
            List.of(SELECTED_SUBSCRIPTION)),
        APP);
  }

  private static BoundedContentFetchResult content(TrustStatementDocument statement, String uri) {
    return new BoundedContentFetchResult(
        PlatformApiJsonWriter.write(statement.toJson()).getBytes(StandardCharsets.UTF_8),
        uri,
        uri,
        "ok");
  }

  private void assertRates(boolean uri, int count) throws IOException {
    var rows = new FileAppNetworkBudgetStore(root.resolve(BUDGET_DIRECTORY)).observe(100);
    assertEquals(uri ? 4 : 2, rows.size());
    for (String scope : List.of(APP, AppNetworkBudgetScope.GLOBAL)) {
      var row =
          rows.stream()
              .filter(
                  value ->
                      value.appId().equals(scope)
                          && value.operation() == AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT)
              .findFirst()
              .orElseThrow();
      assertEquals(count, row.count());
    }
    assertTrue(rows.stream().allMatch(row -> row.count() == count));
  }

  private static void assertReleased(AppNetworkBudgetService budgets) {
    assertTrue(budgets.diagnostics().valid());
    assertEquals(0, budgets.diagnostics().activeFamilyLeases());
    assertEquals(0, budgets.diagnostics().reservedFamilyRates());
  }

  private static List<String> kinds(AppNetworkBudgetService budgets) {
    return budgets.observation().snapshot().events().stream()
        .map(event -> event.kind().name())
        .toList();
  }

  private static TrustGraphStore.StoredTrustStatement find(
      List<TrustGraphStore.StoredTrustStatement> records, TrustStatementDocument document) {
    String fingerprint = TrustStatementFingerprint.documentFingerprint(document);
    return records.stream()
        .filter(statement -> statement.documentFingerprint().equals(fingerprint))
        .findFirst()
        .orElse(null);
  }

  private static TrustGraphStore graphFault(
      FileTrustGraphStore graph,
      AtomicBoolean enabled,
      AtomicInteger attempts,
      boolean afterWrite) {
    return mock(
        TrustGraphStore.class,
        invocation -> {
          if (!invocation.getMethod().getName().equals("importStatement")) {
            return AdditionalAnswers.delegatesTo(graph).answer(invocation);
          }
          attempts.incrementAndGet();
          if (enabled.get() && !afterWrite) {
            throw unavailable();
          }
          Object result = AdditionalAnswers.delegatesTo(graph).answer(invocation);
          if (enabled.get()) {
            throw unavailable();
          }
          return result;
        });
  }

  private static TrustGraphException unavailable() {
    return new TrustGraphException(
        "trust_graph_store_unavailable", "Trust graph store unavailable.");
  }

  private static TrustStatementDocument signedStatement(int score)
      throws java.security.GeneralSecurityException {
    var keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var issuer =
        new TrustIssuer(
            "fixture-" + score,
            TrustStatementFingerprint.sha256Hex(keyPair.getPublic().getEncoded()),
            Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
            "USK@example/profile");
    var payload =
        new TrustStatementPayload(
            issuer,
            new TrustSubject(TrustSubjectKind.PROFILE, "USK@example/subject", null),
            "profile",
            score,
            80,
            "synthetic",
            List.of("fixture"),
            START.minusSeconds(60),
            null);
    var signer = Signature.getInstance("Ed25519");
    signer.initSign(keyPair.getPrivate());
    signer.update(TrustStatementCanonicalizer.canonicalPayloadBytes(payload));
    return new TrustStatementDocument(
        TrustDocumentTypes.TRUST_STATEMENT_V1,
        payload,
        new TrustSignatureEnvelope(
            TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
            TrustDocumentTypes.TRUST_STATEMENT_V1,
            Base64.getEncoder().encodeToString(signer.sign())));
  }

  private static final class MutableClock extends Clock {
    private Instant now;

    private MutableClock(Instant now) {
      this.now = now;
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      if (!ZoneOffset.UTC.equals(zone)) {
        throw new IllegalArgumentException("Test clock uses UTC");
      }
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }

    @Override
    public boolean equals(Object other) {
      return this == other;
    }

    @Override
    public int hashCode() {
      return System.identityHashCode(this);
    }
  }
}
