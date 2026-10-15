package network.crypta.platform.api;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appdata.AppDataStoreConfig;
import network.crypta.platform.api.appdata.FileAppDataStore;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetConfig;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetOperation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.networkbudget.FileAppNetworkBudgetStore;
import network.crypta.platform.api.operator.OperatorSupportRedactor;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.trustgraph.FileTrustGraphStore;
import network.crypta.platform.trustgraph.TrustDocumentTypes;
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
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.runtime.spi.ContentFetchObservation;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

/**
 * File-backed synthetic observations; these exports are private and do not assert installed roles.
 */
class TrustGraphPrivacyIntegrationTest {
  private static final String APP = "privacy-importer";
  private static final String STATEMENT = "PR320_statement_text_synthetic";
  private static final String LABEL = "PR320_source_label_synthetic";
  private static final String SUBJECT = "USK@PR320_subject_identity_synthetic/profile";
  private static final String SOURCE = "CHK@PR320_acquisition_uri_synthetic";
  private static final String RECORD_KEY = "pr320_app_data_key_synthetic";
  private static final String RECORD_VALUE = "PR320_app_data_value_synthetic";
  private static final String CREDENTIAL = "PR320_credential_sentinel_synthetic";
  private static final String UNKNOWN_ROUTE = "PR320_private_selection_token";
  private static final Instant NOW = Instant.parse("2026-10-14T00:00:00Z");
  private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

  @Test
  void realNativeStimulusRetainsPrivateReadbackAndProducesUsefulSafeExports(@TempDir Path root)
      throws Exception {
    var graph =
        spy(
            new FileTrustGraphStore(
                root.resolve("graph"), TrustGraphStoreConfig.defaults(), CLOCK));
    var budgets =
        new AppNetworkBudgetService(
            new FileAppNetworkBudgetStore(root.resolve("budget")),
            new AppNetworkBudgetConfig(20, 40, 2, 8, 20, 40, 1, 4, 20, 40, 1, 4),
            CLOCK);
    var data =
        spy(
            new AppDataService(
                new FileAppDataStore(root.resolve("data")), null, AppDataStoreConfig.defaults()));
    var calls = new AtomicInteger();
    doAnswer(
            invocation -> {
              calls.incrementAndGet();
              return invocation.callRealMethod();
            })
        .when(graph)
        .statements();
    var fetchCalls = new AtomicInteger();
    var fetchMode = new AtomicReference<>("success");
    var document = signedStatement();
    String documentJson = PlatformApiJsonWriter.write(document.toJson());
    var fetchInput = new AtomicReference<String>();
    ContentFetchPort fetch = fetchPort(documentJson, fetchMode, fetchCalls, calls, fetchInput);
    RuntimePorts runtime = runtimePorts();
    when(runtime.contentFetch()).thenReturn(fetch);
    String privatePath = root.resolve("PR320_filesystem_path_synthetic").toString();
    var diagnostic =
        new DiagnosticReportSnapshot(
            List.of(
                new DiagnosticSectionSnapshot(
                    "Budget state",
                    List.of("active requests: 0", "token=" + CREDENTIAL, "path=" + privatePath))));
    when(runtime.diagnostic().snapshot())
        .thenAnswer(
            _ -> {
              calls.incrementAndGet();
              return diagnostic;
            });
    doAnswer(
            invocation -> {
              calls.incrementAndGet();
              return invocation.callRealMethod();
            })
        .when(data)
        .exportBackup(any(), any());
    var handler = new TrustGraphApiHandler(graph, CLOCK, budgets);
    var audit = new AppAuditLog();
    var shared = new PlatformApiSharedAppServices(null, null, null, data, handler, null, budgets);
    var router =
        new PlatformApiRouter(
            runtime, null, null, null, audit, AppUiOriginRegistry.sameOriginOnly(), shared);
    var owner =
        PlatformApiPrincipal.appToken(
            APP,
            List.of(
                "trust.read", "trust.write", "content.fetch", "app.data.read", "app.data.write"));
    var privateSurfaces = new LinkedHashMap<String, Object>();
    var surfaces = new LinkedHashMap<String, Object>();
    var stimuli = new ArrayList<Map<String, String>>();
    var errors = new ArrayList<String>();
    var denials = new ArrayList<Map<String, Object>>();

    var imported =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import"),
                Map.of(
                    "document",
                    List.of(documentJson),
                    "sourceLabel",
                    List.of(LABEL),
                    "sourceUri",
                    List.of(SOURCE)),
                owner));
    assertSignedImport(imported);
    var directReadback =
        new FileTrustGraphStore(root.resolve("graph"), TrustGraphStoreConfig.defaults(), CLOCK)
            .statements()
            .getFirst();
    assertEquals(LABEL, directReadback.sourceLabel(), "source_label_stimulus_not_observed");
    privateSurfaces.put(
        "directSource",
        Map.of(
            "sourceLabel", directReadback.sourceLabel(), "sourceUri", directReadback.sourceUri()));
    stimulus(stimuli, "sourceLabel", LABEL, "directSource");
    var uriImported =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import-uri"),
                Map.of("uri", List.of(SOURCE)),
                owner));
    assertUriFetch(uriImported, fetchCalls.get(), fetchInput.get());
    privateSurfaces.put("fetchInput", Map.of("uri", fetchInput.get()));
    var preview =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import-preview"),
                Map.of("document", List.of(documentJson)),
                owner));
    assertEquals(200, preview.statusCode());
    // Private graph reads prove the statement was admitted, retained, and signature verified.
    var retained =
        new FileTrustGraphStore(root.resolve("graph"), TrustGraphStoreConfig.defaults(), CLOCK)
            .statements()
            .getFirst();
    assertEquals(document, retained.document(), "signed_document_readback_mismatch");
    assertTrue(retained.signatureVerified());
    privateSurfaces.put(
        "graph",
        Map.of(
            "document",
            retained.document().toJson(),
            "documentFingerprint",
            retained.documentFingerprint(),
            "payloadHash",
            retained.payloadHash()));
    // The URI duplicate updates metadata; use the actual readback, never manufacture a private
    // witness.
    privateSurfaces.put(
        "graphSource",
        graph.statements().stream()
            .map(
                row -> {
                  var value = new LinkedHashMap<String, Object>();
                  value.put("sourceLabel", row.sourceLabel());
                  value.put("sourceUri", row.sourceUri());
                  value.put("sourceUriHash", row.sourceUriHash());
                  return value;
                })
            .toList());
    stimulus(stimuli, "statement", STATEMENT, "graph");
    stimulus(stimuli, "subject", SUBJECT, "graph");
    stimulus(stimuli, "documentIdentity", retained.documentFingerprint(), "graph");
    stimulus(stimuli, "sourceUri", SOURCE, "fetchInput");

    var recordParameters =
        Map.of(
            "namespace",
            List.of("privacy"),
            "key",
            List.of(RECORD_KEY),
            "schemaVersion",
            List.of("1"),
            "contentType",
            List.of("text/plain"),
            "valueText",
            List.of(RECORD_VALUE));
    data.putRecord(APP, recordParameters);
    var readback =
        new AppDataService(
                new FileAppDataStore(root.resolve("data")), null, AppDataStoreConfig.defaults())
            .getRecord(APP, "privacy", RECORD_KEY);
    assertEquals(RECORD_VALUE, readback.get("valueText"), "app_data_stimulus_not_observed");
    privateSurfaces.put("appData", readback);
    stimulus(stimuli, "appDataKey", RECORD_KEY, "appData");
    stimulus(stimuli, "appDataValue", RECORD_VALUE, "appData");
    var backup =
        router.route(
            request(
                "POST",
                List.of("operator", "app-data", "backups"),
                Map.of("appId", List.of(APP)),
                PlatformApiPrincipal.hostOperator()));
    assertEquals(200, backup.statusCode());
    privateSurfaces.put("backup", backup.body());
    var rawDiagnostic =
        router.route(
            request("GET", List.of("diagnostics"), Map.of(), PlatformApiPrincipal.hostOperator()));
    assertEquals(200, rawDiagnostic.statusCode());
    privateSurfaces.put("diagnostics", rawDiagnostic.body());
    stimulus(stimuli, "credentialShape", CREDENTIAL, "diagnostics");
    stimulus(stimuli, "filesystem", privatePath, "diagnostics");

    for (var route :
        List.of(
            List.of("operator", "support-bundle"),
            List.of("operator", "runtime-observation"),
            List.of("operator", "network-budgets"),
            List.of("operator", "beta-dashboard"),
            List.of("operator", "app-data", "backups"),
            List.of("trust-graph", "statements"))) {
      int before = calls.get();
      String method = route.contains("backups") ? "POST" : "GET";
      var deniedPrincipal =
          route.getFirst().equals("trust-graph")
              ? PlatformApiPrincipal.appToken("privacy-denied", List.of())
              : owner;
      var denied = router.route(request(method, route, Map.of(), deniedPrincipal));
      assertDeniedBeforeComposition(denied, before, calls);
      errors.add(denied.body());
      denials.add(
          Map.of(
              "route",
              String.join("/", route),
              "status",
              denied.statusCode(),
              "composerCallsBefore",
              before,
              "composerCallsAfter",
              calls.get()));
    }
    var unknown = router.route(request("GET", List.of(UNKNOWN_ROUTE), Map.of(), owner));
    assertEquals(403, unknown.statusCode());
    errors.add(unknown.body());
    privateSurfaces.put("unknownRequest", Map.of("requestedSegment", UNKNOWN_ROUTE));
    stimulus(stimuli, "selectionMapping", UNKNOWN_ROUTE, "unknownRequest");
    var unauthorizedImport =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import"),
                Map.of("document", List.of(documentJson)),
                PlatformApiPrincipal.appToken("privacy-denied", List.of())));
    assertEquals(403, unauthorizedImport.statusCode());
    errors.add(unauthorizedImport.body());
    var malformed =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import"),
                Map.of("document", List.of("{\"private\":\"" + STATEMENT + "\"")),
                owner));
    assertEquals(400, malformed.statusCode());
    errors.add(malformed.body());
    for (String mode : List.of("invalid-utf8", "oversized", "timeout")) {
      fetchMode.set(mode);
      var failed =
          router.route(
              request(
                  "POST",
                  List.of("trust-graph", "import-uri"),
                  Map.of("uri", List.of(SOURCE), "maxBytes", List.of("64")),
                  owner));
      assertTrue(failed.statusCode() >= 400);
      errors.add(failed.body());
    }
    int beforeInvalidUri = fetchCalls.get();
    var invalidUri =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import-uri"),
                Map.of("uri", List.of("file:" + privatePath)),
                owner));
    assertEquals(400, invalidUri.statusCode());
    assertEquals(beforeInvalidUri, fetchCalls.get());
    errors.add(invalidUri.body());
    try (var lease = budgets.acquire(APP, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT).lease()) {
      assertTrue(lease.active());
      var concurrent =
          router.route(
              request(
                  "POST",
                  List.of("trust-graph", "import"),
                  Map.of("document", List.of(documentJson)),
                  owner));
      assertEquals(429, concurrent.statusCode());
      errors.add(concurrent.body());
    }
    boolean exhausted = false;
    for (int attempt = 0; attempt < 25; attempt++) {
      var result =
          router.route(
              request(
                  "POST",
                  List.of("trust-graph", "import"),
                  Map.of("document", List.of(documentJson)),
                  owner));
      if (result.statusCode() == 429) {
        assertTrue(result.body().contains("trust_graph_import_budget_exhausted"));
        errors.add(result.body());
        exhausted = true;
        break;
      }
      assertEquals(200, result.statusCode());
    }
    assertTrue(exhausted);
    surfaces.put("appErrors", errors);
    surfaces.put("appAudit", jsonValue(audit.recentForApp(APP, 100)));
    var support =
        router.route(
            request(
                "GET",
                List.of("operator", "support-bundle"),
                Map.of(),
                PlatformApiPrincipal.hostOperator()));
    var supportPreview =
        router.route(
            request(
                "GET",
                List.of("operator", "support-bundle", "preview"),
                Map.of(),
                PlatformApiPrincipal.hostOperator()));
    var operatorRuntime =
        router.route(
            request(
                "GET",
                List.of("operator", "runtime-observation"),
                Map.of(),
                PlatformApiPrincipal.hostOperator()));
    assertUsefulAuthorizedExports(support, supportPreview, operatorRuntime);
    surfaces.put("supportBundle", support.body());
    surfaces.put("supportPreview", supportPreview.body());
    surfaces.put("operatorRuntime", operatorRuntime.body());
    surfaces.put("workSnapshot", jsonValue(budgets.observation().snapshot()));
    // Controlled negative category fixtures exercise the real secondary redactor. They are not
    // graph/service producer records or public originals, and remain in the private native
    // artifact.
    String fieldName = "PR320_unsafe_field_name_token";
    String nestedSecret = "PR320_nested_credential_synthetic";
    String backupBody = "PR320_backup_body_synthetic";
    String attachmentName = "/private/PR320_attachment_filename_synthetic.json";
    Map<String, Object> redactorInput =
        Map.of(
            "nested",
            List.of(
                Map.of(
                    fieldName,
                    "private-value",
                    "summary",
                    "token=" + nestedSecret,
                    "attachmentName",
                    attachmentName,
                    "archive",
                    Map.of(
                        "kind",
                        "crypta-app-data-backup",
                        "apps",
                        List.of(Map.of("value", backupBody))))),
            "status",
            "available",
            "count",
            1);
    privateSurfaces.put("redactorInput", redactorInput);
    var redaction = OperatorSupportRedactor.redact(redactorInput);
    surfaces.put(
        "redactorProjection",
        Map.of("value", redaction.value(), "omittedFields", redaction.omittedFields()));
    assertTrue(redaction.omittedFields().contains("unsafeFieldName"));
    stimulus(stimuli, "fieldName", fieldName, "redactorInput");
    stimulus(stimuli, "nestedCredential", nestedSecret, "redactorInput");
    stimulus(stimuli, "backupShape", backupBody, "redactorInput");
    stimulus(stimuli, "attachmentName", attachmentName, "redactorInput");
    assertSafeSettledState(surfaces, stimuli, budgets, graph);
    var evidence = new LinkedHashMap<String, Object>();
    evidence.put("schemaVersion", 1);
    evidence.put("caseId", "privacy");
    evidence.put("evidenceClass", "controlled-native-file-backed");
    evidence.put("producer", getClass().getName());
    evidence.put("stimuli", stimuli);
    evidence.put("privateSurfaces", privateSurfaces);
    evidence.put("surfaces", surfaces);
    evidence.put("denials", denials);
    evidence.put(
        "counters",
        Map.of(
            "graphStatements",
            graph.statementCount(),
            "fetchCalls",
            fetchCalls.get(),
            "auditDecisions",
            audit.recentForApp(APP, 100).size(),
            "workEvents",
            budgets.observation().snapshot().events().size(),
            "composerCalls",
            calls.get()));
    export(evidence);
  }

  private static void assertSignedImport(PlatformApiResponse imported) {
    assertEquals(200, imported.statusCode());
    assertTrue(imported.body().contains("\"signatureVerified\":true"));
  }

  private static void assertUriFetch(
      PlatformApiResponse imported, int fetchCalls, String fetchInput) {
    assertEquals(200, imported.statusCode());
    assertEquals(1, fetchCalls);
    assertEquals(SOURCE, fetchInput, "fetch_uri_stimulus_not_observed");
  }

  private static void assertDeniedBeforeComposition(
      PlatformApiResponse denied, int callsBefore, AtomicInteger composerCalls) {
    assertEquals(403, denied.statusCode());
    assertEquals(callsBefore, composerCalls.get());
  }

  private static void assertUsefulAuthorizedExports(
      PlatformApiResponse support, PlatformApiResponse preview, PlatformApiResponse runtime) {
    assertEquals(200, support.statusCode());
    assertEquals(200, preview.statusCode());
    assertEquals(200, runtime.statusCode());
    assertTrue(support.body().contains("\"statementCount\":1"));
    assertTrue(support.body().contains("\"sectionCount\":1"));
    assertTrue(support.body().contains("\"supportDigest\""));
    assertTrue(runtime.body().contains("\"valid\":true"));
  }

  private static void assertSafeSettledState(
      Map<String, Object> surfaces,
      List<Map<String, String>> stimuli,
      AppNetworkBudgetService budgets,
      FileTrustGraphStore graph) {
    String safeBytes = PlatformApiJsonWriter.write(surfaces);
    for (var stimulus : stimuli) assertFalse(safeBytes.contains(stimulus.get("marker")));
    assertEquals(0, budgets.diagnostics().activeFamilyLeases());
    assertEquals(0, budgets.diagnostics().reservedFamilyRates());
    assertEquals(1, graph.statementCount());
    assertTrue(budgets.diagnostics().valid());
  }

  private static ContentFetchPort fetchPort(
      String document,
      AtomicReference<String> mode,
      AtomicInteger fetchCalls,
      AtomicInteger composerCalls,
      AtomicReference<String> fetchInput) {
    return new ContentFetchPort() {
      @Override
      public BoundedContentFetchResult fetchContent(
          network.crypta.runtime.spi.BoundedContentFetchRequest request)
          throws ContentFetchException {
        fetchCalls.incrementAndGet();
        fetchInput.set(request.uri());
        byte[] bytes =
            switch (mode.get()) {
              case "invalid-utf8" -> new byte[] {(byte) 0xc3, 0x28};
              case "oversized" -> new byte[65];
              case "timeout" ->
                  throw new ContentFetchException(
                      ContentFetchException.CATALOG_FETCH_TIMEOUT, "token=" + CREDENTIAL);
              default -> document.getBytes(StandardCharsets.UTF_8);
            };
        return new BoundedContentFetchResult(bytes, request.uri(), null, null);
      }

      @Override
      public ContentFetchObservation observation() {
        composerCalls.incrementAndGet();
        return ContentFetchObservation.unavailable();
      }
    };
  }

  private static void stimulus(
      List<Map<String, String>> stimuli, String purpose, String marker, String surface) {
    stimuli.add(Map.of("purpose", purpose, "marker", marker, "privateSurface", surface));
  }

  private static PlatformApiRequest request(
      String method,
      List<String> route,
      Map<String, List<String>> parameters,
      PlatformApiPrincipal principal) {
    return new PlatformApiRequest(method, route, parameters, principal);
  }

  private static TrustStatementDocument signedStatement() throws Exception {
    var key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var issuer =
        new TrustIssuer(
            "synthetic-issuer",
            TrustStatementFingerprint.sha256Hex(key.getPublic().getEncoded()),
            Base64.getEncoder().encodeToString(key.getPublic().getEncoded()),
            null);
    var payload =
        new TrustStatementPayload(
            issuer,
            new TrustSubject(TrustSubjectKind.PROFILE, SUBJECT, null),
            "profile",
            50,
            80,
            STATEMENT,
            List.of(),
            NOW.minusSeconds(60),
            null);
    var signer = Signature.getInstance("Ed25519");
    signer.initSign(key.getPrivate());
    signer.update(TrustStatementCanonicalizer.canonicalPayloadBytes(payload));
    return new TrustStatementDocument(
        TrustDocumentTypes.TRUST_STATEMENT_V1,
        payload,
        new TrustSignatureEnvelope(
            TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
            TrustDocumentTypes.TRUST_STATEMENT_V1,
            Base64.getEncoder().encodeToString(signer.sign())));
  }

  private static RuntimePorts runtimePorts() {
    return mock(RuntimePorts.class, Answers.RETURNS_DEEP_STUBS);
  }

  private static Object jsonValue(Object value) throws Exception {
    if (value == null
        || value instanceof Number
        || value instanceof Boolean
        || value instanceof String) return value;
    if (value instanceof Instant || value instanceof Enum<?>) return value.toString();
    if (value instanceof List<?> list) {
      var values = new ArrayList<>();
      for (var item : list) values.add(jsonValue(item));
      return values;
    }
    if (value.getClass().isRecord()) {
      var values = new LinkedHashMap<String, Object>();
      for (var field : value.getClass().getRecordComponents())
        values.put(field.getName(), jsonValue(field.getAccessor().invoke(value)));
      return values;
    }
    throw new IllegalArgumentException("Unsupported native privacy fixture field");
  }

  private static void export(Map<String, Object> evidence) throws Exception {
    Path directory = Path.of("build", "test-results", "pr320-native");
    Files.createDirectories(directory);
    Path output = directory.resolve("privacy.json");
    if (directory.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
      if (!Files.exists(output))
        Files.createFile(
            output,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
      Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rw-------"));
    }
    Files.writeString(output, PlatformApiJsonWriter.write(evidence));
  }
}
