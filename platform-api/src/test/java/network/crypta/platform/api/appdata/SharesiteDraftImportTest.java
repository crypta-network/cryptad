package network.crypta.platform.api.appdata;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.appdist.AppBundleVerification;
import network.crypta.platform.appdist.AppDataNamespaceSchema;
import network.crypta.platform.appdist.AppDataSchemaContract;
import network.crypta.platform.appdist.AppRestartPolicy;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppDiskUsageScanner;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.sandbox.AppSandboxPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SharesiteDraftImportTest {
  private static final String APP = "site-publisher";
  private static final String NS = "sharesite-drafts";
  private static final String OP = "00000000-0000-4000-8000-000000000001";
  private static final String OP2 = "00000000-0000-4000-8000-000000000002";
  private static final Instant NOW = Instant.parse("2026-09-05T12:00:00Z");
  private static final List<String> PERMISSIONS =
      List.of("app.data.read", "app.data.write", "content.insert.app-document");
  @TempDir Path root;
  private FileAppDataStore store;
  private AppHost host;
  private AtomicReference<InstalledAppSnapshot> installed;
  private AppDataService service;

  @BeforeEach
  void setUp() throws IOException {
    store = new FileAppDataStore(root.resolve("store"), AppDataStoreConfig.defaults());
    host = mock(AppHost.class);
    installed = new AtomicReference<>(installed("2", 1_048_576L, PERMISSIONS));
    when(host.describe(APP)).thenAnswer(_ -> Optional.of(installed.get()));
    when(host.withVerifiedInstalledBundle(eq(APP), any()))
        .thenAnswer(
            call -> {
              AppHost.VerifiedBundleAction<?> action = call.getArgument(1);
              return action.run(
                  installed.get(),
                  AppBundleVerification.signed(
                      "fixture", "Ed25519", "a".repeat(64), "b".repeat(64)));
            });
    service = service(store);
  }

  @Test
  void import_whenPreviewedAndCommitted_expectDurableExactLiteralAndNoPreviewMutation() {
    String literal = "Unicode 雪 🌍\r\n<script>alert(1)</script>\n\r";
    Map<String, Object> data = dataset(OP, literal);
    Map<String, List<String>> request = request(data, "import", "absent");
    Map<String, Object> preview = service.putRecord(APP, request);
    assertEquals(0, service.status(APP).get("recordCount"));
    assertFalse(PlatformApiJsonWriter.write(preview).contains(literal));

    Map<String, Object> result = commit(request, preview);

    assertEquals(PlatformApiJsonWriter.write(data), result.get("valueText"));
    AppDataService restarted =
        service(new FileAppDataStore(root.resolve("store"), AppDataStoreConfig.defaults()));
    assertEquals(result, restarted.getRecord(APP, NS, "dataset"));
    assertEquals(1, restarted.status(APP).get("recordCount"));
    assertThrows(PlatformApiException.class, () -> commit(request, preview));
    assertEquals(result, restarted.getRecord(APP, NS, "dataset"));
  }

  @Test
  void commit_whenAnyTargetRecordChanged_expectStaleConsentAndUnrelatedDataPreserved() {
    var request = request(dataset(OP, "selected"), "import", "absent");
    var preview = service.putRecord(APP, request);
    service.putRecord(
        APP,
        Map.of(
            "namespace",
            List.of("other"),
            "key",
            List.of("draft"),
            "schemaVersion",
            List.of("1"),
            "valueText",
            List.of("unrelated")));
    assertEquals(
        "sharesite_stale_preview",
        assertThrows(PlatformApiException.class, () -> commit(request, preview)).errorCode());
    assertEquals("unrelated", service.getRecord(APP, "other", "draft").get("valueText"));
    assertEquals(1, service.status(APP).get("recordCount"));
  }

  @Test
  void commit_whenBundleVersionQuotaOrPermissionsChanged_expectNoMutation() {
    for (InstalledAppSnapshot replacement :
        List.of(
            installed("3", 1_048_576L, PERMISSIONS),
            installed("2", 2_097_152L, PERMISSIONS),
            installed("2", 1_048_576L, List.of("app.data.write")))) {
      installed.set(installed("2", 1_048_576L, PERMISSIONS));
      var request = request(dataset(OP, "selected"), "import", "absent");
      var preview = service.putRecord(APP, request);
      installed.set(replacement);
      assertThrows(PlatformApiException.class, () -> commit(request, preview));
      assertEquals(0, service.status(APP).get("recordCount"));
    }
  }

  @Test
  void commit_whenUpdateBarrierActive_expectNoMutationAndRetryRequiresCurrentConsent() {
    var request = request(dataset(OP, "selected"), "import", "absent");
    var preview = service.putRecord(APP, request);
    try (var _ = service.beginUpdateMigrationWriteBarrier(APP)) {
      assertEquals(
          "app_data_migration_in_progress",
          assertThrows(PlatformApiException.class, () -> commit(request, preview)).errorCode());
      assertEquals(0, service.status(APP).get("recordCount"));
    }
    commit(request, preview);
    assertEquals(1, service.status(APP).get("recordCount"));
  }

  @Test
  void import_whenQuotaTooSmall_expectPreviewFailureBeforeNamespaceCreation() {
    installed.set(installed("2", 1L, PERMISSIONS));
    var request = request(dataset(OP, "selected"), "import", "absent");
    assertEquals(
        "app_data_quota_exceeded",
        assertThrows(PlatformApiException.class, () -> service.putRecord(APP, request))
            .errorCode());
    assertEquals(0, service.listNamespaces(APP).size());
  }

  @Test
  void commit_whenPayloadChangedOrRestarted_expectConsentRejected() {
    var request = request(dataset(OP, "selected"), "import", "absent");
    var preview = service.putRecord(APP, request);
    var changed = request(dataset(OP, "altered"), "import", "absent");
    assertEquals(
        "sharesite_stale_preview",
        assertThrows(PlatformApiException.class, () -> commit(changed, preview)).errorCode());
    var stale = service.putRecord(APP, request);
    service = service(store);
    assertThrows(PlatformApiException.class, () -> commit(request, stale));
    assertEquals(0, service.status(APP).get("recordCount"));
  }

  @Test
  void import_whenExistingOperationCollides_expectNoOverwrite() {
    Map<String, Object> data = dataset(OP, "old");
    var written = apply(data, "import", "absent");
    var request = request(dataset(OP, "replacement"), "import", (String) written.get("sha256"));
    assertThrows(PlatformApiException.class, () -> service.putRecord(APP, request));
    assertEquals(written, service.getRecord(APP, NS, "dataset"));
  }

  @Test
  void undo_whenUnchanged_expectOnlySelectedOperationRemovedAndLedgerRetained() {
    Map<String, Object> first = dataset(OP, "first");
    var written = apply(first, "import", "absent");
    var combined = combine(first, dataset(OP2, "second"));
    written = apply(combined, "import", (String) written.get("sha256"));
    Map<String, Object> undone = undo(combined);
    written = apply(undone, "undo", (String) written.get("sha256"));
    assertEquals(PlatformApiJsonWriter.write(undone), written.get("valueText"));
    assertTrue(((String) written.get("valueText")).contains("second"));
    assertFalse(((String) written.get("valueText")).contains("first"));
  }

  @Test
  void undo_whenEdited_expectManualRecoveryAndPrivateRestoreRoundTrip() {
    var original = dataset(OP, "original");
    var written = apply(original, "import", "absent");
    var edited = edit(original, "user edit");
    written = apply(edited, "edit", (String) written.get("sha256"));
    String current = (String) written.get("sha256");
    var request = request(undo(edited), "undo", current);
    assertEquals(
        "sharesite_undo_requires_manual_recovery",
        assertThrows(PlatformApiException.class, () -> service.putRecord(APP, request))
            .errorCode());
    var backup = service.exportData(APP, Map.of("namespace", List.of(NS)));
    assertTrue(PlatformApiJsonWriter.write(backup).contains("payloadBase64"));
    service =
        service(new FileAppDataStore(root.resolve("restored"), AppDataStoreConfig.defaults()));
    var restored = apply(edited, "restore", "absent");
    assertEquals(written.get("valueText"), restored.get("valueText"));
  }

  @Test
  void write_whenMalformedWrongScopeOrSecretBearing_expectContentFreeFailure() {
    for (String secret :
        List.of(
            "token=SECRET_CANARY",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN SECRET-----",
            "Authorization: Bearer SECRET_CANARY",
            "private-key=SECRET_CANARY",
            "insertssk=SECRET_CANARY",
            "password=SECRET_CANARY",
            "secret=SECRET_CANARY",
            "seed=SECRET_CANARY",
            "inserturi=SECRET_CANARY",
            "SSK@invalid,invalid,AQECAAE/site")) {
      var secretRequest = request(dataset(OP, secret), "import", "absent");
      var exception =
          assertThrows(PlatformApiException.class, () -> service.putRecord(APP, secretRequest));
      assertFalse(exception.toString().contains(secret));
    }
    var request = request(dataset(OP, "text"), "import", "absent");
    request.put("schemaVersion", List.of("2"));
    assertThrows(PlatformApiException.class, () -> service.putRecord(APP, request));
    assertEquals(0, service.status(APP).get("recordCount"));
  }

  @Test
  void write_whenOperationHasNonStringStatusOrDraftIds_expectNoMutation() {
    Map<String, Object> original = dataset(OP, "text");
    for (var field :
        List.of(
            Map.entry("status", 42),
            Map.entry("draftIds", List.of(42)),
            Map.entry("draftIds", List.of(Map.of("id", OP + "-0"))),
            Map.entry("draftIds", List.of(OP + "-0", OP + "-0")),
            Map.entry("draftIds", List.of(OP2 + "-0")))) {
      var operation = new LinkedHashMap<>(rows(original, "operations").getFirst());
      operation.put(field.getKey(), field.getValue());
      var candidate = new LinkedHashMap<>(original);
      candidate.put("operations", List.of(operation));
      var request = request(candidate, "import", "absent");

      var failure = assertThrows(PlatformApiException.class, () -> service.putRecord(APP, request));

      assertEquals("sharesite_invalid_dataset", failure.errorCode());
      assertEquals(0, service.status(APP).get("recordCount"));
    }
  }

  @Test
  void write_whenTextContainsUnpairedSurrogate_expectNoMutation() {
    for (String escaped : List.of("\\ud800", "\\udc00", "\\ud800x", "\\ud800\\ud800")) {
      var request = request(dataset(OP, "surrogate-placeholder"), "restore", "absent");
      String json = request.get("valueJson").getFirst().replace("surrogate-placeholder", escaped);
      request.put("valueJson", List.of(json));

      assertThrows(PlatformApiException.class, () -> service.putRecord(APP, request));
      assertEquals(0, service.status(APP).get("recordCount"));
    }
  }

  @Test
  void putRecord_whenOtherAppUsesDraftNamespace_expectOrdinaryIsolatedWrite() {
    var request =
        Map.of(
            "namespace", List.of(" SHARESITE-DRAFTS "),
            "key", List.of("ordinary-record"),
            "schemaVersion", List.of("1"),
            "valueText", List.of("other app data"));

    var written = service.putRecord("another-app", request);

    assertEquals("other app data", written.get("valueText"));
    assertEquals(written, service.getRecord("another-app", NS, "ordinary-record"));
    assertEquals(0, service.status(APP).get("recordCount"));
    assertEquals(1, service.status("another-app").get("recordCount"));
    assertThrows(PlatformApiException.class, () -> service.putRecord(APP, request));
  }

  @Test
  void deleteRecord_whenNamespaceNormalizesToDrafts_expectGuardAndDatasetPreserved() {
    var request = request(dataset(OP, "retained text"), "import", "absent");
    var preview = service.putRecord(APP, request);
    var before = commit(request, preview);

    for (String namespace : List.of(NS, "SHARESITE-DRAFTS", " Sharesite-Drafts ")) {
      PlatformApiException failure =
          assertThrows(
              PlatformApiException.class, () -> service.deleteRecord(APP, namespace, "dataset"));
      assertEquals("sharesite_guard_required", failure.errorCode());
      assertEquals(before, service.getRecord(APP, NS, "dataset"));
      assertEquals(1, service.status(APP).get("recordCount"));
    }
  }

  @Test
  void reservedDataset_whenBypassingGuardOrChangingType_expectNoMutation() {
    var request = request(dataset(OP, "text"), "import", "absent");
    request.put("contentType", List.of("text/plain"));
    assertThrows(PlatformApiException.class, () -> service.putRecord(APP, request));
    var schemaRequest = Map.of("fromSchemaVersion", List.of("1"), "toSchemaVersion", List.of("2"));
    assertThrows(PlatformApiException.class, () -> service.updateSchema(APP, NS, schemaRequest));
    assertThrows(PlatformApiException.class, () -> service.deleteNamespace(APP, NS));
    assertThrows(PlatformApiException.class, () -> service.deleteRecord(APP, NS, "dataset"));
    assertEquals(0, service.status(APP).get("recordCount"));
  }

  @Test
  void commit_whenStoreFailsBeforeOrAfterPointerPublication_expectOldOrCompleteGeneration()
      throws IOException {
    var data = dataset(OP, "old");
    var written = apply(data, "import", "absent");
    for (boolean afterWrite : List.of(false, true)) {
      FileAppDataStore failing = spy(store);
      doAnswer(
              call -> {
                if (afterWrite) call.callRealMethod();
                throw new IOException("injected interruption");
              })
          .when(failing)
          .writeRecord(any());
      service = service(failing);
      var next = edit(data, "complete replacement");
      var request = request(next, "edit", (String) written.get("sha256"));
      var preview = service.putRecord(APP, request);
      assertThrows(PlatformApiException.class, () -> commit(request, preview));
      assertThrows(PlatformApiException.class, () -> commit(request, preview));
      service = service(store);
      var actual = service.getRecord(APP, NS, "dataset");
      assertEquals(PlatformApiJsonWriter.write(afterWrite ? next : data), actual.get("valueText"));
    }
  }

  private AppDataService service(AppDataStore dataStore) {
    return new AppDataService(
        dataStore,
        host,
        AppDataStoreConfig.defaults(),
        Clock.fixed(NOW, ZoneOffset.UTC),
        new AppDiskUsageScanner(),
        true);
  }

  private InstalledAppSnapshot installed(String version, long quota, List<String> permissions) {
    var api =
        new AppApiCompatibilityMetadata(
            9,
            24,
            List.of(),
            AppApiCompatibilityMetadata.TargetStability.STABLE,
            true,
            "1.0",
            true,
            false,
            true);
    var schema =
        new AppDataSchemaContract(1, List.of(new AppDataNamespaceSchema(NS, 1)), List.of());
    var manifest =
        new AppManifest(
            1,
            APP,
            "Site Publisher",
            version,
            "bin/start.sh",
            AppUiMode.NONE,
            null,
            permissions,
            api,
            schema,
            quota,
            null,
            AppSandboxPolicy.defaults(),
            AppRestartPolicy.NEVER,
            0,
            0);
    return new InstalledAppSnapshot(
        manifest,
        new InstalledAppPaths(
            APP,
            root.resolve("bundle"),
            root.resolve("data"),
            root.resolve("cache"),
            root.resolve("run")));
  }

  private static Map<String, Object> dataset(String operation, String text) {
    String id = operation + "-0";
    Map<String, Object> draft =
        Map.of(
            "id",
            id,
            "operationId",
            operation,
            "sourceId",
            0,
            "name",
            "Private name",
            "description",
            "Private description",
            "logicalPath",
            "../metadata-only",
            "text",
            text,
            "historicalEdition",
            -1);
    var drafts = List.of(draft);
    var op =
        Map.of(
            "operationId",
            operation,
            "payloadSha256",
            "c".repeat(64),
            "status",
            "committed",
            "draftIds",
            List.of(id),
            "originalsSha256",
            SharesiteDraftWriteGuard.canonicalDigest(drafts));
    return Map.of("schemaVersion", 1, "operations", List.of(op), "drafts", drafts);
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> rows(Map<String, Object> data, String field) {
    return (List<Map<String, Object>>) data.get(field);
  }

  private static Map<String, Object> combine(
      Map<String, Object> first, Map<String, Object> second) {
    var operations = new ArrayList<>(rows(first, "operations"));
    operations.addAll(rows(second, "operations"));
    var drafts = new ArrayList<>(rows(first, "drafts"));
    drafts.addAll(rows(second, "drafts"));
    return Map.of("schemaVersion", 1, "operations", operations, "drafts", drafts);
  }

  private static Map<String, Object> edit(Map<String, Object> original, String text) {
    var draft = new LinkedHashMap<>(rows(original, "drafts").getFirst());
    draft.put("text", text);
    return Map.of(
        "schemaVersion", 1, "operations", original.get("operations"), "drafts", List.of(draft));
  }

  private static Map<String, Object> undo(Map<String, Object> original) {
    var operations =
        rows(original, "operations").stream()
            .map(
                op -> {
                  var next = new LinkedHashMap<>(op);
                  if (OP.equals(op.get("operationId"))) next.put("status", "undone");
                  return next;
                })
            .toList();
    var drafts =
        rows(original, "drafts").stream()
            .filter(draft -> !OP.equals(draft.get("operationId")))
            .toList();
    return Map.of("schemaVersion", 1, "operations", operations, "drafts", drafts);
  }

  private static Map<String, List<String>> request(
      Map<String, Object> data, String mode, String current) {
    return new LinkedHashMap<>(
        Map.of(
            "namespace",
            List.of(NS),
            "key",
            List.of("dataset"),
            "schemaVersion",
            List.of("1"),
            "valueJson",
            List.of(PlatformApiJsonWriter.write(data)),
            "ifMatchSha256",
            List.of(current),
            "writeIntent",
            List.of("preview"),
            "writeMode",
            List.of(mode),
            "backupReady",
            List.of("true")));
  }

  private Map<String, Object> commit(
      Map<String, List<String>> request, Map<String, Object> preview) {
    var commit = new LinkedHashMap<>(request);
    commit.put("writeIntent", List.of("commit"));
    commit.put("writePreviewId", List.of((String) preview.get("previewId")));
    return service.putRecord(APP, commit);
  }

  private Map<String, Object> apply(Map<String, Object> data, String mode, String current) {
    var request = request(data, mode, current);
    return commit(request, service.putRecord(APP, request));
  }
}
