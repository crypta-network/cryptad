package network.crypta.platform.api.appdata;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppDiskUsageScanner;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AppDataServiceTest {
  private static final String APP_ID = "feed-reader";
  private static final String OTHER_APP_ID = "other-app";
  private static final String UI_STATE_NAMESPACE = "ui-state";
  private static final String PROFILE_DRAFT_NAMESPACE = "profile-draft";
  private static final String SETTINGS_KEY = "settings";
  private static final String DRAFT_KEY = "draft";
  private static final String STALE_KEY = "stale";
  private static final String FIELD_IMPORTED = "imported";
  private static final String FIELD_PAYLOAD_BASE64 = "payloadBase64";
  private static final String FIELD_RECORD_COUNT = "recordCount";
  private static final String FIELD_SCHEMA_VERSION = "schemaVersion";
  private static final String FIELD_VALUE_TEXT = "valueText";
  private static final String PARAM_FROM_SCHEMA_VERSION = "fromSchemaVersion";
  private static final String PARAM_TO_SCHEMA_VERSION = "toSchemaVersion";
  private static final String ERROR_QUOTA_EXCEEDED = "app_data_quota_exceeded";
  private static final String ERROR_MIGRATION_IN_PROGRESS = "app_data_migration_in_progress";
  private static final String THEME_DARK_JSON = "{\"theme\":\"dark\"}";
  private static final Instant NOW = Instant.parse("2026-05-24T12:00:00Z");

  @TempDir private Path tempDir;

  @Test
  void recordLifecycle_whenCalledForOneApp_expectCreateListReadStatusAndDelete() {
    AppDataService service = service(config(64, 16, 4, 4096, 4096));

    Map<String, Object> written =
        service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "one"));

    assertEquals(UI_STATE_NAMESPACE, written.get("namespace"));
    assertEquals(SETTINGS_KEY, written.get("key"));
    assertEquals("one", written.get(FIELD_VALUE_TEXT));
    assertEquals(1, service.listNamespaces(APP_ID).size());
    Map<String, Object> records = service.listRecords(APP_ID, Map.of());
    assertEquals(1, records.get("totalRecords"));
    assertEquals(
        "one", service.getRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY).get(FIELD_VALUE_TEXT));
    Map<String, Object> status = service.status(APP_ID);
    assertEquals(1, status.get(FIELD_RECORD_COUNT));
    assertEquals(1, status.get("namespaceCount"));

    Map<String, Object> deleted = service.deleteRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY);

    assertEquals(true, deleted.get("deleted"));
    assertThrows(
        PlatformApiException.class,
        () -> service.getRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY));
  }

  @Test
  void deleteRecord_whenDeletedRecordWasNewest_expectNamespaceUpdatedAtReflectsDeleteTime() {
    InMemoryAppDataStore store = new InMemoryAppDataStore();
    Instant recordUpdatedAt = NOW.plusSeconds(20);
    Instant deletedAt = NOW.plusSeconds(30);
    store.writeNamespace(
        new AppDataNamespaceMetadata(
            APP_ID, UI_STATE_NAMESPACE, 1, 0, 0L, NOW, NOW, null, java.util.List.of()));
    store.writeRecord(
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload("text/plain", 1, "one".getBytes(StandardCharsets.UTF_8)),
            NOW,
            recordUpdatedAt));
    AppDataService service =
        new AppDataService(
            store,
            null,
            config(64, 16, 4, 4096, 4096),
            Clock.fixed(deletedAt, ZoneOffset.UTC),
            new AppDiskUsageScanner());

    service.deleteRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY);
    Map<String, Object> namespace = service.getNamespace(APP_ID, UI_STATE_NAMESPACE);

    assertEquals(0, namespace.get(FIELD_RECORD_COUNT));
    assertEquals(deletedAt.toString(), namespace.get("updatedAt"));
  }

  @Test
  void updateSchema_whenVersionMovesForward_expectMigrationMetadataRecorded() {
    AppDataService service = service(config(64, 16, 4, 4096, 4096));
    service.putRecord(APP_ID, recordParams(PROFILE_DRAFT_NAMESPACE, DRAFT_KEY, "{}"));

    Map<String, Object> namespace =
        service.updateSchema(
            APP_ID,
            PROFILE_DRAFT_NAMESPACE,
            params(
                PARAM_FROM_SCHEMA_VERSION,
                "1",
                PARAM_TO_SCHEMA_VERSION,
                "2",
                "summary",
                "draft migration"));

    assertEquals(2, namespace.get(FIELD_SCHEMA_VERSION));
    assertTrue(namespace.toString().contains("draft migration"));
    Map<String, List<String>> downgradeParams =
        params(PARAM_FROM_SCHEMA_VERSION, "2", PARAM_TO_SCHEMA_VERSION, "1");
    PlatformApiException downgrade =
        assertThrows(
            PlatformApiException.class,
            () -> service.updateSchema(APP_ID, PROFILE_DRAFT_NAMESPACE, downgradeParams));
    assertEquals("invalid_app_data_schema", downgrade.errorCode());
  }

  @Test
  void inMemoryNamespaceTotals_whenMetadataNewerThanRecords_expectUpdatedAtPreserved() {
    InMemoryAppDataStore store = new InMemoryAppDataStore();
    Instant recordUpdatedAt = NOW.plusSeconds(10);
    Instant metadataUpdatedAt = NOW.plusSeconds(20);
    store.writeNamespace(
        new AppDataNamespaceMetadata(
            APP_ID,
            UI_STATE_NAMESPACE,
            2,
            0,
            0L,
            NOW,
            metadataUpdatedAt,
            metadataUpdatedAt,
            List.of(new AppDataMigrationRecord(1, 2, "schema update", metadataUpdatedAt))));
    store.writeRecord(
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(
                "text/plain", 1, "older-record".getBytes(StandardCharsets.UTF_8)),
            NOW,
            recordUpdatedAt));

    AppDataNamespaceMetadata metadata =
        store.readNamespace(APP_ID, UI_STATE_NAMESPACE).orElseThrow();

    assertEquals(metadataUpdatedAt, metadata.updatedAt());
    assertEquals(metadataUpdatedAt, metadata.lastMigrationAt());
    assertEquals(1, metadata.recordCount());
  }

  @Test
  void exportImport_whenPayloadRoundTrips_expectValuesCopiedAndOtherAppRejected() {
    AppDataService service = service(config(128, 16, 4, 4096, 4096));
    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, THEME_DARK_JSON));

    Map<String, Object> exported = service.exportData(APP_ID, Map.of());
    String payloadBase64 = (String) exported.get(FIELD_PAYLOAD_BASE64);
    AppDataService target = service(config(128, 16, 4, 4096, 4096));

    Map<String, Object> imported =
        target.importData(APP_ID, params(FIELD_PAYLOAD_BASE64, payloadBase64));

    assertEquals(true, imported.get(FIELD_IMPORTED));
    assertEquals(
        THEME_DARK_JSON,
        target.getRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY).get(FIELD_VALUE_TEXT));
    Map<String, List<String>> mismatchedAppImportParams =
        params(FIELD_PAYLOAD_BASE64, payloadBase64);
    PlatformApiException mismatch =
        assertThrows(
            PlatformApiException.class,
            () -> target.importData(OTHER_APP_ID, mismatchedAppImportParams));
    assertEquals("app_data_import_app_mismatch", mismatch.errorCode());
  }

  @Test
  void importData_whenTopLevelAppIdOmittedButEntryAppIdsDiffer_expectAppMismatch() {
    String payloadWithoutTopLevelAppId =
        new String(themeExportPayloadBytes(), StandardCharsets.UTF_8)
            .replaceFirst("\"appId\":\"" + APP_ID + "\",", "");
    String payloadBase64 =
        payloadBase64(payloadWithoutTopLevelAppId.getBytes(StandardCharsets.UTF_8));
    AppDataService target = service(config(128, 16, 4, 4096, 4096));
    Map<String, List<String>> importParams = params(FIELD_PAYLOAD_BASE64, payloadBase64);

    PlatformApiException mismatch =
        assertThrows(
            PlatformApiException.class, () -> target.importData(OTHER_APP_ID, importParams));

    assertEquals("app_data_import_app_mismatch", mismatch.errorCode());
  }

  @Test
  void importData_whenAllAppIdsOmitted_expectImportedForCaller() {
    String payloadWithoutAppIds =
        new String(themeExportPayloadBytes(), StandardCharsets.UTF_8)
            .replace("\"appId\":\"" + APP_ID + "\",", "");
    String payloadBase64 = payloadBase64(payloadWithoutAppIds.getBytes(StandardCharsets.UTF_8));
    AppDataService target = service(config(128, 16, 4, 4096, 4096));
    Map<String, List<String>> importParams = params(FIELD_PAYLOAD_BASE64, payloadBase64);

    Map<String, Object> imported = target.importData(OTHER_APP_ID, importParams);

    assertEquals(true, imported.get(FIELD_IMPORTED));
    assertEquals(
        THEME_DARK_JSON,
        target.getRecord(OTHER_APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY).get(FIELD_VALUE_TEXT));
  }

  @Test
  void importData_whenExportContainsEmptyValue_expectEmptyRecordImported() {
    AppDataRecord emptyRecord =
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            "empty",
            new AppDataRecord.Payload("application/octet-stream", 1, new byte[0]),
            NOW,
            NOW);
    String payloadBase64 =
        payloadBase64(
            new AppDataExportPayload(
                    AppDataExportPayload.CURRENT_EXPORT_VERSION,
                    APP_ID,
                    NOW,
                    List.of(uiStateNamespace()),
                    List.of(emptyRecord))
                .toJsonBytes());
    AppDataService target = service(config(128, 16, 4, 4096, 4096));

    Map<String, Object> imported =
        target.importData(APP_ID, params(FIELD_PAYLOAD_BASE64, payloadBase64));
    Map<String, Object> importedRecord = target.getRecord(APP_ID, UI_STATE_NAMESPACE, "empty");

    assertEquals(true, imported.get(FIELD_IMPORTED));
    assertEquals(0, importedRecord.get("valueBytes"));
    assertEquals("", importedRecord.get("valueBase64"));
  }

  @Test
  void exportImport_whenNamespaceHasOnlySchemaMetadata_expectNamespaceRoundTrips() {
    AppDataService service = service(config(128, 16, 4, 4096, 4096));
    service.putRecord(APP_ID, recordParams(PROFILE_DRAFT_NAMESPACE, DRAFT_KEY, "{}"));
    service.updateSchema(
        APP_ID,
        PROFILE_DRAFT_NAMESPACE,
        params(
            PARAM_FROM_SCHEMA_VERSION,
            "1",
            PARAM_TO_SCHEMA_VERSION,
            "2",
            "summary",
            "draft schema"));
    service.deleteRecord(APP_ID, PROFILE_DRAFT_NAMESPACE, DRAFT_KEY);
    String payloadBase64 = (String) service.exportData(APP_ID, Map.of()).get(FIELD_PAYLOAD_BASE64);
    AppDataService target = service(config(128, 16, 4, 4096, 4096));

    Map<String, Object> imported =
        target.importData(APP_ID, params(FIELD_PAYLOAD_BASE64, payloadBase64));
    Map<String, Object> namespace = target.getNamespace(APP_ID, PROFILE_DRAFT_NAMESPACE);

    assertEquals(true, imported.get(FIELD_IMPORTED));
    assertEquals(1, imported.get("namespaceCount"));
    assertEquals(0, imported.get(FIELD_RECORD_COUNT));
    assertEquals(2, namespace.get(FIELD_SCHEMA_VERSION));
    assertTrue(namespace.toString().contains("draft schema"));
  }

  @Test
  void importData_whenReplacingNamespace_expectOldRecordsRemovedOnlyAfterReplacementWritten() {
    AppDataService source = service(config(128, 16, 4, 4096, 4096));
    source.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "new"));
    String payloadBase64 = (String) source.exportData(APP_ID, Map.of()).get(FIELD_PAYLOAD_BASE64);
    AppDataService target = service(config(128, 16, 4, 4096, 4096));
    target.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "old"));
    target.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, STALE_KEY, STALE_KEY));

    Map<String, Object> imported =
        target.importData(
            APP_ID, params(FIELD_PAYLOAD_BASE64, payloadBase64, "mode", "replaceNamespace"));

    assertEquals(true, imported.get(FIELD_IMPORTED));
    assertEquals(
        "new", target.getRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY).get(FIELD_VALUE_TEXT));
    PlatformApiException stale =
        assertThrows(
            PlatformApiException.class,
            () -> target.getRecord(APP_ID, UI_STATE_NAMESPACE, STALE_KEY));
    assertEquals("app_data_record_not_found", stale.errorCode());
  }

  @Test
  void importData_whenReplaceWriteFails_expectNamespaceNotDeletedFirst() throws Exception {
    AppDataStore store = mock(AppDataStore.class);
    AppDataNamespaceMetadata currentNamespace = uiStateNamespace();
    AppDataRecordSummary oldSummary = settingsSummary(3);
    AppDataRecord importedRecord =
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(
                AppDataRecord.JSON_CONTENT_TYPE, 1, "new".getBytes(StandardCharsets.UTF_8)),
            NOW,
            NOW);
    String payloadBase64 =
        payloadBase64(
            new AppDataExportPayload(
                    AppDataExportPayload.CURRENT_EXPORT_VERSION,
                    APP_ID,
                    NOW,
                    List.of(currentNamespace),
                    List.of(importedRecord))
                .toJsonBytes());
    when(store.listRecordSummaries(APP_ID, null)).thenReturn(List.of(oldSummary));
    when(store.listRecordSummaries(APP_ID, UI_STATE_NAMESPACE)).thenReturn(List.of(oldSummary));
    when(store.listNamespaces(APP_ID)).thenReturn(List.of(currentNamespace));
    when(store.readNamespace(APP_ID, UI_STATE_NAMESPACE)).thenReturn(Optional.of(currentNamespace));
    doThrow(new IOException("write failed")).when(store).writeRecord(any(AppDataRecord.class));
    AppDataService service =
        new AppDataService(
            store,
            null,
            config(128, 16, 4, 4096, 4096),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new AppDiskUsageScanner());
    Map<String, List<String>> replaceImportParams =
        params(FIELD_PAYLOAD_BASE64, payloadBase64, "mode", "replaceNamespace");

    PlatformApiException failure =
        assertThrows(
            PlatformApiException.class, () -> service.importData(APP_ID, replaceImportParams));

    assertEquals("app_data_store_unavailable", failure.errorCode());
    verify(store, never()).deleteNamespace(APP_ID, UI_STATE_NAMESPACE);
    verify(store, never()).deleteRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY);
  }

  @Test
  void exportData_whenProjectedPayloadExceedsLimit_expectRejectsBeforeLoadingValues()
      throws Exception {
    AppDataStore store = mock(AppDataStore.class);
    AppDataNamespaceMetadata namespace = uiStateNamespace();
    AppDataRecordSummary summary = settingsSummary(128);
    when(store.listNamespaces(APP_ID)).thenReturn(List.of(namespace));
    when(store.listRecordSummaries(APP_ID, null)).thenReturn(List.of(summary));
    when(store.listRecords(APP_ID, null))
        .thenThrow(new AssertionError("record values must not be loaded for oversized exports"));
    AppDataService service =
        new AppDataService(
            store,
            null,
            config(256, 16, 4, 96, 4096),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new AppDiskUsageScanner());
    Map<String, List<String>> exportParameters = Map.of();

    PlatformApiException failure =
        assertThrows(
            PlatformApiException.class, () -> service.exportData(APP_ID, exportParameters));

    assertEquals("app_data_export_too_large", failure.errorCode());
    verify(store, never()).listRecords(APP_ID, null);
  }

  @Test
  void status_whenRecordSummaryReadFails_expectStoreUnavailable() throws Exception {
    AppDataStore store = mock(AppDataStore.class);
    when(store.listNamespaces(APP_ID)).thenReturn(List.of(uiStateNamespace()));
    when(store.listRecordSummaries(APP_ID, null)).thenThrow(new IOException("read failed"));
    AppDataService service =
        new AppDataService(
            store,
            null,
            config(256, 16, 4, 4096, 4096),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new AppDiskUsageScanner());

    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> service.status(APP_ID));

    assertEquals("app_data_store_unavailable", failure.errorCode());
  }

  @Test
  void importData_whenMigrationHistoryDowngrades_expectInvalidImportError() {
    AppDataService service = service(config(128, 16, 4, 4096, 4096));
    String payload =
        """
        {
          "exportVersion": 1,
          "appId": "feed-reader",
          "exportedAt": "2026-05-24T12:00:00Z",
          "namespaces": [
            {
              "namespace": "ui-state",
              "schemaVersion": 2,
              "createdAt": "2026-05-24T12:00:00Z",
              "updatedAt": "2026-05-24T12:00:00Z",
              "migrationHistory": [
                {
                  "fromSchemaVersion": 2,
                  "toSchemaVersion": 1,
                  "summary": "downgrade",
                  "migratedAt": "2026-05-24T12:00:00Z"
                }
              ]
            }
          ],
          "records": []
        }
        """;
    String payloadBase64 =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    Map<String, List<String>> importParams = params(FIELD_PAYLOAD_BASE64, payloadBase64);

    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> service.importData(APP_ID, importParams));

    assertEquals(400, failure.statusCode());
    assertEquals("invalid_app_data_import", failure.errorCode());
  }

  @Test
  void importData_whenMigrationHistoryExceedsLimit_expectInvalidImportError() {
    AppDataService service = service(config(128, 16, 4, 4096, 4096, 2));
    AppDataNamespaceMetadata namespace =
        uiStateNamespace(4, List.of(migration(1, 2), migration(2, 3), migration(3, 4)));
    String payloadBase64 =
        payloadBase64(
            new AppDataExportPayload(
                    AppDataExportPayload.CURRENT_EXPORT_VERSION,
                    APP_ID,
                    NOW,
                    List.of(namespace),
                    List.of())
                .toJsonBytes());
    Map<String, List<String>> importParams = params(FIELD_PAYLOAD_BASE64, payloadBase64);

    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> service.importData(APP_ID, importParams));

    assertEquals(400, failure.statusCode());
    assertEquals("invalid_app_data_import", failure.errorCode());
  }

  @Test
  void importData_whenMigrationMetadataCannotFitManifestQuota_expectQuotaExceededBeforeWrite()
      throws Exception {
    Path dataRoot = tempDir.resolve("data");
    Files.createDirectories(dataRoot.resolve(APP_ID));
    AppDataService service =
        new AppDataService(
            new FileAppDataStore(dataRoot),
            appHostWithDataQuota(dataRoot, 8_500L),
            config(128, 16, 4, 4096, 4096),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new AppDiskUsageScanner());
    AppDataNamespaceMetadata namespace =
        uiStateNamespace(3, List.of(migration(1, 2), migration(2, 3)));
    String payloadBase64 =
        payloadBase64(
            new AppDataExportPayload(
                    AppDataExportPayload.CURRENT_EXPORT_VERSION,
                    APP_ID,
                    NOW,
                    List.of(namespace),
                    List.of())
                .toJsonBytes());
    Map<String, List<String>> importParams = params(FIELD_PAYLOAD_BASE64, payloadBase64);

    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> service.importData(APP_ID, importParams));

    assertEquals(ERROR_QUOTA_EXCEEDED, failure.errorCode());
    PlatformApiException missing =
        assertThrows(
            PlatformApiException.class, () -> service.getNamespace(APP_ID, UI_STATE_NAMESPACE));
    assertEquals("app_data_namespace_not_found", missing.errorCode());
  }

  @Test
  void advanceUpdateMigrationDryRunPayload_whenOutputExceedsImportQuota_expectQuotaError() {
    AppDataService service = service(config(128, 1, 4, 4096, 4096));
    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "ok"));
    byte[] outputPayload =
        migrationOutputPayloadBytes(
            List.of(
                migratedRecord(SETTINGS_KEY, "{\"theme\":\"dark\"}"),
                migratedRecord("layout", "{\"density\":\"compact\"}")));

    PlatformApiException failure =
        assertThrows(
            PlatformApiException.class,
            () ->
                service.advanceUpdateMigrationDryRunPayload(
                    APP_ID, UI_STATE_NAMESPACE, 1, 2, "dry-run", outputPayload));

    assertEquals(ERROR_QUOTA_EXCEEDED, failure.errorCode());
    assertEquals(1, service.status(APP_ID).get(FIELD_RECORD_COUNT));
  }

  @Test
  void advanceUpdateMigrationDryRunPayload_whenTargetManifestRaisesQuota_expectTargetQuotaUsed()
      throws Exception {
    Path dataRoot = tempDir.resolve("data");
    Files.createDirectories(dataRoot.resolve(APP_ID));
    AtomicLong installedQuotaBytes = new AtomicLong(Long.MAX_VALUE);
    AppDataService service =
        new AppDataService(
            new InMemoryAppDataStore(),
            appHostWithMutableDataQuota(dataRoot, installedQuotaBytes),
            config(4096, 16, 4, 65536, 65536),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new AppDiskUsageScanner(),
            true);
    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "ok"));
    long currentUsageBytes = quotaDataUsageBytes(service);
    installedQuotaBytes.set(currentUsageBytes);
    byte[] outputPayload =
        migrationOutputPayloadBytes(
            List.of(
                migratedRecord(
                    SETTINGS_KEY, "{\"theme\":\"dark\",\"payload\":\"" + "x".repeat(512) + "\"}")));

    PlatformApiException installedQuotaFailure =
        assertThrows(
            PlatformApiException.class,
            () ->
                service.advanceUpdateMigrationDryRunPayload(
                    APP_ID, UI_STATE_NAMESPACE, 1, 2, "dry-run", outputPayload));
    byte[] advancedPayload =
        service.advanceUpdateMigrationDryRunPayload(
            APP_ID,
            UI_STATE_NAMESPACE,
            1,
            2,
            "dry-run",
            outputPayload,
            currentUsageBytes + 20_000L);

    assertEquals(ERROR_QUOTA_EXCEEDED, installedQuotaFailure.errorCode());
    assertTrue(advancedPayload.length > 0);
    assertEquals(1, service.getNamespace(APP_ID, UI_STATE_NAMESPACE).get(FIELD_SCHEMA_VERSION));
  }

  @Test
  void
      preflightUpdateMigrationDryRunPayloads_whenCombinedOutputExceedsRecordQuota_expectQuotaError() {
    AppDataService service = service(config(4096, 3, 4, 65536, 65536));
    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "ok"));
    service.putRecord(APP_ID, recordParams(PROFILE_DRAFT_NAMESPACE, DRAFT_KEY, "draft"));
    byte[] uiOutput =
        migrationOutputPayloadBytes(
            UI_STATE_NAMESPACE,
            List.of(
                migratedRecord(UI_STATE_NAMESPACE, SETTINGS_KEY, "{\"theme\":\"dark\"}", 2),
                migratedRecord(UI_STATE_NAMESPACE, "layout", "{\"density\":\"compact\"}", 2)));
    byte[] profileOutput =
        migrationOutputPayloadBytes(
            PROFILE_DRAFT_NAMESPACE,
            List.of(
                migratedRecord(PROFILE_DRAFT_NAMESPACE, DRAFT_KEY, "{\"body\":\"draft\"}", 2),
                migratedRecord(PROFILE_DRAFT_NAMESPACE, "title", "{\"text\":\"Draft\"}", 2)));
    byte[] uiAdvanced =
        service.advanceUpdateMigrationDryRunPayload(
            APP_ID, UI_STATE_NAMESPACE, 1, 2, "ui dry-run", uiOutput);
    byte[] profileAdvanced =
        service.advanceUpdateMigrationDryRunPayload(
            APP_ID, PROFILE_DRAFT_NAMESPACE, 1, 2, "profile dry-run", profileOutput);
    List<byte[]> projectedPayloads = List.of(uiAdvanced, profileAdvanced);

    PlatformApiException failure =
        assertThrows(
            PlatformApiException.class,
            () -> service.preflightUpdateMigrationDryRunPayloads(APP_ID, projectedPayloads));

    assertEquals(ERROR_QUOTA_EXCEEDED, failure.errorCode());
    assertEquals(2, service.status(APP_ID).get(FIELD_RECORD_COUNT));
    assertEquals(1, service.getNamespace(APP_ID, UI_STATE_NAMESPACE).get(FIELD_SCHEMA_VERSION));
    assertEquals(
        1, service.getNamespace(APP_ID, PROFILE_DRAFT_NAMESPACE).get(FIELD_SCHEMA_VERSION));
  }

  @Test
  void advanceUpdateMigrationDryRunPayload_whenChainedDryRun_expectNamespaceTotalsMatchRecords() {
    AppDataService service = service(config(4096, 16, 4, 65536, 65536));
    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "ok"));
    byte[] stepOneOutput =
        migrationOutputPayloadBytes(
            List.of(
                migratedRecord(SETTINGS_KEY, "{\"theme\":\"dark\"}"),
                migratedRecord("layout", "{\"density\":\"compact\"}")));

    byte[] stepTwoInput =
        service.advanceUpdateMigrationDryRunPayload(
            APP_ID, UI_STATE_NAMESPACE, 1, 2, "step one dry-run", stepOneOutput);

    AppDataExportPayload stepTwoPayload = AppDataExportPayload.parseForImport(stepTwoInput, APP_ID);
    Map<String, Object> stepTwoNamespaceJson = firstNamespaceJson(stepTwoInput);
    assertEquals(2L, stepTwoNamespaceJson.get(FIELD_SCHEMA_VERSION));
    assertEquals(2L, stepTwoNamespaceJson.get(FIELD_RECORD_COUNT));
    assertEquals(
        importedValueBytes(stepTwoPayload.records()), stepTwoNamespaceJson.get("totalBytes"));

    byte[] stepTwoOutput =
        new AppDataExportPayload(
                AppDataExportPayload.CURRENT_EXPORT_VERSION,
                APP_ID,
                NOW,
                stepTwoPayload.namespaces(),
                List.of(
                    migratedRecord(SETTINGS_KEY, "{\"theme\":\"dark\",\"layout\":\"compact\"}", 3),
                    migratedRecord("layout", "{\"density\":\"compact\"}", 3)))
            .toJsonBytes();
    byte[] finalPayloadBytes =
        service.advanceUpdateMigrationDryRunPayload(
            APP_ID, UI_STATE_NAMESPACE, 2, 3, "step two dry-run", stepTwoOutput);
    AppDataExportPayload finalPayload =
        AppDataExportPayload.parseForImport(finalPayloadBytes, APP_ID);
    Map<String, Object> finalNamespaceJson = firstNamespaceJson(finalPayloadBytes);

    assertEquals(3L, finalNamespaceJson.get(FIELD_SCHEMA_VERSION));
    assertEquals(2L, finalNamespaceJson.get(FIELD_RECORD_COUNT));
    assertEquals(importedValueBytes(finalPayload.records()), finalNamespaceJson.get("totalBytes"));
    assertEquals(1, service.getNamespace(APP_ID, UI_STATE_NAMESPACE).get(FIELD_SCHEMA_VERSION));
  }

  @Test
  void updateSchema_whenManifestQuotaCannotHoldMetadata_expectQuotaExceededBeforeWrite()
      throws Exception {
    Path dataRoot = tempDir.resolve("data");
    Files.createDirectories(dataRoot.resolve(APP_ID));
    AppDataService service =
        new AppDataService(
            new FileAppDataStore(dataRoot),
            appHostWithDataQuota(dataRoot, 1L),
            config(128, 16, 4, 4096, 4096),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new AppDiskUsageScanner());
    Map<String, List<String>> schemaParams =
        params(PARAM_FROM_SCHEMA_VERSION, "1", PARAM_TO_SCHEMA_VERSION, "2");

    PlatformApiException failure =
        assertThrows(
            PlatformApiException.class,
            () -> service.updateSchema(APP_ID, PROFILE_DRAFT_NAMESPACE, schemaParams));

    assertEquals(ERROR_QUOTA_EXCEEDED, failure.errorCode());
    assertFalse(failure.getMessage().contains(dataRoot.toString()));
    PlatformApiException missing =
        assertThrows(
            PlatformApiException.class,
            () -> service.getNamespace(APP_ID, PROFILE_DRAFT_NAMESPACE));
    assertEquals("app_data_namespace_not_found", missing.errorCode());
  }

  @Test
  void putRecord_whenStoreUsageOutsideDataDir_expectManifestQuotaIncludesCurrentStoreUsage()
      throws Exception {
    Path dataRoot = tempDir.resolve("data");
    Files.createDirectories(dataRoot.resolve(APP_ID));
    AppDataService service =
        new AppDataService(
            new InMemoryAppDataStore(),
            appHostWithDataQuota(dataRoot, 11_000L),
            config(128, 16, 4, 4096, 4096),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new AppDiskUsageScanner(),
            true);
    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, "one", "ok"));
    Map<String, List<String>> secondRecordParams = recordParams(UI_STATE_NAMESPACE, "two", "ok");

    PlatformApiException failure =
        assertThrows(
            PlatformApiException.class, () -> service.putRecord(APP_ID, secondRecordParams));

    assertEquals(ERROR_QUOTA_EXCEEDED, failure.errorCode());
  }

  @Test
  void putRecord_whenReplacingRecordAtManifestQuota_expectExistingMetadataNotChargedAgain()
      throws Exception {
    Path dataRoot = tempDir.resolve("data");
    Files.createDirectories(dataRoot.resolve(APP_ID));
    AtomicLong quotaBytes = new AtomicLong(Long.MAX_VALUE);
    InMemoryAppDataStore store = new InMemoryAppDataStore();
    AppDataService service =
        new AppDataService(
            store,
            appHostWithMutableDataQuota(dataRoot, quotaBytes),
            config(128, 16, 4, 4096, 4096),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new AppDiskUsageScanner(),
            true);
    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "ok"));
    quotaBytes.set(quotaDataUsageBytes(service));
    Map<String, List<String>> replacementParams =
        recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "ok");

    Map<String, Object> replaced = service.putRecord(APP_ID, replacementParams);

    assertEquals("ok", replaced.get(FIELD_VALUE_TEXT));
  }

  @Test
  void putRecord_whenLimitsExceeded_expectPathFreeQuotaErrors() {
    AppDataService service = service(config(4, 1, 1, 128, 128));
    Map<String, List<String>> oversizedRecordParams =
        recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "too-large");

    PlatformApiException tooLarge =
        assertThrows(
            PlatformApiException.class, () -> service.putRecord(APP_ID, oversizedRecordParams));
    assertEquals("app_data_record_too_large", tooLarge.errorCode());
    assertFalse(tooLarge.getMessage().contains("/"));

    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, "one", "ok"));
    Map<String, List<String>> secondRecordParams = recordParams(UI_STATE_NAMESPACE, "two", "ok");
    PlatformApiException quota =
        assertThrows(
            PlatformApiException.class, () -> service.putRecord(APP_ID, secondRecordParams));
    assertEquals(ERROR_QUOTA_EXCEEDED, quota.errorCode());
    assertFalse(quota.getMessage().contains("/"));
  }

  @Test
  void putRecord_whenIdentifierContainsTraversal_expectPathFreeValidationError() {
    AppDataService service = service(config(64, 16, 4, 4096, 4096));
    Map<String, List<String>> traversalParams = recordParams("../secret", SETTINGS_KEY, "one");

    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> service.putRecord(APP_ID, traversalParams));

    assertEquals("invalid_app_data_identifier", failure.errorCode());
    assertFalse(failure.getMessage().contains(".."));
    assertFalse(failure.getMessage().contains("/"));
  }

  @Test
  void createUpdateSnapshot_whenOtherAppHasData_expectSnapshotIsAppScoped() {
    AppDataService service = service(config(64, 16, 4, 4096, 4096));
    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "one"));
    service.putRecord(OTHER_APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "other"));

    AppDataUpdateSnapshot snapshot = service.createUpdateSnapshot(APP_ID);

    assertEquals(APP_ID, snapshot.appId());
    assertEquals(1, snapshot.payload().records().size());
    assertEquals(
        "one", new String(snapshot.payload().records().getFirst().value(), StandardCharsets.UTF_8));
  }

  @Test
  void restoreUpdateSnapshot_whenDataChangedAfterSnapshot_expectOriginalStateRestored() {
    AppDataService service = service(config(64, 16, 4, 4096, 4096));
    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "one"));
    AppDataUpdateSnapshot snapshot = service.createUpdateSnapshot(APP_ID);
    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "two"));
    service.putRecord(APP_ID, recordParams(PROFILE_DRAFT_NAMESPACE, DRAFT_KEY, "draft"));

    service.restoreUpdateSnapshot(APP_ID, snapshot);

    assertEquals(
        "one", service.getRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY).get(FIELD_VALUE_TEXT));
    PlatformApiException missing =
        assertThrows(
            PlatformApiException.class,
            () -> service.getRecord(APP_ID, PROFILE_DRAFT_NAMESPACE, DRAFT_KEY));
    assertEquals("app_data_record_not_found", missing.errorCode());
  }

  @Test
  void appFacingWrites_whenUpdateMigrationWriteBarrierActive_expectMigrationInProgressConflict() {
    AppDataService service = service(config(128, 16, 4, 4096, 4096));
    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "one"));
    String payloadBase64 = payloadBase64(themeExportPayloadBytes());
    Map<String, List<String>> schemaParams =
        params(PARAM_FROM_SCHEMA_VERSION, "1", PARAM_TO_SCHEMA_VERSION, "2");

    try (var _ = service.beginUpdateMigrationWriteBarrier(APP_ID)) {
      assertBlockedByMigration(
          () -> service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, "two", "two")));
      assertBlockedByMigration(
          () -> service.deleteRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY));
      assertBlockedByMigration(
          () -> service.updateSchema(APP_ID, UI_STATE_NAMESPACE, schemaParams));
      assertBlockedByMigration(
          () -> service.importData(APP_ID, params(FIELD_PAYLOAD_BASE64, payloadBase64)));
      assertBlockedByMigration(() -> service.deleteNamespace(APP_ID, UI_STATE_NAMESPACE));
      assertBlockedByMigration(() -> service.clearAppState(APP_ID));

      service.putRecord(OTHER_APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "other"));
    }

    Map<String, Object> written =
        service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, "two", "two"));
    assertEquals("two", written.get(FIELD_VALUE_TEXT));
  }

  @Test
  void updateMigrationImport_whenWriteBarrierActive_expectInternalMigrationWritesAllowed() {
    AppDataService service = service(config(128, 16, 4, 4096, 4096));
    service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, SETTINGS_KEY, "one"));

    try (var _ = service.beginUpdateMigrationWriteBarrier(APP_ID)) {
      service.importUpdateMigrationPayload(
          APP_ID,
          UI_STATE_NAMESPACE,
          1,
          2,
          migrationOutputPayloadBytes(List.of(migratedRecord(SETTINGS_KEY, "migrated"))));
      service.recordUpdateMigration(APP_ID, UI_STATE_NAMESPACE, 1, 2, "signed update migration");

      assertBlockedByMigration(
          () -> service.putRecord(APP_ID, recordParams(UI_STATE_NAMESPACE, "two", "two")));
    }

    Map<String, Object> migratedStateRecord =
        service.getRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY);
    assertEquals(2, migratedStateRecord.get(FIELD_SCHEMA_VERSION));
    assertEquals("migrated", migratedStateRecord.get(FIELD_VALUE_TEXT));
    assertEquals(2, service.getNamespace(APP_ID, UI_STATE_NAMESPACE).get(FIELD_SCHEMA_VERSION));
  }

  @Test
  void defaults_whenImportPayloadUsesUrlSafeFormEncoding_expectFitsPlatformApiBodyCap() {
    AppDataStoreConfig defaults = AppDataStoreConfig.defaults();
    String encodedPayload =
        Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[defaults.maxImportBytes()]);

    assertEquals(defaults.maxImportBytes(), defaults.maxExportBytes());
    assertTrue(FIELD_PAYLOAD_BASE64.length() + "=".length() + encodedPayload.length() <= 1_048_576);
  }

  private static AppDataService service(AppDataStoreConfig config) {
    return new AppDataService(
        new InMemoryAppDataStore(),
        null,
        config,
        Clock.fixed(NOW, ZoneOffset.UTC),
        new AppDiskUsageScanner());
  }

  private static AppDataStoreConfig config(
      int maxRecordBytes,
      int maxRecordsPerApp,
      int maxNamespacesPerApp,
      int maxExportBytes,
      int maxImportBytes) {
    return config(
        maxRecordBytes, maxRecordsPerApp, maxNamespacesPerApp, maxExportBytes, maxImportBytes, 8);
  }

  private static AppDataStoreConfig config(
      int maxRecordBytes,
      int maxRecordsPerApp,
      int maxNamespacesPerApp,
      int maxExportBytes,
      int maxImportBytes,
      int maxMigrationHistory) {
    return new AppDataStoreConfig(
        maxRecordBytes,
        maxRecordsPerApp,
        maxNamespacesPerApp,
        maxExportBytes,
        maxImportBytes,
        maxMigrationHistory);
  }

  private static Map<String, List<String>> recordParams(
      String namespace, String key, String value) {
    return params(
        "namespace",
        namespace,
        "key",
        key,
        FIELD_SCHEMA_VERSION,
        "1",
        "contentType",
        AppDataRecord.JSON_CONTENT_TYPE,
        FIELD_VALUE_TEXT,
        value);
  }

  private static AppDataNamespaceMetadata uiStateNamespace() {
    return uiStateNamespace(1, List.of());
  }

  private static AppDataNamespaceMetadata uiStateNamespace(
      int schemaVersion, List<AppDataMigrationRecord> migrations) {
    return new AppDataNamespaceMetadata(
        APP_ID,
        UI_STATE_NAMESPACE,
        schemaVersion,
        0,
        0L,
        NOW,
        NOW,
        migrations.isEmpty() ? null : migrations.getLast().migratedAt(),
        migrations);
  }

  private static AppDataMigrationRecord migration(int fromSchemaVersion, int toSchemaVersion) {
    return new AppDataMigrationRecord(
        fromSchemaVersion,
        toSchemaVersion,
        "migration " + fromSchemaVersion + " to " + toSchemaVersion,
        NOW.plusSeconds(toSchemaVersion));
  }

  private static AppDataRecordSummary settingsSummary(int valueBytes) {
    return new AppDataRecordSummary(
        UI_STATE_NAMESPACE,
        SETTINGS_KEY,
        AppDataRecord.JSON_CONTENT_TYPE,
        1,
        valueBytes,
        AppDataRecord.sha256(new byte[valueBytes]),
        NOW,
        NOW);
  }

  private static byte[] themeExportPayloadBytes() {
    AppDataRecord appDataRecord =
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(
                AppDataRecord.JSON_CONTENT_TYPE,
                1,
                THEME_DARK_JSON.getBytes(StandardCharsets.UTF_8)),
            NOW,
            NOW);
    return new AppDataExportPayload(
            AppDataExportPayload.CURRENT_EXPORT_VERSION,
            APP_ID,
            NOW,
            List.of(uiStateNamespace()),
            List.of(appDataRecord))
        .toJsonBytes();
  }

  private static byte[] migrationOutputPayloadBytes(List<AppDataRecord> records) {
    return migrationOutputPayloadBytes(UI_STATE_NAMESPACE, records);
  }

  private static byte[] migrationOutputPayloadBytes(String namespace, List<AppDataRecord> records) {
    return new AppDataExportPayload(
            AppDataExportPayload.CURRENT_EXPORT_VERSION,
            APP_ID,
            NOW,
            List.of(namespaceMetadata(namespace)),
            records)
        .toJsonBytes();
  }

  private static AppDataRecord migratedRecord(String key, String value) {
    return migratedRecord(key, value, 2);
  }

  private static AppDataRecord migratedRecord(String key, String value, int schemaVersion) {
    return migratedRecord(UI_STATE_NAMESPACE, key, value, schemaVersion);
  }

  private static AppDataRecord migratedRecord(
      String namespace, String key, String value, int schemaVersion) {
    return new AppDataRecord(
        APP_ID,
        namespace,
        key,
        new AppDataRecord.Payload(
            AppDataRecord.JSON_CONTENT_TYPE, schemaVersion, value.getBytes(StandardCharsets.UTF_8)),
        NOW,
        NOW);
  }

  private static AppDataNamespaceMetadata namespaceMetadata(String namespace) {
    return new AppDataNamespaceMetadata(APP_ID, namespace, 1, 0, 0L, NOW, NOW, null, List.of());
  }

  private static long importedValueBytes(List<AppDataRecord> records) {
    return records.stream().mapToLong(AppDataRecord::valueBytes).sum();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> firstNamespaceJson(byte[] payloadBytes) {
    Map<String, Object> payloadJson =
        (Map<String, Object>)
            AppDataJsonParser.parse(new String(payloadBytes, StandardCharsets.UTF_8));
    return (Map<String, Object>) ((List<?>) payloadJson.get("namespaces")).getFirst();
  }

  private static String payloadBase64(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static Map<String, List<String>> params(String... pairs) {
    java.util.LinkedHashMap<String, List<String>> values = new java.util.LinkedHashMap<>();
    for (int index = 0; index < pairs.length; index += 2) {
      values.put(pairs[index], List.of(pairs[index + 1]));
    }
    return values;
  }

  private static void assertBlockedByMigration(Runnable operation) {
    PlatformApiException failure = assertThrows(PlatformApiException.class, operation::run);
    assertEquals(ERROR_MIGRATION_IN_PROGRESS, failure.errorCode());
  }

  private static long quotaDataUsageBytes(AppDataService service) {
    @SuppressWarnings("unchecked")
    Map<String, Object> quota = (Map<String, Object>) service.status(APP_ID).get("quota");
    return ((Number) quota.get("dataUsageBytes")).longValue();
  }

  private static AppHost appHostWithDataQuota(Path dataRoot, long dataQuotaBytes)
      throws java.io.IOException {
    AppHost appHost = mock(AppHost.class);
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedApp(dataRoot, dataQuotaBytes)));
    return appHost;
  }

  private static AppHost appHostWithMutableDataQuota(Path dataRoot, AtomicLong dataQuotaBytes)
      throws java.io.IOException {
    AppHost appHost = mock(AppHost.class);
    when(appHost.describe(APP_ID))
        .thenAnswer(_ -> Optional.of(installedApp(dataRoot, dataQuotaBytes.get())));
    return appHost;
  }

  private static InstalledAppSnapshot installedApp(Path dataRoot, long dataQuotaBytes) {
    Path root = dataRoot.getParent();
    AppManifest manifest =
        new AppManifest(
            1,
            APP_ID,
            "Feed Reader",
            "1.0.0",
            "bin/launch.sh",
            AppUiMode.NONE,
            null,
            List.of(),
            dataQuotaBytes,
            null);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            APP_ID,
            root.resolve("installed").resolve(APP_ID),
            dataRoot.resolve(APP_ID),
            root.resolve("cache").resolve(APP_ID),
            root.resolve("run").resolve(APP_ID));
    return new InstalledAppSnapshot(manifest, paths);
  }
}
