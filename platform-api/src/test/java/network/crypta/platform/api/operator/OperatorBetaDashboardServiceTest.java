package network.crypta.platform.api.operator;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.appcatalogs.AppCatalogsApiHandler;
import network.crypta.platform.api.apps.AppsApiHandler;
import network.crypta.platform.api.appupdates.AppUpdateService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings({"java:S100", "unchecked"})
class OperatorBetaDashboardServiceTest {
  private static final String APP_ID = "feed-reader";
  private static final String APPLY_APP_UPDATE_ACTION = "apply-app-update";
  private static final String AVAILABLE = "available";
  private static final String MANUAL_SOURCE_KIND = "manual";
  private static final String ROLLBACK_APP_ACTION = "rollback-app";
  private static final String SOURCE_KIND_FIELD = "sourceKind";
  private static final String STAGE_APP_UPDATE_ACTION = "stage-app-update";
  private static final String SUMMARY_FIELD = "summary";
  private static final String UPPERCASE_FILE_CATALOG_SOURCE =
      "FILE:///home/operator/private/cryptad-app-catalog.properties";
  private static final String WARNINGS_FIELD = "warnings";
  private static final Clock CLOCK =
      Clock.fixed(Instant.parse("2026-05-24T12:00:00Z"), ZoneOffset.UTC);

  @Test
  void dashboard_whenUpdateCandidateAvailable_expectPendingCountAndStageActionAvailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID)).thenReturn(updateSummary(availableCandidate()));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    Map<String, Object> summary = mapValue(dashboard.get(SUMMARY_FIELD));
    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertEquals(1L, summary.get("pendingUpdateCount"));
    assertTrue(actionAvailable(actions, "check-app-update"));
    assertTrue(actionAvailable(actions, STAGE_APP_UPDATE_ACTION));
  }

  @Test
  void dashboard_whenUpdateCandidateRequiresAcknowledgement_expectStageActionUnavailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(updateSummary(availableCandidate(Map.of("requiresAcknowledgement", true))));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    Map<String, Object> summary = mapValue(dashboard.get(SUMMARY_FIELD));
    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertEquals(1L, summary.get("pendingUpdateCount"));
    assertFalse(actionAvailable(actions, STAGE_APP_UPDATE_ACTION));
  }

  @Test
  void dashboard_whenAppRunningWithStagedUpdateAndRollback_expectApplyAndRollbackUnavailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(updateSummary(availableCandidate(), stagedUpdate(), rollbackAvailable()));

    Map<String, Object> dashboard = service(appsHandler(true), updateService).dashboard();

    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertFalse(actionAvailable(actions, APPLY_APP_UPDATE_ACTION));
    assertFalse(actionAvailable(actions, ROLLBACK_APP_ACTION));
  }

  @Test
  void dashboard_whenAppStoppedWithStagedUpdateAndRollback_expectApplyAndRollbackAvailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(updateSummary(availableCandidate(), stagedUpdate(), rollbackAvailable()));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertTrue(actionAvailable(actions, APPLY_APP_UPDATE_ACTION));
    assertTrue(actionAvailable(actions, ROLLBACK_APP_ACTION));
  }

  @Test
  void dashboard_whenUpdateServiceUnavailable_expectUpdateRecoveryActionsUnavailable() {
    Map<String, Object> dashboard = service(appsHandler(), null).dashboard();

    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertFalse(actionAvailable(actions, "check-app-update"));
    assertFalse(actionAvailable(actions, STAGE_APP_UPDATE_ACTION));
    assertFalse(actionAvailable(actions, APPLY_APP_UPDATE_ACTION));
    assertFalse(actionAvailable(actions, ROLLBACK_APP_ACTION));
  }

  @Test
  void dashboard_whenBuildingUninstallRecoveryAction_expectPreserveDataQueryParameter() {
    Map<String, Object> dashboard = service(appsHandler(), null).dashboard();

    Map<String, Object> action =
        action(recoveryActionsForFirstApp(dashboard), "preserve-data-uninstall");
    assertEquals("DELETE", action.get("method"));
    assertEquals("apps/feed-reader?preserveData=true", action.get("path"));
  }

  @Test
  void dashboard_whenCatalogSourceUsesUppercaseFileUri_expectSourceDisplayRedacted() {
    AppCatalogsApiHandler catalogsApiHandler = mock(AppCatalogsApiHandler.class);
    when(catalogsApiHandler.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogsApiHandler.listRecommendedCatalogs()).thenReturn(List.of());

    Map<String, Object> dashboard = service(appsHandler(), catalogsApiHandler, null).dashboard();

    Map<String, Object> catalog = listOfMaps(dashboard.get("catalogs")).getFirst();
    assertEquals(MANUAL_SOURCE_KIND, catalog.get(SOURCE_KIND_FIELD));
    assertEquals("file:<redacted>", catalog.get("sourceDisplay"));
  }

  @Test
  void dashboard_whenCatalogSourceUsesRemoteUri_expectSourceDisplayRedactedAndDigestRetained() {
    AppCatalogsApiHandler catalogsApiHandler = mock(AppCatalogsApiHandler.class);
    when(catalogsApiHandler.listCatalogs()).thenReturn(List.of(remoteCatalog()));
    when(catalogsApiHandler.listRecommendedCatalogs()).thenReturn(List.of());

    Map<String, Object> dashboard = service(appsHandler(), catalogsApiHandler, null).dashboard();

    Map<String, Object> catalog = listOfMaps(dashboard.get("catalogs")).getFirst();
    assertEquals(MANUAL_SOURCE_KIND, catalog.get(SOURCE_KIND_FIELD));
    assertEquals("https:<redacted>", catalog.get("sourceDisplay"));
    assertTrue(
        catalog.get("sourceDigest") instanceof String digest && digest.matches("[a-f0-9]{64}"));
  }

  @Test
  void dashboard_whenUpdateBlockedByReviewTrust_expectQuotaWarningCountIgnoresAppWarning() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(updateSummary(availableCandidate(Map.of("blocksUpdate", true))));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    Map<String, Object> summary = mapValue(dashboard.get(SUMMARY_FIELD));
    assertEquals(0L, summary.get("quotaWarningCount"));
    assertTrue(warningsForFirstApp(dashboard).contains("app_update_blocked"));
  }

  @Test
  void dashboard_whenAppHostQuotaWarningPresent_expectQuotaWarningCountIncludesApp() {
    Map<String, Object> dashboard =
        service(appsHandler(installedAppWithQuotaWarning()), null).dashboard();

    Map<String, Object> summary = mapValue(dashboard.get(SUMMARY_FIELD));
    assertEquals(1L, summary.get("quotaWarningCount"));
  }

  private static OperatorBetaDashboardService service(
      AppsApiHandler appsApiHandler, AppUpdateService appUpdateService) {
    return service(appsApiHandler, null, appUpdateService);
  }

  private static OperatorBetaDashboardService service(
      AppsApiHandler appsApiHandler,
      AppCatalogsApiHandler appCatalogsApiHandler,
      AppUpdateService appUpdateService) {
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            appsApiHandler, appCatalogsApiHandler, appUpdateService, null),
        new OperatorBetaDashboardService.AppStateSources(null, null, null, null),
        CLOCK);
  }

  private static AppsApiHandler appsHandler() {
    return appsHandler(false);
  }

  private static AppsApiHandler appsHandler(boolean running) {
    return appsHandler(installedApp(running));
  }

  private static AppsApiHandler appsHandler(Map<String, Object> app) {
    AppsApiHandler appsApiHandler = mock(AppsApiHandler.class);
    when(appsApiHandler.list(false)).thenReturn(List.of(app));
    return appsApiHandler;
  }

  private static Map<String, Object> installedApp(boolean running) {
    LinkedHashMap<String, Object> app = new LinkedHashMap<>();
    app.put("appId", APP_ID);
    app.put("name", "Feed Reader");
    app.put("version", "1.0.0");
    app.put("running", running);
    app.put(
        "quota",
        Map.of(WARNINGS_FIELD, List.of(), "dataOverLimit", false, "cacheOverLimit", false));
    app.put("sandbox", Map.of(WARNINGS_FIELD, List.of()));
    app.put("apiCompatibility", Map.of("status", "compatible"));
    return app;
  }

  private static Map<String, Object> installedAppWithQuotaWarning() {
    Map<String, Object> app = installedApp(false);
    app.put(
        "quota",
        Map.of(
            WARNINGS_FIELD,
            List.of("Cache usage exceeds the configured app limit."),
            "dataOverLimit",
            false,
            "cacheOverLimit",
            false));
    return app;
  }

  private static Map<String, Object> catalog() {
    LinkedHashMap<String, Object> catalog = new LinkedHashMap<>();
    catalog.put("catalogId", "local-catalog");
    catalog.put("name", "Local Catalog");
    catalog.put("source", UPPERCASE_FILE_CATALOG_SOURCE);
    catalog.put(SOURCE_KIND_FIELD, "file");
    catalog.put("lastFetchStatus", "success");
    catalog.put("appCount", 0);
    return catalog;
  }

  private static Map<String, Object> remoteCatalog() {
    LinkedHashMap<String, Object> catalog = new LinkedHashMap<>();
    catalog.put("catalogId", "private-beta");
    catalog.put("name", "Private Beta");
    catalog.put("source", "https://staging.example.invalid/private/catalog.json");
    catalog.put(SOURCE_KIND_FIELD, MANUAL_SOURCE_KIND);
    catalog.put("lastFetchStatus", "success");
    catalog.put("appCount", 0);
    return catalog;
  }

  private static Map<String, Object> updateSummary(Map<String, Object> candidate) {
    return updateSummary(candidate, Map.of(AVAILABLE, false), Map.of(AVAILABLE, false));
  }

  private static Map<String, Object> updateSummary(
      Map<String, Object> candidate, Map<String, Object> staged, Map<String, Object> rollback) {
    return Map.of("candidate", candidate, "staged", staged, "rollback", rollback);
  }

  private static Map<String, Object> availableCandidate() {
    return availableCandidate(Map.of());
  }

  private static Map<String, Object> availableCandidate(Map<String, Object> reviewTrust) {
    return Map.of(
        "status",
        AVAILABLE,
        "autoStageAllowed",
        true,
        "operatorActionRequired",
        false,
        "reviewTrust",
        reviewTrust);
  }

  private static Map<String, Object> stagedUpdate() {
    return Map.of(AVAILABLE, true, "reviewTrust", Map.of());
  }

  private static Map<String, Object> rollbackAvailable() {
    return Map.of(AVAILABLE, true);
  }

  private static List<Map<String, Object>> recoveryActionsForFirstApp(
      Map<String, Object> dashboard) {
    return listOfMaps(listOfMaps(dashboard.get("apps")).getFirst().get("recoveryActions"));
  }

  private static List<String> warningsForFirstApp(Map<String, Object> dashboard) {
    return stringList(listOfMaps(dashboard.get("apps")).getFirst().get(WARNINGS_FIELD));
  }

  private static boolean actionAvailable(List<Map<String, Object>> actions, String actionId) {
    return Boolean.TRUE.equals(action(actions, actionId).get(AVAILABLE));
  }

  private static Map<String, Object> action(List<Map<String, Object>> actions, String actionId) {
    return actions.stream()
        .filter(candidate -> actionId.equals(candidate.get("id")))
        .findFirst()
        .orElseThrow();
  }

  private static Map<String, Object> mapValue(Object value) {
    return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
  }

  private static List<Map<String, Object>> listOfMaps(Object value) {
    return value instanceof List<?> list ? (List<Map<String, Object>>) list : List.of();
  }

  private static List<String> stringList(Object value) {
    if (value instanceof List<?> list) {
      return list.stream().map(String.class::cast).toList();
    }
    return List.of();
  }
}
