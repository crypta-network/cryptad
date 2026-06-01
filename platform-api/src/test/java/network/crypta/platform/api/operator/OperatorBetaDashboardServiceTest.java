package network.crypta.platform.api.operator;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
  private static final Clock CLOCK =
      Clock.fixed(Instant.parse("2026-05-24T12:00:00Z"), ZoneOffset.UTC);

  @Test
  void dashboard_whenUpdateCandidateAvailable_expectPendingCountAndStageActionAvailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID)).thenReturn(updateSummary(availableCandidate()));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    Map<String, Object> summary = mapValue(dashboard.get("summary"));
    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertEquals(1L, summary.get("pendingUpdateCount"));
    assertTrue(actionAvailable(actions, "check-app-update"));
    assertTrue(actionAvailable(actions, "stage-app-update"));
  }

  @Test
  void dashboard_whenUpdateCandidateRequiresAcknowledgement_expectStageActionUnavailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(updateSummary(availableCandidate(Map.of("requiresAcknowledgement", true))));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    Map<String, Object> summary = mapValue(dashboard.get("summary"));
    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertEquals(1L, summary.get("pendingUpdateCount"));
    assertFalse(actionAvailable(actions, "stage-app-update"));
  }

  @Test
  void dashboard_whenAppRunningWithStagedUpdateAndRollback_expectApplyAndRollbackUnavailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(updateSummary(availableCandidate(), stagedUpdate(), rollbackAvailable()));

    Map<String, Object> dashboard = service(appsHandler(true), updateService).dashboard();

    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertFalse(actionAvailable(actions, "apply-app-update"));
    assertFalse(actionAvailable(actions, "rollback-app"));
  }

  @Test
  void dashboard_whenAppStoppedWithStagedUpdateAndRollback_expectApplyAndRollbackAvailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(updateSummary(availableCandidate(), stagedUpdate(), rollbackAvailable()));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertTrue(actionAvailable(actions, "apply-app-update"));
    assertTrue(actionAvailable(actions, "rollback-app"));
  }

  @Test
  void dashboard_whenUpdateServiceUnavailable_expectUpdateRecoveryActionsUnavailable() {
    Map<String, Object> dashboard = service(appsHandler(), null).dashboard();

    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertFalse(actionAvailable(actions, "check-app-update"));
    assertFalse(actionAvailable(actions, "stage-app-update"));
    assertFalse(actionAvailable(actions, "apply-app-update"));
    assertFalse(actionAvailable(actions, "rollback-app"));
  }

  @Test
  void dashboard_whenBuildingUninstallRecoveryAction_expectPreserveDataQueryParameter() {
    Map<String, Object> dashboard = service(appsHandler(), null).dashboard();

    Map<String, Object> action =
        action(recoveryActionsForFirstApp(dashboard), "preserve-data-uninstall");
    assertEquals("DELETE", action.get("method"));
    assertEquals("apps/feed-reader?preserveData=true", action.get("path"));
  }

  private static OperatorBetaDashboardService service(
      AppsApiHandler appsApiHandler, AppUpdateService appUpdateService) {
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            appsApiHandler, null, appUpdateService, null),
        new OperatorBetaDashboardService.AppStateSources(null, null, null, null),
        CLOCK);
  }

  private static AppsApiHandler appsHandler() {
    return appsHandler(false);
  }

  private static AppsApiHandler appsHandler(boolean running) {
    AppsApiHandler appsApiHandler = mock(AppsApiHandler.class);
    when(appsApiHandler.list(false)).thenReturn(List.of(installedApp(running)));
    return appsApiHandler;
  }

  private static Map<String, Object> installedApp(boolean running) {
    LinkedHashMap<String, Object> app = new LinkedHashMap<>();
    app.put("appId", APP_ID);
    app.put("name", "Feed Reader");
    app.put("version", "1.0.0");
    app.put("running", running);
    app.put(
        "quota", Map.of("warnings", List.of(), "dataOverLimit", false, "cacheOverLimit", false));
    app.put("sandbox", Map.of("warnings", List.of()));
    app.put("apiCompatibility", Map.of("status", "compatible"));
    return app;
  }

  private static Map<String, Object> updateSummary(Map<String, Object> candidate) {
    return updateSummary(candidate, Map.of("available", false), Map.of("available", false));
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
        "available",
        "autoStageAllowed",
        true,
        "operatorActionRequired",
        false,
        "reviewTrust",
        reviewTrust);
  }

  private static Map<String, Object> stagedUpdate() {
    return Map.of("available", true, "reviewTrust", Map.of());
  }

  private static Map<String, Object> rollbackAvailable() {
    return Map.of("available", true);
  }

  private static List<Map<String, Object>> recoveryActionsForFirstApp(
      Map<String, Object> dashboard) {
    return listOfMaps(listOfMaps(dashboard.get("apps")).getFirst().get("recoveryActions"));
  }

  private static boolean actionAvailable(List<Map<String, Object>> actions, String actionId) {
    return Boolean.TRUE.equals(action(actions, actionId).get("available"));
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
}
