package network.crypta.platform.api.appupdates;

import java.util.List;
import java.util.Map;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appcatalog.AppCatalogChannel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class AppUpdatesApiHandlerTest {
  private static final String APP_ID = "queue-manager";

  @Mock private AppUpdateService updateService;

  private AppUpdatesApiHandler handler;

  @BeforeEach
  void setUp() {
    handler = new AppUpdatesApiHandler(updateService);
  }

  @Test
  void check_whenRefreshCatalogsQueryIsTrue_expectDelegatesRefresh() {
    Map<String, Object> expected = Map.of("appId", APP_ID);
    when(updateService.check(APP_ID, true)).thenReturn(expected);

    Map<String, Object> result = handler.check(APP_ID, Map.of("refreshCatalogs", List.of("true")));

    assertSame(expected, result);
    verify(updateService).check(APP_ID, true);
  }

  @Test
  void stage_whenSourceSwitchTargetProvided_expectDelegatesExactTargetAndConsent() {
    Map<String, Object> expected = Map.of("status", "staged");
    when(updateService.stage(APP_ID, false, false, false, "consent-digest", "community"))
        .thenReturn(expected);

    Map<String, Object> result =
        handler.stage(
            APP_ID,
            Map.of(
                "sourceSwitchConsent", List.of("consent-digest"),
                "targetCatalogId", List.of("community")));

    assertSame(expected, result);
    verify(updateService).stage(APP_ID, false, false, false, "consent-digest", "community");
  }

  @Test
  void apply_whenQueryOptionsAreProvided_expectDelegatesParsedOptions() {
    Map<String, Object> expected = Map.of("status", "ok");
    when(updateService.apply(eq(APP_ID), any(AppUpdateService.ApplyOptions.class)))
        .thenReturn(expected);

    Map<String, Object> result =
        handler.apply(
            APP_ID,
            Map.of(
                "restart",
                List.of(" TRUE "),
                "healthCheck",
                List.of("Process"),
                "rollbackOnHealthFailure",
                List.of("true")));

    ArgumentCaptor<AppUpdateService.ApplyOptions> optionsCaptor =
        ArgumentCaptor.forClass(AppUpdateService.ApplyOptions.class);
    assertSame(expected, result);
    verify(updateService).apply(eq(APP_ID), optionsCaptor.capture());
    AppUpdateService.ApplyOptions options = optionsCaptor.getValue();
    assertTrue(options.restart());
    assertEquals(AppUpdateService.HealthCheckMode.PROCESS, options.healthCheck());
    assertTrue(options.rollbackOnHealthFailure());
  }

  @Test
  void apply_whenBooleanOptionIsInvalid_expectStableInvalidOption() {
    Map<String, List<String>> queryParameters = Map.of("restart", List.of("maybe"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.apply(APP_ID, queryParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_update_option", exception.errorCode());
    verifyNoInteractions(updateService);
  }

  @Test
  void apply_whenHealthCheckOptionIsInvalid_expectStableInvalidOption() {
    Map<String, List<String>> queryParameters = Map.of("healthCheck", List.of("http"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.apply(APP_ID, queryParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_update_option", exception.errorCode());
    verifyNoInteractions(updateService);
  }

  @Test
  void rollback_whenRestartQueryIsTrue_expectDelegatesRestart() {
    Map<String, Object> expected = Map.of("rollback", "queued");
    when(updateService.rollback(APP_ID, true)).thenReturn(expected);

    Map<String, Object> result = handler.rollback(APP_ID, Map.of("restart", List.of("true")));

    assertSame(expected, result);
    verify(updateService).rollback(APP_ID, true);
  }

  @Test
  void setPolicy_whenModeUsesMixedCaseAndWhitespace_expectDelegatesParsedPolicy() {
    Map<String, Object> expected = Map.of("mode", "apply_when_stopped");
    when(updateService.setPolicy(
            APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED, Set.of(AppCatalogChannel.STABLE)))
        .thenReturn(expected);

    Map<String, Object> result =
        handler.setPolicy(APP_ID, Map.of("mode", List.of(" APPLY_WHEN_STOPPED ")));

    assertSame(expected, result);
    verify(updateService)
        .setPolicy(
            APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED, Set.of(AppCatalogChannel.STABLE));
  }

  @Test
  void setPolicy_whenChannelsAreProvided_expectDelegatesParsedChannels() {
    Map<String, Object> expected = Map.of("mode", "stage");
    when(updateService.setPolicy(
            APP_ID,
            AppUpdatePolicyMode.STAGE,
            Set.of(AppCatalogChannel.STABLE, AppCatalogChannel.BETA)))
        .thenReturn(expected);

    Map<String, Object> result =
        handler.setPolicy(
            APP_ID, Map.of("mode", List.of("stage"), "channels", List.of("stable,beta")));

    assertSame(expected, result);
    verify(updateService)
        .setPolicy(
            APP_ID,
            AppUpdatePolicyMode.STAGE,
            Set.of(AppCatalogChannel.STABLE, AppCatalogChannel.BETA));
  }

  @Test
  void setPolicy_whenChannelIsUnsupported_expectStableInvalidOption() {
    Map<String, List<String>> queryParameters =
        Map.of("mode", List.of("stage"), "channels", List.of("stable,preview"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.setPolicy(APP_ID, queryParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_update_option", exception.errorCode());
    verifyNoInteractions(updateService);
  }

  @Test
  void setPolicy_whenModeIsUnsupported_expectStablePolicyError() {
    Map<String, List<String>> queryParameters = Map.of("mode", List.of("automatic"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.setPolicy(APP_ID, queryParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_update_policy", exception.errorCode());
    verifyNoInteractions(updateService);
  }
}
