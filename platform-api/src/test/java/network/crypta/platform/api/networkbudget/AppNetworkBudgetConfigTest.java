package network.crypta.platform.api.networkbudget;

import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class AppNetworkBudgetConfigTest {
  @Test
  void from_whenNoSettings_expectConservativeDefaults() {
    AppNetworkBudgetConfig config = AppNetworkBudgetConfig.from(new Properties(), Map.of());

    assertEquals(20, config.foregroundContentFetchPerAppPerMinute());
    assertEquals(200, config.foregroundContentFetchGlobalPerMinute());
    assertEquals(2, config.foregroundContentFetchConcurrentPerApp());
    assertEquals(16, config.foregroundContentFetchConcurrentGlobal());
    assertEquals(48, config.subscriptionPollPerAppPerHour());
    assertEquals(1024, config.subscriptionPollGlobalPerHour());
    assertEquals(1, config.subscriptionPollConcurrentPerApp());
    assertEquals(8, config.subscriptionPollConcurrentGlobal());
    assertEquals(120, config.trustGraphImportPerAppPerHour());
    assertEquals(1024, config.trustGraphImportGlobalPerHour());
    assertEquals(1, config.trustGraphImportConcurrentPerApp());
    assertEquals(8, config.trustGraphImportConcurrentGlobal());
  }

  @Test
  void from_whenMalformedSettingsProvided_expectDefaultsRemainFinite() {
    Properties properties = new Properties();
    properties.setProperty(
        AppNetworkBudgetConfig.FOREGROUND_CONTENT_FETCH_PER_APP_PER_MINUTE_PROPERTY, "0");
    properties.setProperty(
        AppNetworkBudgetConfig.SUBSCRIPTION_POLL_PER_APP_PER_HOUR_PROPERTY, "-10");
    properties.setProperty(
        AppNetworkBudgetConfig.TRUST_GRAPH_IMPORT_GLOBAL_PER_HOUR_PROPERTY, "not-a-number");

    AppNetworkBudgetConfig config = AppNetworkBudgetConfig.from(properties, Map.of());

    assertEquals(20, config.foregroundContentFetchPerAppPerMinute());
    assertEquals(48, config.subscriptionPollPerAppPerHour());
    assertEquals(1024, config.trustGraphImportGlobalPerHour());
  }

  @Test
  void from_whenPropertyAndEnvironmentProvided_expectPropertyWins() {
    Properties properties = new Properties();
    properties.setProperty(
        AppNetworkBudgetConfig.FOREGROUND_CONTENT_FETCH_GLOBAL_PER_MINUTE_PROPERTY, "7");
    Map<String, String> environment =
        Map.of(AppNetworkBudgetConfig.FOREGROUND_CONTENT_FETCH_GLOBAL_PER_MINUTE_ENV, "99");

    AppNetworkBudgetConfig config = AppNetworkBudgetConfig.from(properties, environment);

    assertEquals(7, config.foregroundContentFetchGlobalPerMinute());
  }

  @Test
  void from_whenEnvironmentProvided_expectEnvironmentUsed() {
    Map<String, String> environment =
        Map.of(AppNetworkBudgetConfig.TRUST_GRAPH_IMPORT_CONCURRENT_GLOBAL_ENV, "3");

    AppNetworkBudgetConfig config = AppNetworkBudgetConfig.from(new Properties(), environment);

    assertEquals(3, config.trustGraphImportConcurrentGlobal());
  }
}
