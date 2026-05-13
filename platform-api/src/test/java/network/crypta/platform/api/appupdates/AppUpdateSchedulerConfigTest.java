package network.crypta.platform.api.appupdates;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppUpdateSchedulerConfigTest {
  @Test
  void defaults_whenLoaded_expectConservativeBackgroundDiscoveryEnabled() {
    AppUpdateSchedulerConfig config = AppUpdateSchedulerConfig.defaults();

    assertTrue(config.enabled());
    assertEquals(Duration.ofMinutes(5), config.initialDelay());
    assertEquals(Duration.ofHours(6), config.catalogRefreshInterval());
    assertEquals(Duration.ofHours(1), config.appCheckInterval());
    assertEquals(Duration.ofMinutes(5), config.jitter());
    assertEquals(Duration.ofMinutes(5), config.failureBackoff());
    assertEquals(Duration.ofHours(1), config.maxFailureBackoff());
  }

  @Test
  void from_whenPropertyAndEnvironmentBothSet_expectPropertyWins() {
    AppUpdateSchedulerConfig config =
        AppUpdateSchedulerConfig.from(
            Map.of(
                AppUpdateSchedulerConfig.ENABLED_PROPERTY,
                "false",
                AppUpdateSchedulerConfig.APP_CHECK_INTERVAL_PROPERTY,
                "45"),
            Map.of(
                AppUpdateSchedulerConfig.ENABLED_ENV,
                "true",
                AppUpdateSchedulerConfig.APP_CHECK_INTERVAL_ENV,
                "90"));

    assertFalse(config.enabled());
    assertEquals(Duration.ofSeconds(45), config.appCheckInterval());
  }

  @Test
  void from_whenValuesMalformed_expectDefaultsRetained() {
    AppUpdateSchedulerConfig defaults = AppUpdateSchedulerConfig.defaults();

    AppUpdateSchedulerConfig config =
        AppUpdateSchedulerConfig.from(
            Map.of(
                AppUpdateSchedulerConfig.ENABLED_PROPERTY,
                "maybe",
                AppUpdateSchedulerConfig.CATALOG_REFRESH_INTERVAL_PROPERTY,
                "-1",
                AppUpdateSchedulerConfig.APP_CHECK_INTERVAL_PROPERTY,
                "0",
                AppUpdateSchedulerConfig.FAILURE_BACKOFF_PROPERTY,
                "not-a-number"),
            Map.of());

    assertEquals(defaults.enabled(), config.enabled());
    assertEquals(defaults.catalogRefreshInterval(), config.catalogRefreshInterval());
    assertEquals(defaults.appCheckInterval(), config.appCheckInterval());
    assertEquals(defaults.failureBackoff(), config.failureBackoff());
  }

  @Test
  void constructor_whenMaximumBackoffBelowInitialBackoff_expectPromotedMaximum() {
    AppUpdateSchedulerConfig config =
        new AppUpdateSchedulerConfig(
            true,
            Duration.ZERO,
            Duration.ofSeconds(60),
            Duration.ofSeconds(30),
            Duration.ZERO,
            Duration.ofSeconds(120),
            Duration.ofSeconds(10));

    assertEquals(Duration.ofMinutes(2), config.maxFailureBackoff());
  }

  @Test
  void from_whenEnvironmentOnlyUsesNumericBooleanAndDurations_expectEnvironmentApplied() {
    AppUpdateSchedulerConfig config =
        AppUpdateSchedulerConfig.from(
            Map.of(),
            Map.of(
                AppUpdateSchedulerConfig.ENABLED_ENV,
                "0",
                AppUpdateSchedulerConfig.INITIAL_DELAY_ENV,
                "0",
                AppUpdateSchedulerConfig.JITTER_ENV,
                "0",
                AppUpdateSchedulerConfig.CATALOG_REFRESH_INTERVAL_ENV,
                "120",
                AppUpdateSchedulerConfig.APP_CHECK_INTERVAL_ENV,
                "30",
                AppUpdateSchedulerConfig.FAILURE_BACKOFF_ENV,
                "45",
                AppUpdateSchedulerConfig.MAX_FAILURE_BACKOFF_ENV,
                "90"));

    assertFalse(config.enabled());
    assertEquals(Duration.ZERO, config.initialDelay());
    assertEquals(Duration.ZERO, config.jitter());
    assertEquals(Duration.ofMinutes(2), config.catalogRefreshInterval());
    assertEquals(Duration.ofSeconds(30), config.appCheckInterval());
    assertEquals(Duration.ofSeconds(45), config.failureBackoff());
    assertEquals(Duration.ofSeconds(90), config.maxFailureBackoff());
  }

  @Test
  void pollInterval_whenFailureBackoffIsSmallest_expectFailureBackoffInterval() {
    AppUpdateSchedulerConfig config =
        new AppUpdateSchedulerConfig(
            true,
            Duration.ZERO,
            Duration.ofMinutes(10),
            Duration.ofMinutes(5),
            Duration.ZERO,
            Duration.ofSeconds(20),
            Duration.ofMinutes(1));

    assertEquals(Duration.ofSeconds(20), config.pollInterval());
  }

  @Test
  void constructor_whenRequiredIntervalIsZero_expectIllegalArgumentException() {
    Duration initialDelay = Duration.ZERO;
    Duration catalogRefreshInterval = Duration.ZERO;
    Duration appCheckInterval = Duration.ofSeconds(30);
    Duration jitter = Duration.ZERO;
    Duration failureBackoff = Duration.ofSeconds(30);
    Duration maxFailureBackoff = Duration.ofSeconds(30);

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new AppUpdateSchedulerConfig(
                    true,
                    initialDelay,
                    catalogRefreshInterval,
                    appCheckInterval,
                    jitter,
                    failureBackoff,
                    maxFailureBackoff));

    assertEquals("catalogRefreshInterval must be positive", exception.getMessage());
  }
}
