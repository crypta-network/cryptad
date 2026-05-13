package network.crypta.platform.api.appupdates;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * Local configuration for the app-update background scheduler.
 *
 * <p>The defaults keep background discovery enabled while preserving Cryptad's conservative update
 * policy. Scheduler passes may refresh signed catalogs and call {@link AppUpdateService#check} for
 * installed apps, but policy-driven staging or apply still depends on each app's explicit {@link
 * AppUpdatePolicyMode}. The default policy remains manual, so third-party apps are not silently
 * updated merely because the scheduler is enabled.
 *
 * <p>Configuration is read from process properties first and environment variables second. Invalid
 * duration or boolean values fall back to the default for that field. This keeps a malformed local
 * setting from disabling app-management routes or changing update policy behavior during startup.
 *
 * <p>All duration overrides are expressed in whole seconds. {@link #initialDelay} and {@link
 * #jitter} may be zero for deterministic local runs, while catalog refresh, app checks, and backoff
 * values must stay positive so the background executor cannot spin.
 *
 * @param enabled whether background scheduler work should run after runtime startup
 * @param initialDelay delay before the first background pass after scheduler start
 * @param catalogRefreshInterval interval between configured signed catalog refresh attempts
 * @param appCheckInterval interval between update checks for each installed app
 * @param jitter maximum random delay added to scheduled and backoff due times
 * @param failureBackoff first retry delay after catalog, app-check, or store failure
 * @param maxFailureBackoff maximum retry delay after repeated scheduler failures
 */
public record AppUpdateSchedulerConfig(
    boolean enabled,
    Duration initialDelay,
    Duration catalogRefreshInterval,
    Duration appCheckInterval,
    Duration jitter,
    Duration failureBackoff,
    Duration maxFailureBackoff) {
  /**
   * System property used to enable or disable the scheduler.
   *
   * <p>Accepted values are {@code true}, {@code false}, {@code 1}, and {@code 0}. This property has
   * priority over {@link #ENABLED_ENV} when both are present.
   */
  public static final String ENABLED_PROPERTY = "cryptad.appupdates.scheduler.enabled";

  /**
   * Environment variable used to enable or disable the scheduler.
   *
   * <p>Accepted values match {@link #ENABLED_PROPERTY}. It is intended for service managers and
   * container-style launches where editing a JVM property list is less convenient.
   */
  public static final String ENABLED_ENV = "CRYPTAD_APPUPDATES_SCHEDULER_ENABLED";

  /**
   * System property for the initial scheduler delay in seconds.
   *
   * <p>The default gives the daemon time to finish startup before catalog refresh or app checks
   * begin. A value of {@code 0} is valid for tests and local smoke runs.
   */
  public static final String INITIAL_DELAY_PROPERTY =
      "cryptad.appupdates.scheduler.initialDelaySeconds";

  /**
   * Environment variable for the initial scheduler delay in seconds.
   *
   * <p>This has the same units and validation as {@link #INITIAL_DELAY_PROPERTY}. The system
   * property wins if both settings are present.
   */
  public static final String INITIAL_DELAY_ENV =
      "CRYPTAD_APPUPDATES_SCHEDULER_INITIAL_DELAY_SECONDS";

  /**
   * System property for the catalog refresh interval in seconds.
   *
   * <p>The interval controls the global signed-catalog refresh target, not one refresh per app. The
   * value must be positive; invalid values fall back to the conservative default.
   */
  public static final String CATALOG_REFRESH_INTERVAL_PROPERTY =
      "cryptad.appupdates.scheduler.catalogRefreshIntervalSeconds";

  /**
   * Environment variable for the catalog refresh interval in seconds.
   *
   * <p>This is the service-manager equivalent of {@link #CATALOG_REFRESH_INTERVAL_PROPERTY}. Use it
   * only for local operator policy; Cryptad does not ship public remote catalog defaults here.
   */
  public static final String CATALOG_REFRESH_INTERVAL_ENV =
      "CRYPTAD_APPUPDATES_SCHEDULER_CATALOG_REFRESH_INTERVAL_SECONDS";

  /**
   * System property for the installed-app check interval in seconds.
   *
   * <p>The interval applies independently to each installed app's durable scheduler state. Checks
   * still call {@link AppUpdateService#check(String, boolean)} and inherit the app's policy mode.
   */
  public static final String APP_CHECK_INTERVAL_PROPERTY =
      "cryptad.appupdates.scheduler.appCheckIntervalSeconds";

  /**
   * Environment variable for the installed-app check interval in seconds.
   *
   * <p>This setting mirrors {@link #APP_CHECK_INTERVAL_PROPERTY}. Values are whole positive seconds
   * and malformed values fall back to the default one-hour app-check interval.
   */
  public static final String APP_CHECK_INTERVAL_ENV =
      "CRYPTAD_APPUPDATES_SCHEDULER_APP_CHECK_INTERVAL_SECONDS";

  /**
   * System property for the scheduler jitter bound in seconds.
   *
   * <p>Jitter is added to successful due times and failure backoff. It may be {@code 0} for
   * deterministic local runs, but production deployments should keep a nonzero value.
   */
  public static final String JITTER_PROPERTY = "cryptad.appupdates.scheduler.jitterSeconds";

  /**
   * Environment variable for the scheduler jitter bound in seconds.
   *
   * <p>This has the same validation as {@link #JITTER_PROPERTY}. It lets package or service
   * configuration adjust scheduler spread without changing daemon code.
   */
  public static final String JITTER_ENV = "CRYPTAD_APPUPDATES_SCHEDULER_JITTER_SECONDS";

  /**
   * System property for the first failure backoff in seconds.
   *
   * <p>The value is the base retry delay after catalog listing, catalog refresh, installed-app
   * listing, update-check, or scheduler-store failure. It must be positive.
   */
  public static final String FAILURE_BACKOFF_PROPERTY =
      "cryptad.appupdates.scheduler.failureBackoffSeconds";

  /**
   * Environment variable for the first failure backoff in seconds.
   *
   * <p>This mirrors {@link #FAILURE_BACKOFF_PROPERTY}. Repeated failures double from this base
   * delay until they reach {@link #MAX_FAILURE_BACKOFF_ENV} or its property counterpart.
   */
  public static final String FAILURE_BACKOFF_ENV =
      "CRYPTAD_APPUPDATES_SCHEDULER_FAILURE_BACKOFF_SECONDS";

  /**
   * System property for the maximum failure backoff in seconds.
   *
   * <p>The constructor promotes this value to at least {@link #FAILURE_BACKOFF_PROPERTY}'s resolved
   * delay. That avoids a maximum that is lower than the first retry interval.
   */
  public static final String MAX_FAILURE_BACKOFF_PROPERTY =
      "cryptad.appupdates.scheduler.maxFailureBackoffSeconds";

  /**
   * Environment variable for the maximum failure backoff in seconds.
   *
   * <p>This mirrors {@link #MAX_FAILURE_BACKOFF_PROPERTY}. It bounds repeated scheduler retries
   * while still keeping failure state visible through app-update summaries.
   */
  public static final String MAX_FAILURE_BACKOFF_ENV =
      "CRYPTAD_APPUPDATES_SCHEDULER_MAX_FAILURE_BACKOFF_SECONDS";

  private static final AppUpdateSchedulerConfig DEFAULT =
      new AppUpdateSchedulerConfig(
          true,
          Duration.ofMinutes(5),
          Duration.ofHours(6),
          Duration.ofHours(1),
          Duration.ofMinutes(5),
          Duration.ofMinutes(5),
          Duration.ofHours(1));

  /**
   * Creates a validated scheduler configuration.
   *
   * <p>Durations must be non-negative. Operational intervals and backoff values must also be
   * positive so a scheduler cannot enter a tight loop. If the maximum backoff is lower than the
   * first backoff, the constructor promotes it to the first backoff. The record is immutable after
   * construction and safe to share between the runtime scheduler, router wiring, and tests.
   *
   * @param enabled whether scheduler work should run after runtime startup
   * @param initialDelay delay before the first background pass after scheduler start
   * @param catalogRefreshInterval interval between configured signed catalog refresh attempts
   * @param appCheckInterval interval between update checks for each installed app
   * @param jitter maximum random delay added to scheduled and backoff due times
   * @param failureBackoff first retry delay after catalog, app-check, or store failure
   * @param maxFailureBackoff maximum retry delay after repeated scheduler failures
   * @throws NullPointerException if any duration component is {@code null}
   * @throws IllegalArgumentException if a duration component violates its allowed range
   */
  public AppUpdateSchedulerConfig {
    requireNonNegative(initialDelay, "initialDelay");
    requirePositive(catalogRefreshInterval, "catalogRefreshInterval");
    requirePositive(appCheckInterval, "appCheckInterval");
    requireNonNegative(jitter, "jitter");
    requirePositive(failureBackoff, "failureBackoff");
    requirePositive(maxFailureBackoff, "maxFailureBackoff");
    if (maxFailureBackoff.compareTo(failureBackoff) < 0) {
      maxFailureBackoff = failureBackoff;
    }
  }

  /**
   * Returns the conservative default scheduler configuration.
   *
   * <p>The default enables background discovery with a five-minute initial delay, six-hour catalog
   * refreshes, hourly app checks, five-minute jitter, and bounded failure backoff. Those defaults
   * discover candidates but do not change the per-app update policy.
   *
   * @return default scheduler configuration used when no local overrides are present
   */
  public static AppUpdateSchedulerConfig defaults() {
    return DEFAULT;
  }

  /**
   * Loads scheduler configuration from system properties and environment variables.
   *
   * <p>System properties take precedence over environment variables so explicit process-launch
   * configuration wins over ambient shell settings. Blank values are ignored, and malformed values
   * fall back to the documented defaults. The method does not persist or normalize settings; it
   * only snapshots the current process environment into an immutable record.
   *
   * @return configured scheduler settings for the current process
   */
  public static AppUpdateSchedulerConfig loadFromSystem() {
    return from(System.getProperties(), System.getenv());
  }

  static AppUpdateSchedulerConfig from(Map<?, ?> properties, Map<String, String> environment) {
    Objects.requireNonNull(properties, "properties");
    Objects.requireNonNull(environment, "environment");
    AppUpdateSchedulerConfig defaults = defaults();
    Duration failureBackoff =
        positiveDurationSetting(
            properties,
            environment,
            FAILURE_BACKOFF_PROPERTY,
            FAILURE_BACKOFF_ENV,
            defaults.failureBackoff());
    return new AppUpdateSchedulerConfig(
        enabledSetting(properties, environment, defaults.enabled()),
        nonNegativeDurationSetting(
            properties,
            environment,
            INITIAL_DELAY_PROPERTY,
            INITIAL_DELAY_ENV,
            defaults.initialDelay()),
        positiveDurationSetting(
            properties,
            environment,
            CATALOG_REFRESH_INTERVAL_PROPERTY,
            CATALOG_REFRESH_INTERVAL_ENV,
            defaults.catalogRefreshInterval()),
        positiveDurationSetting(
            properties,
            environment,
            APP_CHECK_INTERVAL_PROPERTY,
            APP_CHECK_INTERVAL_ENV,
            defaults.appCheckInterval()),
        nonNegativeDurationSetting(
            properties, environment, JITTER_PROPERTY, JITTER_ENV, defaults.jitter()),
        failureBackoff,
        positiveDurationSetting(
            properties,
            environment,
            MAX_FAILURE_BACKOFF_PROPERTY,
            MAX_FAILURE_BACKOFF_ENV,
            defaults.maxFailureBackoff()));
  }

  /**
   * Returns the fixed-delay poll interval for the runtime executor.
   *
   * <p>The scheduler still checks per-app and catalog due timestamps before doing work. This value
   * is only the cadence at which the background thread wakes up to inspect state. It is the minimum
   * of catalog refresh interval, app-check interval, and first failure backoff, with a one-second
   * floor to protect the executor from zero-delay polling.
   *
   * @return executor wake-up interval used between due-state inspection passes
   */
  public Duration pollInterval() {
    Duration minimum =
        catalogRefreshInterval.compareTo(appCheckInterval) <= 0
            ? catalogRefreshInterval
            : appCheckInterval;
    minimum = minimum.compareTo(failureBackoff) <= 0 ? minimum : failureBackoff;
    return minimum.compareTo(Duration.ofSeconds(1)) < 0 ? Duration.ofSeconds(1) : minimum;
  }

  private static boolean enabledSetting(
      Map<?, ?> properties, Map<String, String> environment, boolean defaultValue) {
    String raw = configuredValue(properties, environment, ENABLED_PROPERTY, ENABLED_ENV);
    if (raw == null) {
      return defaultValue;
    }
    if ("true".equalsIgnoreCase(raw) || "1".equals(raw)) {
      return true;
    }
    if ("false".equalsIgnoreCase(raw) || "0".equals(raw)) {
      return false;
    }
    return defaultValue;
  }

  private static Duration nonNegativeDurationSetting(
      Map<?, ?> properties,
      Map<String, String> environment,
      String propertyName,
      String environmentName,
      Duration defaultValue) {
    return durationSetting(
        properties, environment, propertyName, environmentName, defaultValue, true);
  }

  private static Duration positiveDurationSetting(
      Map<?, ?> properties,
      Map<String, String> environment,
      String propertyName,
      String environmentName,
      Duration defaultValue) {
    return durationSetting(
        properties, environment, propertyName, environmentName, defaultValue, false);
  }

  private static Duration durationSetting(
      Map<?, ?> properties,
      Map<String, String> environment,
      String propertyName,
      String environmentName,
      Duration defaultValue,
      boolean allowZero) {
    String raw = configuredValue(properties, environment, propertyName, environmentName);
    if (raw == null) {
      return defaultValue;
    }
    try {
      long seconds = Long.parseLong(raw);
      if (seconds < 0 || (!allowZero && seconds == 0)) {
        return defaultValue;
      }
      return Duration.ofSeconds(seconds);
    } catch (NumberFormatException | ArithmeticException _) {
      return defaultValue;
    }
  }

  private static String configuredValue(
      Map<?, ?> properties,
      Map<String, String> environment,
      String propertyName,
      String environmentName) {
    Object propertyValue = properties.get(propertyName);
    if (propertyValue != null && !propertyValue.toString().isBlank()) {
      return propertyValue.toString().trim();
    }
    String environmentValue = environment.get(environmentName);
    return environmentValue == null || environmentValue.isBlank() ? null : environmentValue.trim();
  }

  private static void requireNonNegative(Duration value, String label) {
    Duration duration = Objects.requireNonNull(value, label);
    if (duration.isNegative()) {
      throw new IllegalArgumentException(label + " must be non-negative");
    }
  }

  private static void requirePositive(Duration value, String label) {
    Duration duration = Objects.requireNonNull(value, label);
    if (duration.isNegative()) {
      throw new IllegalArgumentException(label + " must be non-negative");
    }
    if (duration.isZero()) {
      throw new IllegalArgumentException(label + " must be positive");
    }
  }
}
