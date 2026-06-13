package network.crypta.platform.api.networkbudget;

import java.util.Map;
import java.util.Objects;

/**
 * Local operator configuration for app-network rate and concurrency budgets.
 *
 * <p>The defaults are conservative and finite. Invalid system properties or environment variables
 * keep those defaults instead of creating an unbounded budget. Property values take precedence over
 * environment variables, matching the subscription scheduler configuration style.
 *
 * <p>The record is immutable and safe to share between router, subscription, and Trust Graph
 * services. It does not contain app ids, content keys, request bodies, filesystem locations, or
 * other per-request material. Callers load it once during runtime composition, then pass the same
 * instance into {@code AppNetworkBudgetService}. All numeric values are positive integer limits:
 * rate values are fixed-window counts, and concurrency values are in-process lease counts.
 *
 * @param foregroundContentFetchPerAppPerMinute per-app foreground fetches allowed in each
 *     fixed-minute window
 * @param foregroundContentFetchGlobalPerMinute node-wide content-fetch family operations allowed in
 *     each fixed-minute window
 * @param foregroundContentFetchConcurrentPerApp concurrent foreground fetch leases allowed for one
 *     app id
 * @param foregroundContentFetchConcurrentGlobal concurrent content-fetch family leases allowed
 *     across the local node
 * @param subscriptionPollPerAppPerHour per-app scheduled polls or manual refreshes allowed in each
 *     fixed-hour window
 * @param subscriptionPollGlobalPerHour node-wide subscription polls or manual refreshes allowed in
 *     each fixed-hour window
 * @param subscriptionPollConcurrentPerApp concurrent subscription fetch leases allowed for one app
 *     id
 * @param subscriptionPollConcurrentGlobal concurrent subscription fetch leases allowed across the
 *     local node
 * @param trustGraphImportPerAppPerHour per-app Trust Graph imports allowed in each fixed-hour
 *     window
 * @param trustGraphImportGlobalPerHour node-wide Trust Graph imports allowed in each fixed-hour
 *     window
 * @param trustGraphImportConcurrentPerApp concurrent Trust Graph import leases allowed for one app
 *     id
 * @param trustGraphImportConcurrentGlobal concurrent Trust Graph import leases allowed across the
 *     local node
 */
public record AppNetworkBudgetConfig(
    int foregroundContentFetchPerAppPerMinute,
    int foregroundContentFetchGlobalPerMinute,
    int foregroundContentFetchConcurrentPerApp,
    int foregroundContentFetchConcurrentGlobal,
    int subscriptionPollPerAppPerHour,
    int subscriptionPollGlobalPerHour,
    int subscriptionPollConcurrentPerApp,
    int subscriptionPollConcurrentGlobal,
    int trustGraphImportPerAppPerHour,
    int trustGraphImportGlobalPerHour,
    int trustGraphImportConcurrentPerApp,
    int trustGraphImportConcurrentGlobal) {
  /** System property for the per-app foreground content-fetch rate limit, measured per minute. */
  public static final String FOREGROUND_CONTENT_FETCH_PER_APP_PER_MINUTE_PROPERTY =
      "cryptad.appNetworkBudget.foregroundContentFetchPerAppPerMinute";

  /** Environment variable for the per-app foreground content-fetch rate limit per minute. */
  public static final String FOREGROUND_CONTENT_FETCH_PER_APP_PER_MINUTE_ENV =
      "CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_PER_APP_PER_MINUTE";

  /** System property for the node-wide content-fetch family rate limit, measured per minute. */
  public static final String FOREGROUND_CONTENT_FETCH_GLOBAL_PER_MINUTE_PROPERTY =
      "cryptad.appNetworkBudget.foregroundContentFetchGlobalPerMinute";

  /** Environment variable for the node-wide content-fetch family rate limit per minute. */
  public static final String FOREGROUND_CONTENT_FETCH_GLOBAL_PER_MINUTE_ENV =
      "CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_GLOBAL_PER_MINUTE";

  /** System property for the per-app foreground content-fetch concurrency lease limit. */
  public static final String FOREGROUND_CONTENT_FETCH_CONCURRENT_PER_APP_PROPERTY =
      "cryptad.appNetworkBudget.foregroundContentFetchConcurrentPerApp";

  /** Environment variable for the per-app foreground content-fetch concurrency lease limit. */
  public static final String FOREGROUND_CONTENT_FETCH_CONCURRENT_PER_APP_ENV =
      "CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_CONCURRENT_PER_APP";

  /** System property for the node-wide content-fetch family concurrency lease limit. */
  public static final String FOREGROUND_CONTENT_FETCH_CONCURRENT_GLOBAL_PROPERTY =
      "cryptad.appNetworkBudget.foregroundContentFetchConcurrentGlobal";

  /** Environment variable for the node-wide content-fetch family concurrency lease limit. */
  public static final String FOREGROUND_CONTENT_FETCH_CONCURRENT_GLOBAL_ENV =
      "CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_CONCURRENT_GLOBAL";

  /** System property for the per-app subscription poll and manual-refresh rate limit per hour. */
  public static final String SUBSCRIPTION_POLL_PER_APP_PER_HOUR_PROPERTY =
      "cryptad.appNetworkBudget.subscriptionPollPerAppPerHour";

  /** Environment variable for the per-app subscription poll and manual-refresh rate limit. */
  public static final String SUBSCRIPTION_POLL_PER_APP_PER_HOUR_ENV =
      "CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_PER_APP_PER_HOUR";

  /** System property for the node-wide subscription poll and manual-refresh rate limit per hour. */
  public static final String SUBSCRIPTION_POLL_GLOBAL_PER_HOUR_PROPERTY =
      "cryptad.appNetworkBudget.subscriptionPollGlobalPerHour";

  /** Environment variable for the node-wide subscription poll and manual-refresh rate limit. */
  public static final String SUBSCRIPTION_POLL_GLOBAL_PER_HOUR_ENV =
      "CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_GLOBAL_PER_HOUR";

  /** System property for the per-app subscription poll concurrency lease limit. */
  public static final String SUBSCRIPTION_POLL_CONCURRENT_PER_APP_PROPERTY =
      "cryptad.appNetworkBudget.subscriptionPollConcurrentPerApp";

  /** Environment variable for the per-app subscription poll concurrency lease limit. */
  public static final String SUBSCRIPTION_POLL_CONCURRENT_PER_APP_ENV =
      "CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_CONCURRENT_PER_APP";

  /** System property for the node-wide subscription poll concurrency lease limit. */
  public static final String SUBSCRIPTION_POLL_CONCURRENT_GLOBAL_PROPERTY =
      "cryptad.appNetworkBudget.subscriptionPollConcurrentGlobal";

  /** Environment variable for the node-wide subscription poll concurrency lease limit. */
  public static final String SUBSCRIPTION_POLL_CONCURRENT_GLOBAL_ENV =
      "CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_CONCURRENT_GLOBAL";

  /** System property for the per-app Trust Graph import rate limit, measured per hour. */
  public static final String TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR_PROPERTY =
      "cryptad.appNetworkBudget.trustGraphImportPerAppPerHour";

  /** Environment variable for the per-app Trust Graph import rate limit per hour. */
  public static final String TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR_ENV =
      "CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR";

  /** System property for the node-wide Trust Graph import rate limit, measured per hour. */
  public static final String TRUST_GRAPH_IMPORT_GLOBAL_PER_HOUR_PROPERTY =
      "cryptad.appNetworkBudget.trustGraphImportGlobalPerHour";

  /** Environment variable for the node-wide Trust Graph import rate limit per hour. */
  public static final String TRUST_GRAPH_IMPORT_GLOBAL_PER_HOUR_ENV =
      "CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_GLOBAL_PER_HOUR";

  /** System property for the per-app Trust Graph import concurrency lease limit. */
  public static final String TRUST_GRAPH_IMPORT_CONCURRENT_PER_APP_PROPERTY =
      "cryptad.appNetworkBudget.trustGraphImportConcurrentPerApp";

  /** Environment variable for the per-app Trust Graph import concurrency lease limit. */
  public static final String TRUST_GRAPH_IMPORT_CONCURRENT_PER_APP_ENV =
      "CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_CONCURRENT_PER_APP";

  /** System property for the node-wide Trust Graph import concurrency lease limit. */
  public static final String TRUST_GRAPH_IMPORT_CONCURRENT_GLOBAL_PROPERTY =
      "cryptad.appNetworkBudget.trustGraphImportConcurrentGlobal";

  /** Environment variable for the node-wide Trust Graph import concurrency lease limit. */
  public static final String TRUST_GRAPH_IMPORT_CONCURRENT_GLOBAL_ENV =
      "CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_CONCURRENT_GLOBAL";

  private static final AppNetworkBudgetConfig DEFAULT =
      new AppNetworkBudgetConfig(20, 200, 2, 16, 48, 1024, 1, 8, 120, 1024, 1, 8);

  /**
   * Creates a validated finite budget configuration.
   *
   * <p>All limits must be positive. A value of zero would disable a budget family and is rejected
   * instead of being interpreted as unlimited. Operators who provide malformed process settings get
   * the conservative defaults through {@link #loadFromSystem()} rather than this canonical
   * constructor.
   */
  public AppNetworkBudgetConfig {
    requirePositive(foregroundContentFetchPerAppPerMinute, "foregroundContentFetchPerAppPerMinute");
    requirePositive(foregroundContentFetchGlobalPerMinute, "foregroundContentFetchGlobalPerMinute");
    requirePositive(
        foregroundContentFetchConcurrentPerApp, "foregroundContentFetchConcurrentPerApp");
    requirePositive(
        foregroundContentFetchConcurrentGlobal, "foregroundContentFetchConcurrentGlobal");
    requirePositive(subscriptionPollPerAppPerHour, "subscriptionPollPerAppPerHour");
    requirePositive(subscriptionPollGlobalPerHour, "subscriptionPollGlobalPerHour");
    requirePositive(subscriptionPollConcurrentPerApp, "subscriptionPollConcurrentPerApp");
    requirePositive(subscriptionPollConcurrentGlobal, "subscriptionPollConcurrentGlobal");
    requirePositive(trustGraphImportPerAppPerHour, "trustGraphImportPerAppPerHour");
    requirePositive(trustGraphImportGlobalPerHour, "trustGraphImportGlobalPerHour");
    requirePositive(trustGraphImportConcurrentPerApp, "trustGraphImportConcurrentPerApp");
    requirePositive(trustGraphImportConcurrentGlobal, "trustGraphImportConcurrentGlobal");
  }

  /**
   * Returns the conservative finite defaults.
   *
   * <p>The default values are intentionally small enough to make long-lived app workflows bounded
   * during beta use, while still allowing first-party reference apps to refresh content and import
   * local Trust Graph statements. The returned record is immutable and may be reused directly.
   *
   * @return immutable default app-network budget configuration with finite rate and concurrency
   *     limits
   */
  public static AppNetworkBudgetConfig defaults() {
    return DEFAULT;
  }

  /**
   * Loads process-local budget settings from system properties and environment variables.
   *
   * <p>System properties take precedence over environment variables so launch scripts can override
   * inherited service-manager environments. Missing, blank, non-numeric, or non-positive values are
   * ignored independently; one bad setting does not discard the rest of the configuration.
   *
   * @return finite app-network budget configuration for the current process
   */
  public static AppNetworkBudgetConfig loadFromSystem() {
    return from(System.getProperties(), System.getenv());
  }

  static AppNetworkBudgetConfig from(Map<?, ?> properties, Map<String, String> environment) {
    Objects.requireNonNull(properties, "properties");
    Objects.requireNonNull(environment, "environment");
    AppNetworkBudgetConfig defaults = defaults();
    return new AppNetworkBudgetConfig(
        integerSetting(
            properties,
            environment,
            FOREGROUND_CONTENT_FETCH_PER_APP_PER_MINUTE_PROPERTY,
            FOREGROUND_CONTENT_FETCH_PER_APP_PER_MINUTE_ENV,
            defaults.foregroundContentFetchPerAppPerMinute()),
        integerSetting(
            properties,
            environment,
            FOREGROUND_CONTENT_FETCH_GLOBAL_PER_MINUTE_PROPERTY,
            FOREGROUND_CONTENT_FETCH_GLOBAL_PER_MINUTE_ENV,
            defaults.foregroundContentFetchGlobalPerMinute()),
        integerSetting(
            properties,
            environment,
            FOREGROUND_CONTENT_FETCH_CONCURRENT_PER_APP_PROPERTY,
            FOREGROUND_CONTENT_FETCH_CONCURRENT_PER_APP_ENV,
            defaults.foregroundContentFetchConcurrentPerApp()),
        integerSetting(
            properties,
            environment,
            FOREGROUND_CONTENT_FETCH_CONCURRENT_GLOBAL_PROPERTY,
            FOREGROUND_CONTENT_FETCH_CONCURRENT_GLOBAL_ENV,
            defaults.foregroundContentFetchConcurrentGlobal()),
        integerSetting(
            properties,
            environment,
            SUBSCRIPTION_POLL_PER_APP_PER_HOUR_PROPERTY,
            SUBSCRIPTION_POLL_PER_APP_PER_HOUR_ENV,
            defaults.subscriptionPollPerAppPerHour()),
        integerSetting(
            properties,
            environment,
            SUBSCRIPTION_POLL_GLOBAL_PER_HOUR_PROPERTY,
            SUBSCRIPTION_POLL_GLOBAL_PER_HOUR_ENV,
            defaults.subscriptionPollGlobalPerHour()),
        integerSetting(
            properties,
            environment,
            SUBSCRIPTION_POLL_CONCURRENT_PER_APP_PROPERTY,
            SUBSCRIPTION_POLL_CONCURRENT_PER_APP_ENV,
            defaults.subscriptionPollConcurrentPerApp()),
        integerSetting(
            properties,
            environment,
            SUBSCRIPTION_POLL_CONCURRENT_GLOBAL_PROPERTY,
            SUBSCRIPTION_POLL_CONCURRENT_GLOBAL_ENV,
            defaults.subscriptionPollConcurrentGlobal()),
        integerSetting(
            properties,
            environment,
            TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR_PROPERTY,
            TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR_ENV,
            defaults.trustGraphImportPerAppPerHour()),
        integerSetting(
            properties,
            environment,
            TRUST_GRAPH_IMPORT_GLOBAL_PER_HOUR_PROPERTY,
            TRUST_GRAPH_IMPORT_GLOBAL_PER_HOUR_ENV,
            defaults.trustGraphImportGlobalPerHour()),
        integerSetting(
            properties,
            environment,
            TRUST_GRAPH_IMPORT_CONCURRENT_PER_APP_PROPERTY,
            TRUST_GRAPH_IMPORT_CONCURRENT_PER_APP_ENV,
            defaults.trustGraphImportConcurrentPerApp()),
        integerSetting(
            properties,
            environment,
            TRUST_GRAPH_IMPORT_CONCURRENT_GLOBAL_PROPERTY,
            TRUST_GRAPH_IMPORT_CONCURRENT_GLOBAL_ENV,
            defaults.trustGraphImportConcurrentGlobal()));
  }

  private static int integerSetting(
      Map<?, ?> properties,
      Map<String, String> environment,
      String propertyName,
      String environmentName,
      int defaultValue) {
    String configured = configuredValue(properties, environment, propertyName, environmentName);
    if (configured == null) {
      return defaultValue;
    }
    try {
      int parsed = Integer.parseInt(configured);
      return parsed > 0 ? parsed : defaultValue;
    } catch (NumberFormatException _) {
      return defaultValue;
    }
  }

  private static String configuredValue(
      Map<?, ?> properties, Map<String, String> environment, String propertyName, String envName) {
    Object propertyValue = properties.get(propertyName);
    if (propertyValue != null && !propertyValue.toString().isBlank()) {
      return propertyValue.toString().trim();
    }
    String environmentValue = environment.get(envName);
    return environmentValue == null || environmentValue.isBlank() ? null : environmentValue.trim();
  }

  private static void requirePositive(int value, String name) {
    if (value <= 0) {
      throw new IllegalArgumentException(name + " must be positive");
    }
  }
}
