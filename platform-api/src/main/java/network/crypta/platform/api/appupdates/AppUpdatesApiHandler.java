package network.crypta.platform.api.appupdates;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.appcatalog.AppCatalogChannel;
import network.crypta.platform.appcatalog.AppCatalogException;

/**
 * Platform API adapter for the installed-app update lifecycle routes.
 *
 * <p>The router owns path matching, authorization, and response envelopes. This handler keeps the
 * route methods small: it validates query parameters, converts public string values into domain
 * enums, and delegates to {@link AppUpdateService}. Keeping query parsing here means the service
 * can be tested without HTTP concerns while clients still receive stable Platform API error codes
 * for malformed options.
 *
 * <p>The handler never reads request bodies, filesystem paths, tokens, private catalog URIs, or
 * signing material. All returned maps come from the service and are expected to be safe for Web
 * Shell display. Boolean query options default to {@code false}; invalid option text is rejected
 * before the update service can mutate lifecycle state.
 */
public final class AppUpdatesApiHandler {
  private static final String PARAM_HEALTH_CHECK = "healthCheck";
  private static final String PARAM_CHANNELS = "channels";
  private static final String PARAM_MODE = "mode";
  private static final String PARAM_MIGRATION_ACKNOWLEDGED = "migrationAcknowledged";
  private static final String PARAM_REFRESH_CATALOGS = "refreshCatalogs";
  private static final String PARAM_RESTART = "restart";
  private static final String PARAM_REVIEW_ACKNOWLEDGED = "reviewAcknowledged";
  private static final String PARAM_ROLLBACK_ON_HEALTH_FAILURE = "rollbackOnHealthFailure";
  private static final String PARAM_SECURITY_ACKNOWLEDGED = "securityAcknowledged";
  private static final String PARAM_SOURCE_SWITCH_CONSENT = "sourceSwitchConsent";
  private static final String PARAM_TARGET_CATALOG_ID = "targetCatalogId";

  private final AppUpdateService updateService;

  /**
   * Creates an app-update handler.
   *
   * <p>The handler is intentionally stateless. The supplied service owns cached candidates, staged
   * plans, update history, and policy state for the router lifetime.
   *
   * @param updateService service that owns update lifecycle state
   */
  public AppUpdatesApiHandler(AppUpdateService updateService) {
    this.updateService = java.util.Objects.requireNonNull(updateService, "updateService");
  }

  /**
   * Returns update state for one installed app.
   *
   * <p>No query parameters are accepted by this adapter method. Missing apps and lifecycle read
   * failures are reported by the service using stable Platform API exceptions.
   *
   * @param appId app id from the request path
   * @return path-free update state for Platform API envelopes
   */
  public Map<String, Object> summary(String appId) {
    return updateService.summary(appId);
  }

  /**
   * Checks catalogs for an update candidate.
   *
   * <p>The optional {@code refreshCatalogs} query parameter controls whether the service asks the
   * catalog manager to refresh configured sources before detection. It defaults to {@code false}
   * and must be a single boolean value when present.
   *
   * @param appId app id from the request path
   * @param queryParameters decoded query parameters from the router
   * @return path-free update state after check and policy handling
   */
  public Map<String, Object> check(String appId, Map<String, List<String>> queryParameters) {
    return updateService.check(appId, optionalBoolean(queryParameters, PARAM_REFRESH_CATALOGS));
  }

  /**
   * Stages the current verified update candidate.
   *
   * <p>Staging has no request options in this first lifecycle version. The service detects a
   * candidate when needed, verifies the prepared catalog plan against reviewed metadata, and keeps
   * staging paths out of the returned summary.
   *
   * @param appId app id from the request path
   * @return path-free update state after staging
   */
  public Map<String, Object> stage(String appId) {
    return updateService.stage(appId);
  }

  /**
   * Stages the current verified update candidate with optional review acknowledgement.
   *
   * @param appId app id from the request path
   * @param queryParameters decoded query parameters from the router
   * @return path-free update state after staging
   */
  public Map<String, Object> stage(String appId, Map<String, List<String>> queryParameters) {
    return updateService.stage(
        appId,
        optionalBoolean(queryParameters, PARAM_REVIEW_ACKNOWLEDGED),
        optionalBoolean(queryParameters, PARAM_SECURITY_ACKNOWLEDGED),
        optionalBoolean(queryParameters, PARAM_MIGRATION_ACKNOWLEDGED),
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE_SWITCH_CONSENT),
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_TARGET_CATALOG_ID));
  }

  /**
   * Applies the current staged update.
   *
   * <p>The supported query parameters are {@code restart}, {@code healthCheck}, and {@code
   * rollbackOnHealthFailure}. Boolean values default to {@code false}. The health check value
   * accepts {@code none} or {@code process}; invalid values fail before AppHost replacement can
   * begin.
   *
   * @param appId app id from the request path
   * @param queryParameters decoded query parameters from the router
   * @return path-free update state after apply or post-apply cleanup
   */
  public Map<String, Object> apply(String appId, Map<String, List<String>> queryParameters) {
    return updateService.apply(appId, applyOptions(queryParameters));
  }

  /**
   * Rolls back to the previous retained AppHost bundle.
   *
   * <p>The optional {@code restart} boolean controls whether the service may stop and restart a
   * running app around rollback. Rollback still restores only the installed bundle; mutable app
   * data and cache remain outside the request scope.
   *
   * @param appId app id from the request path
   * @param queryParameters decoded query parameters from the router
   * @return path-free update state after rollback
   */
  public Map<String, Object> rollback(String appId, Map<String, List<String>> queryParameters) {
    return updateService.rollback(appId, optionalBoolean(queryParameters, PARAM_RESTART));
  }

  /**
   * Reads the current update policy for one installed app.
   *
   * <p>Policy reads are delegated directly to the service. Authorization for app principals is
   * handled by the contract and router before this method is called.
   *
   * @param appId app id from the request path
   * @return path-free policy summary for the installed app
   */
  public Map<String, Object> policy(String appId) {
    return updateService.policy(appId);
  }

  /**
   * Updates the current update policy for one installed app.
   *
   * <p>The required {@code mode} query parameter is parsed using the public policy values, not Java
   * enum names. The router exposes this mutation as host/operator-only so apps cannot silently
   * change their own update automation.
   *
   * @param appId app id from the request path
   * @param queryParameters decoded query parameters from the router
   * @return path-free policy summary after the new mode is stored
   */
  public Map<String, Object> setPolicy(String appId, Map<String, List<String>> queryParameters) {
    String mode = PlatformApiParameters.requireString(queryParameters, PARAM_MODE);
    return updateService.setPolicy(
        appId, AppUpdatePolicyMode.parse(mode), allowedChannels(queryParameters));
  }

  private static Set<AppCatalogChannel> allowedChannels(Map<String, List<String>> queryParameters) {
    String value = PlatformApiParameters.readOptionalString(queryParameters, PARAM_CHANNELS);
    if (value == null || value.isBlank()) {
      return AppUpdatePolicy.DEFAULT_ALLOWED_CHANNELS;
    }
    LinkedHashSet<AppCatalogChannel> channels = new LinkedHashSet<>();
    for (String token : value.split(",", -1)) {
      try {
        channels.add(AppCatalogChannel.parse(token, PARAM_CHANNELS));
      } catch (AppCatalogException | IllegalArgumentException _) {
        throw new PlatformApiException(
            400, "invalid_update_option", "channels contains an unsupported catalog channel.");
      }
    }
    if (channels.isEmpty()) {
      throw new PlatformApiException(
          400, "invalid_update_option", "channels must include at least one catalog channel.");
    }
    return Set.copyOf(channels);
  }

  private static AppUpdateService.ApplyOptions applyOptions(
      Map<String, List<String>> queryParameters) {
    return new AppUpdateService.ApplyOptions(
        optionalBoolean(queryParameters, PARAM_RESTART),
        healthCheckMode(queryParameters),
        optionalBoolean(queryParameters, PARAM_ROLLBACK_ON_HEALTH_FAILURE));
  }

  private static AppUpdateService.HealthCheckMode healthCheckMode(
      Map<String, List<String>> queryParameters) {
    String value = PlatformApiParameters.readOptionalString(queryParameters, PARAM_HEALTH_CHECK);
    if (value == null || value.isBlank() || "none".equalsIgnoreCase(value.trim())) {
      return AppUpdateService.HealthCheckMode.NONE;
    }
    if ("process".equals(value.trim().toLowerCase(Locale.ROOT))) {
      return AppUpdateService.HealthCheckMode.PROCESS;
    }
    throw new PlatformApiException(
        400, "invalid_update_option", "healthCheck must be 'none' or 'process'.");
  }

  private static boolean optionalBoolean(
      Map<String, List<String>> queryParameters, String parameterName) {
    String value = PlatformApiParameters.readOptionalString(queryParameters, parameterName);
    if (value == null || value.isBlank()) {
      return false;
    }
    if ("true".equalsIgnoreCase(value.trim())) {
      return true;
    }
    if ("false".equalsIgnoreCase(value.trim())) {
      return false;
    }
    throw new PlatformApiException(
        400, "invalid_update_option", parameterName + " must be 'true' or 'false'.");
  }
}
