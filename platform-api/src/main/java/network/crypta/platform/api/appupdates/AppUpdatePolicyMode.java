package network.crypta.platform.api.appupdates;

import java.util.Locale;
import network.crypta.platform.api.PlatformApiException;

/**
 * Operator-selected app update automation mode.
 *
 * <p>The modes define the maximum action the update service may take after a check. They are
 * ordered by increasing automation, but each mode still depends on candidate eligibility,
 * compatibility metadata, review metadata, permission deltas, and current AppHost state. A policy
 * never grants route authorization by itself, and it never makes an unsigned or unverified catalog
 * bundle trusted.
 *
 * <p>The string values returned by {@link #jsonValue()} are stable Platform API values. Query
 * parsing is case-insensitive and trims surrounding whitespace so forms and scripts can submit the
 * documented values without depending on Java enum names.
 *
 * @see AppUpdatePolicy
 * @see AppUpdateService
 */
public enum AppUpdatePolicyMode {
  /**
   * Detect candidates only; do not stage or apply automatically.
   *
   * <p>This is the default for every app. Catalog checks may record an available candidate, but an
   * operator must explicitly stage and apply it.
   */
  MANUAL("manual"),

  /**
   * Stage verified candidates automatically; do not apply automatically.
   *
   * <p>The service may prepare a verified pending update after detection. It still leaves bundle
   * replacement to an explicit apply request.
   */
  STAGE("stage"),

  /**
   * Apply eligible candidates automatically only when the app is already stopped.
   *
   * <p>This mode does not stop or restart a running app. It is intended for operators who want
   * low-touch updates for stopped apps while preserving explicit control over live processes.
   */
  APPLY_WHEN_STOPPED("apply_when_stopped");

  private final String jsonValue;

  AppUpdatePolicyMode(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Parses a policy mode from Platform API query input.
   *
   * <p>Only the public JSON values are accepted. Blank, missing, or unknown values are reported
   * with the stable {@code invalid_update_policy} error code so callers can distinguish policy
   * mistakes from lifecycle failures.
   *
   * @param value raw mode text from the Platform API query parameter
   * @return parsed policy mode matching the supplied public value
   */
  public static AppUpdatePolicyMode parse(String value) {
    if (value == null || value.isBlank()) {
      throw new PlatformApiException(
          400, "invalid_update_policy", "Update policy mode must not be blank.");
    }
    String normalized = value.trim().toLowerCase(Locale.ROOT);
    for (AppUpdatePolicyMode mode : values()) {
      if (mode.jsonValue.equals(normalized)) {
        return mode;
      }
    }
    throw new PlatformApiException(
        400, "invalid_update_policy", "Update policy mode is not supported.");
  }

  /**
   * Returns the stable JSON value for this mode.
   *
   * <p>The returned value is the form accepted by policy update requests and emitted by policy
   * summaries. It is lower-case and uses underscores where the Java enum name would use multiple
   * words.
   *
   * @return lower-case policy value used in Platform API JSON
   */
  public String jsonValue() {
    return jsonValue;
  }
}
