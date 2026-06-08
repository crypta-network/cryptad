package network.crypta.platform.api.appdata;

import java.util.Locale;
import network.crypta.platform.api.PlatformApiException;

/**
 * Operator restore modes for portable app-data backup bundles.
 *
 * <p>The restore mode is the operator's explicit choice about how backup records interact with
 * existing durable app-data on the target node. The modes intentionally mirror the existing
 * app-facing import semantics where possible: {@link #MERGE} and {@link #REPLACE_NAMESPACE} reuse
 * normal import preflight and commit behavior, while {@link #REPLACE_APP} adds an operator-only
 * full-app replacement path. All modes remain scoped to the app ids carried by the backup bundle;
 * none grants app principals cross-app read or write access.
 *
 * <p>Callers should always generate an {@link AppDataRestorePlan} before committing a destructive
 * mode. The plan reports conflicts, namespace replacement, app replacement, quota blockers, and
 * uninstalled-app warnings without exposing raw record values. Web Shell confirmations rely on the
 * stable {@link #apiValue()} strings rather than enum names.
 */
public enum AppDataRestoreMode {
  /**
   * Add or replace records from the backup without deleting unrelated app-data records.
   *
   * <p>Merge is the default restore mode. Existing records with matching namespace and key are
   * overwritten by backup values, while unrelated records and namespaces remain in place.
   */
  MERGE("merge"),

  /**
   * Replace each namespace present in the backup while preserving unrelated namespaces.
   *
   * <p>The service clears only namespaces included in the backup entry before importing that
   * entry's records. Namespaces absent from the backup remain available for the same app id.
   */
  REPLACE_NAMESPACE("replaceNamespace"),

  /**
   * Replace all durable app-data state for the target app before importing the backup entry.
   *
   * <p>This is the broadest destructive mode. It clears every durable namespace for the target app
   * id before writing the backup entry and is available only through operator restore routes.
   */
  REPLACE_APP("replaceApp");

  private final String apiValue;

  AppDataRestoreMode(String apiValue) {
    this.apiValue = apiValue;
  }

  /**
   * Returns the Platform API form value for this mode.
   *
   * <p>The API value is stable route vocabulary. It is camel-case where the Platform API already
   * uses camel-case form values and should be used in JSON responses, Web Shell controls, and
   * release evidence instead of {@link #name()}.
   *
   * @return stable camel-case mode value used by operator restore routes
   */
  public String apiValue() {
    return apiValue;
  }

  /**
   * Parses a restore mode from a Platform API form value.
   *
   * <p>Mode parsing is case-sensitive for compatibility with the existing app-data import route,
   * but the enum constant names are accepted for tests and internal callers.
   *
   * <p>A missing or blank value defaults to {@link #MERGE}, which is the least destructive restore
   * behavior. Unsupported values fail before a restore plan or write can proceed, keeping route
   * errors deterministic and free of backup payload details.
   *
   * @param value raw mode value supplied by the operator route, or {@code null} for merge
   * @return restore mode, defaulting to {@link #MERGE}
   * @throws PlatformApiException when the value is not a supported restore mode
   */
  public static AppDataRestoreMode parse(String value) {
    if (value == null || value.isBlank()) {
      return MERGE;
    }
    for (AppDataRestoreMode mode : values()) {
      if (mode.apiValue.equals(value) || mode.name().equals(value.toUpperCase(Locale.ROOT))) {
        return mode;
      }
    }
    throw new PlatformApiException(
        400,
        "invalid_query_parameter",
        "App-data restore mode must be merge, replaceNamespace, or replaceApp.");
  }
}
