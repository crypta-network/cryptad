package network.crypta.platform.appvault;

import java.util.Locale;
import java.util.Objects;

/**
 * Lifecycle state for one app-bound identity grant.
 *
 * <p>Status is separate from expiry and scope. A grant authorizes use only when its status is
 * active, its optional expiry is still in the future, and the requested scope remains present.
 * Keeping status as explicit metadata lets operator workflows suspend access, preserve audit
 * history, and distinguish update-driven review from permanent revocation.
 */
public enum AppIdentityGrantStatus {
  /**
   * Grant may authorize matching operations when unexpired and capability checks also pass.
   *
   * <p>Active does not bypass manifest permissions. The caller still needs the vault capability
   * required for the route and operation being attempted.
   */
  ACTIVE("active"),

  /**
   * Grant is disabled pending operator review, commonly after permission removal.
   *
   * <p>Inactive grants remain visible to operator management routes so the reason for disabled
   * access is inspectable without preserving app-facing use.
   */
  INACTIVE("inactive"),

  /**
   * Grant was explicitly revoked by the operator or lifecycle cleanup.
   *
   * <p>Revoked grants are not app-visible after reinstall cleanup, but they can remain in
   * management listings as historical evidence.
   */
  REVOKED("revoked");

  private final String jsonValue;

  AppIdentityGrantStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the public status value.
   *
   * <p>The returned spelling is used in Platform API JSON, properties files, and Web Shell status
   * displays.
   *
   * @return stable lower-case grant status value
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Parses a public grant status.
   *
   * <p>The parser accepts surrounding whitespace and case variants, then returns the canonical enum
   * value. Unknown text is reported as a stable vault error so corrupted store files and invalid
   * API requests have predictable handling.
   *
   * @param value status text from a request or persisted grant record
   * @return matching lifecycle status
   */
  public static AppIdentityGrantStatus fromJsonValue(String value) {
    String normalized = Objects.requireNonNull(value, "value").trim().toLowerCase(Locale.ROOT);
    for (AppIdentityGrantStatus status : values()) {
      if (status.jsonValue.equals(normalized)) {
        return status;
      }
    }
    throw new AppVaultException(
        400, "unsupported_grant_status", "Unsupported identity grant status.");
  }
}
