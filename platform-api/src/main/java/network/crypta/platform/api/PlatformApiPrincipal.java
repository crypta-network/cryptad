package network.crypta.platform.api;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

/**
 * Token-free identity attached to one Platform API request.
 *
 * <p>The principal intentionally stores only stable identity metadata and manifest-declared
 * permissions. Raw launch tokens, headers, and transport details remain outside this model so they
 * cannot appear in router JSON, audit entries, snapshots, or diagnostic strings by accident.
 *
 * <p>There are two valid shapes. A host/operator principal has no app id and no app permissions; it
 * represents the existing trusted local management path. An app principal has a normalized app id,
 * an {@link PlatformApiAuthSource#APP_TOKEN} source, and the manifest permissions from the
 * currently running app snapshot. The router uses that immutable permission list for default-deny
 * capability checks.
 *
 * @param type principal category used by the router's authorization path
 * @param authSource transport-side authentication source that established the identity
 * @param appId normalized app id for app principals, or {@code null} for host/operator principals
 * @param permissions immutable sorted app permissions for app principals
 */
public record PlatformApiPrincipal(
    PlatformApiPrincipalType type,
    PlatformApiAuthSource authSource,
    String appId,
    List<String> permissions) {
  /**
   * Creates a validated token-free principal.
   *
   * <p>The constructor enforces the two supported principal shapes and normalizes app permissions
   * into sorted immutable order. It trims app ids and permission strings, rejects blank app ids for
   * app principals, and rejects any host/operator principal that accidentally carries app identity
   * or capabilities.
   *
   * @throws IllegalArgumentException if the identity fields do not match the principal type
   * @throws NullPointerException if {@code type}, {@code authSource}, or {@code permissions} is
   *     {@code null}, or if a permission element is {@code null}
   */
  public PlatformApiPrincipal {
    Objects.requireNonNull(type, "type");
    Objects.requireNonNull(authSource, "authSource");
    permissions = sortedPermissions(permissions);
    if (type == PlatformApiPrincipalType.APP) {
      if (appId == null || appId.isBlank()) {
        throw new IllegalArgumentException("app principal requires an app id");
      }
      appId = appId.trim();
      if (authSource != PlatformApiAuthSource.APP_TOKEN) {
        throw new IllegalArgumentException("app principal requires APP_TOKEN auth source");
      }
    } else {
      if (appId != null) {
        throw new IllegalArgumentException("host principal must not carry an app id");
      }
      if (!permissions.isEmpty()) {
        throw new IllegalArgumentException("host principal must not carry app permissions");
      }
      if (authSource != PlatformApiAuthSource.HOST_LOCAL) {
        throw new IllegalArgumentException("host principal requires HOST_LOCAL auth source");
      }
    }
  }

  /**
   * Returns the default host/operator principal used by existing tests and call sites.
   *
   * <p>This factory preserves compatibility for transport bridges and tests that predate app
   * principals. Requests built with this principal continue through the legacy host/operator path
   * and do not require manifest capability strings.
   *
   * @return trusted local host/operator principal with no app id or permissions
   */
  public static PlatformApiPrincipal hostOperator() {
    return new PlatformApiPrincipal(
        PlatformApiPrincipalType.HOST_OPERATOR, PlatformApiAuthSource.HOST_LOCAL, null, List.of());
  }

  /**
   * Builds an app principal from an AppHost-verified launch token identity.
   *
   * <p>The caller must authenticate the launch token before invoking this factory. The raw token is
   * deliberately absent from the resulting value; only the app id and manifest permission strings
   * needed for authorization cross the transport-neutral boundary.
   *
   * @param appId normalized app id associated with the verified live app process
   * @param permissions manifest-declared permissions for the currently running app
   * @return token-free app principal ready for Platform API capability checks
   */
  public static PlatformApiPrincipal appToken(String appId, Collection<String> permissions) {
    return new PlatformApiPrincipal(
        PlatformApiPrincipalType.APP,
        PlatformApiAuthSource.APP_TOKEN,
        appId,
        List.copyOf(permissions));
  }

  /**
   * Returns whether this request was authenticated as an app process.
   *
   * <p>This convenience method is used by the router and audit log to separate app-originated
   * decisions from host/operator traffic. It does not re-check the authentication source; the
   * constructor already enforces that app principals use the app-token source.
   *
   * @return {@code true} for app principals and {@code false} for host/operator principals
   */
  public boolean isApp() {
    return type == PlatformApiPrincipalType.APP;
  }

  /**
   * Returns immutable sorted manifest permissions carried by this principal.
   *
   * <p>Host/operator principals always return an empty list. App principals return the permissions
   * captured after launch-token authentication. A defensive copy is returned so callers cannot
   * mutate the record's retained authorization view.
   *
   * @return immutable sorted permission strings for app principals, or an empty list for host
   *     principals
   */
  @Override
  public List<String> permissions() {
    return List.copyOf(this.permissions);
  }

  private static List<String> sortedPermissions(Collection<String> source) {
    Objects.requireNonNull(source, "permissions");
    TreeSet<String> sorted = new TreeSet<>();
    for (String permission : source) {
      String normalized = Objects.requireNonNull(permission, "permissions value").trim();
      if (normalized.isEmpty()) {
        throw new IllegalArgumentException("permissions must not contain blank values");
      }
      sorted.add(normalized);
    }
    return List.copyOf(sorted);
  }
}
