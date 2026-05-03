package network.crypta.platform.appui;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

/**
 * Token-free browser session identity for one installed static app UI.
 *
 * <p>This record is the safe result of verifying an opaque browser-session token. The raw token is
 * deliberately absent. HTTP adapters and other transport bridges can convert the app id and
 * permission snapshot into a Platform API principal without carrying the credential into router
 * state, audit entries, JSON responses, diagnostics, or accidental {@link Object#toString()}
 * output.
 *
 * <p>The permission list is normalized at construction time: entries are trimmed, blank values are
 * rejected, duplicates collapse, and the retained list is sorted and immutable. That makes
 * capability checks deterministic even when an issuer receives permissions from a manifest parser
 * or test fixture in a different order. The timestamps are descriptive state for the verified
 * session. Callers must still check expiry when they accept the original bearer token.
 *
 * <ul>
 *   <li>Use this type after session verification, never as a bearer credential.
 *   <li>Keep it process-local and token-free when passing identity into Platform API code.
 *   <li>Treat instances as immutable snapshots of app identity and manifest permissions.
 * </ul>
 *
 * @param appId normalized application identifier bound to the browser session
 * @param permissions immutable sorted manifest permission strings captured when the session was
 *     issued
 * @param issuedAt UTC timestamp when the session was issued
 * @param expiresAt UTC timestamp after which the session must not authenticate
 * @param expectedOrigin serialized browser origin this session is bound to, or {@code null} for
 *     legacy same-origin fallback sessions that still accept missing {@code Origin} headers
 * @param originMode origin mode used when the session was issued
 */
public record AppBrowserSession(
    String appId,
    List<String> permissions,
    Instant issuedAt,
    Instant expiresAt,
    String expectedOrigin,
    AppUiOriginMode originMode) {
  /**
   * Creates a token-free session identity.
   *
   * <p>The constructor performs the same normalization expected from production verifiers. It trims
   * the app id, canonicalizes permissions into immutable sorted order, and rejects expired-at-issue
   * sessions so downstream authorization code only sees coherent principal metadata. The
   * constructor does not check the current clock; expiry enforcement remains the responsibility of
   * the verifier that still has access to the raw token and backing session store.
   *
   * @param appId app identifier associated with the verified browser session
   * @param permissions manifest permissions captured when the session was issued
   * @param issuedAt UTC timestamp when the browser session was issued
   * @param expiresAt UTC timestamp after which the browser session is invalid
   * @throws IllegalArgumentException if {@code appId} is blank, a permission is blank, or the
   *     expiry does not come after the issue time
   * @throws NullPointerException if a required field or permission value is {@code null}
   */
  public AppBrowserSession(
      String appId, List<String> permissions, Instant issuedAt, Instant expiresAt) {
    this(appId, permissions, issuedAt, expiresAt, null, AppUiOriginMode.SAME_ORIGIN_FALLBACK);
  }

  /**
   * Creates a token-free session identity using one app UI origin binding.
   *
   * @param appId app identifier associated with the verified browser session
   * @param permissions manifest permissions captured when the session was issued
   * @param issuedAt UTC timestamp when the browser session was issued
   * @param expiresAt UTC timestamp after which the browser session is invalid
   * @param binding app UI origin binding used for bootstrap
   */
  public AppBrowserSession(
      String appId,
      List<String> permissions,
      Instant issuedAt,
      Instant expiresAt,
      AppUiOriginBinding binding) {
    this(
        appId,
        permissions,
        issuedAt,
        expiresAt,
        binding == null ? null : binding.origin(),
        binding == null ? AppUiOriginMode.SAME_ORIGIN_FALLBACK : binding.mode());
  }

  public AppBrowserSession {
    Objects.requireNonNull(appId, "appId");
    Objects.requireNonNull(issuedAt, "issuedAt");
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(originMode, "originMode");
    if (appId.isBlank()) {
      throw new IllegalArgumentException("appId must not be blank");
    }
    if (!expiresAt.isAfter(issuedAt)) {
      throw new IllegalArgumentException("expiresAt must be after issuedAt");
    }
    if (expectedOrigin != null && expectedOrigin.isBlank()) {
      throw new IllegalArgumentException("expectedOrigin must not be blank");
    }
    appId = appId.trim();
    permissions = sortedPermissions(permissions);
    expectedOrigin = expectedOrigin == null ? null : expectedOrigin.trim();
  }

  /**
   * Returns immutable sorted manifest permissions carried by this session.
   *
   * <p>A fresh defensive copy is returned for the accessor, matching the record's token-free,
   * immutable identity contract. Callers may read the list for capability checks but cannot mutate
   * the retained authorization view inside this session.
   *
   * @return immutable sorted permission strings suitable for capability checks
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
