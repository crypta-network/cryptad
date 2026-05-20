package network.crypta.clients.http;

import java.util.List;
import java.util.Objects;

/**
 * Immutable retirement metadata for one legacy admin HTTP surface.
 *
 * <p>The legacy path is the canonical route prefix used for notices, diagnostics, and Web Shell
 * fallback-link decisions. Replacement fields are optional because pending, retained, and
 * infrastructure routes may not have a shell-native successor.
 *
 * <p>The record carries route-level metadata only. It deliberately does not hold query strings,
 * form fields, peer references, keys, filesystem paths, or request-specific values. This keeps the
 * same object safe to use in page rendering, Web Shell bootstrap data, and process-local
 * diagnostics. Instances are immutable, validate same-origin paths at construction time, and can be
 * shared freely across request-handling threads.
 *
 * <p>Two boolean inclusion flags keep policy decisions explicit. A surface can be counted in
 * diagnostics without appearing in the Web Shell fallback list, and infrastructure entries can be
 * registered for matching while remaining excluded from both user-facing telemetry and navigation.
 * Removal metadata is separate from the retirement state so {@link
 * LegacyAdminRetirementState#PRIMARY_REPLACED} can continue to mean "has a primary replacement"
 * even when a route is still intentionally rendered by legacy code.
 *
 * @param id stable machine-readable identifier used by diagnostics and tests
 * @param title human-readable surface title suitable for notices and link labels
 * @param legacyPath canonical same-origin route prefix for the legacy surface
 * @param state current retirement state that drives notices and navigation decisions
 * @param replacementUrl primary same-origin Web Shell or app URL when known
 * @param replacementLabel visible label for the replacement URL when present
 * @param notes short maintainer note describing the classification and migration context
 * @param removalMode current execution policy for the canonical legacy route
 * @param removalWave first removal wave number, or {@code 0} when not removed by default
 * @param removedByDefaultSince stable release/phase marker for removal-by-default, or {@code null}
 * @param fallbackPolicy path-free description of temporary fallback behavior
 * @param removalScope request-path matching scope for removal responses
 * @param scopeExpandedInWave removal wave that expanded matching beyond canonical aliases, or
 *     {@code 0} when the scope has not been expanded by a later wave
 * @param explicitRemovalChildPaths same-origin child paths eligible for replacement responses when
 *     {@code removalScope} is {@link LegacyAdminRemovalScope#EXPLICIT_CHILDREN}
 * @param blockMutatingRequests whether non-read requests should be blocked when this surface's
 *     replacement is available; partial replacements leave mutations as legacy fallback
 * @param includeInUsageDiagnostics whether process-local usage diagnostics should include this
 *     surface
 * @param includeInWebShellFallbackLinks whether the Web Shell should show this as a fallback link
 */
public record LegacyAdminSurface(
    String id,
    String title,
    String legacyPath,
    LegacyAdminRetirementState state,
    String replacementUrl,
    String replacementLabel,
    String notes,
    LegacyAdminRemovalMode removalMode,
    int removalWave,
    String removedByDefaultSince,
    String fallbackPolicy,
    LegacyAdminRemovalScope removalScope,
    int scopeExpandedInWave,
    List<String> explicitRemovalChildPaths,
    boolean blockMutatingRequests,
    boolean includeInUsageDiagnostics,
    boolean includeInWebShellFallbackLinks) {
  /**
   * Creates an immutable legacy-admin surface description.
   *
   * <p>Required text fields must be nonblank. Route fields must be same-origin absolute paths,
   * which prevents notice rendering from introducing external or protocol-relative links. Optional
   * replacement fields may be {@code null} for retained, pending, fallback, and infrastructure
   * surfaces that do not have a declared primary successor.
   *
   * @throws NullPointerException if any required field is {@code null}
   * @throws IllegalArgumentException if text fields are blank or a path is not same-origin
   */
  public LegacyAdminSurface {
    requireText(id, "id");
    requireText(title, "title");
    requirePath(legacyPath, "legacyPath");
    Objects.requireNonNull(state, "state");
    if (replacementUrl != null) {
      requirePath(replacementUrl, "replacementUrl");
    }
    if (replacementLabel != null) {
      requireText(replacementLabel, "replacementLabel");
    }
    requireText(notes, "notes");
    Objects.requireNonNull(removalMode, "removalMode");
    if (removalWave < 0) {
      throw new IllegalArgumentException("removalWave must not be negative");
    }
    if (removedByDefaultSince != null) {
      requireText(removedByDefaultSince, "removedByDefaultSince");
    }
    requireText(fallbackPolicy, "fallbackPolicy");
    Objects.requireNonNull(removalScope, "removalScope");
    if (scopeExpandedInWave < 0) {
      throw new IllegalArgumentException("scopeExpandedInWave must not be negative");
    }
    explicitRemovalChildPaths = List.copyOf(explicitRemovalChildPaths);
    for (String childPath : explicitRemovalChildPaths) {
      requirePath(childPath, "explicitRemovalChildPaths");
    }
    if (removalScope != LegacyAdminRemovalScope.EXPLICIT_CHILDREN
        && !explicitRemovalChildPaths.isEmpty()) {
      throw new IllegalArgumentException(
          "explicitRemovalChildPaths require EXPLICIT_CHILDREN removal scope");
    }
  }

  /**
   * Returns whether this surface should render a retirement notice on legacy HTML pages.
   *
   * <p>Only primary-replaced surfaces with a concrete replacement URL and a render-legacy execution
   * mode render notices. Pending and retained pages intentionally stay quiet so operators are not
   * pushed away from flows whose replacement is incomplete or intentionally out of scope. Removed
   * pages emit a separate replacement response before legacy rendering starts.
   *
   * @return {@code true} when the surface has a primary replacement and replacement link
   */
  public boolean rendersNotice() {
    return state == LegacyAdminRetirementState.PRIMARY_REPLACED
        && removalMode == LegacyAdminRemovalMode.RENDER_LEGACY
        && replacementUrl != null;
  }

  private static void requireText(String value, String label) {
    Objects.requireNonNull(value, label);
    if (value.isBlank()) {
      throw new IllegalArgumentException(label + " must not be blank");
    }
  }

  private static void requirePath(String value, String label) {
    requireText(value, label);
    if (!value.startsWith("/") || value.startsWith("//")) {
      throw new IllegalArgumentException(label + " must be a same-origin absolute path");
    }
  }
}
