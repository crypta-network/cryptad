package network.crypta.platform.devtools;

/**
 * One deterministic app-owned UI lint finding.
 *
 * <p>Findings are the stable boundary between the offline linter, CLI text output, JSON reports,
 * and release-certification evidence. The values intentionally avoid absolute paths, request data,
 * query strings, or runtime credentials. A finding should identify the affected bundle-relative
 * file and the rule that fired, while leaving policy decisions to the command mode that selected
 * the effective {@link AppUiLintSeverity}. That keeps normal lint runs advisory where appropriate
 * and lets strict validation promote the same rule ids without inventing a separate result model.
 *
 * <p>The record is immutable and contains only presentation-safe strings. Callers should keep
 * {@code id} values stable because app authors and certification tools may compare them across
 * builds.
 *
 * @param id stable machine-readable finding id used by CLI and JSON consumers
 * @param category broad lint category, such as {@code csp}, {@code sdk}, or {@code accessibility}
 * @param severity effective severity after normal or strict lint mode has been applied
 * @param message human-readable diagnostic text that avoids secrets and host-private paths
 * @param path bundle-relative path, or an empty string when the finding applies to the whole bundle
 */
record AppUiLintFinding(
    String id, String category, AppUiLintSeverity severity, String message, String path) {}
