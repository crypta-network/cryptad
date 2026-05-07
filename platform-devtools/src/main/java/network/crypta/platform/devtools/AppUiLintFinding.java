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
 * {@code id} values stable because app authors, JSON fixtures, and certification tools may compare
 * them across builds. The {@code path} value is always a bundle-relative display path, not a host
 * path. When a rule applies to the whole bundle, use an empty path and explain the scope in the
 * message. That convention lets command output stay useful without leaking local staging
 * directories.
 *
 * @param id stable machine-readable finding id used by CLI, tests, and JSON evidence consumers
 * @param category broad lint category, such as {@code csp}, {@code sdk}, or {@code accessibility}
 * @param severity effective severity after normal or strict lint mode has been applied
 * @param message human-readable diagnostic text that avoids secrets, query strings, and
 *     host-private paths
 * @param path bundle-relative path, or an empty string when the finding applies to the whole bundle
 * @see AppUiLintResult
 */
record AppUiLintFinding(
    String id, String category, AppUiLintSeverity severity, String message, String path) {}
