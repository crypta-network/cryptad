package network.crypta.platform.devtools;

/**
 * Effective severity level for one app-owned UI lint finding.
 *
 * <p>The linter stores the severity after command mode has been applied. For example, a design
 * system adoption rule may be advisory in normal lint mode and fatal in strict validation, but the
 * resulting {@link AppUiLintFinding} carries only the effective value that the CLI should print and
 * count. Keeping this enum small makes command status decisions straightforward: notes are
 * evidence, warnings are advisory unless promoted before the finding is created, and errors fail
 * the explicit UI lint command.
 */
enum AppUiLintSeverity {
  /**
   * Informational evidence that does not affect command status.
   *
   * <p>Use this for not-applicable results or other report entries that help explain why a lint run
   * did not inspect static UI files.
   */
  NOTE,
  /**
   * Advisory finding that stays non-fatal unless a strict check promotes it.
   *
   * <p>Warnings identify platform consistency, accessibility, or future-compatibility issues that
   * app authors should fix before signing, while allowing non-strict developer workflows to
   * continue.
   */
  WARNING,
  /**
   * Fatal finding that makes {@code crypta-app ui lint} fail.
   *
   * <p>Errors represent CSP, safety, SDK-bootstrap, or strict-mode failures that should block the
   * current command result until the staged bundle is corrected.
   */
  ERROR
}
