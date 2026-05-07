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
 *
 * <p>Do not treat these values as a global policy table. The same rule id can be emitted with
 * different severities in normal and strict runs, and release-certification code reads the already
 * computed counts from {@link AppUiLintResult}. That separation keeps the offline linter usable for
 * third-party authors while still allowing first-party or release-candidate checks to be stricter.
 */
enum AppUiLintSeverity {
  /**
   * Informational evidence that does not affect command status.
   *
   * <p>Use this for not-applicable results or other report entries that help explain why a lint run
   * did not inspect static UI files. Notes should be sparse and explanatory because they are
   * preserved in JSON evidence even when no findings are fatal.
   */
  NOTE,
  /**
   * Advisory finding that stays non-fatal unless a strict check promotes it.
   *
   * <p>Warnings identify platform consistency, accessibility, or future-compatibility issues that
   * app authors should fix before signing, while allowing non-strict developer workflows to
   * continue. A warning should still be actionable and tied to a stable rule id.
   */
  WARNING,
  /**
   * Fatal finding that makes {@code crypta-app ui lint} fail.
   *
   * <p>Errors represent CSP, safety, SDK-bootstrap, or strict-mode failures that should block the
   * current command result until the staged bundle is corrected. Error messages must remain
   * sanitized because they can appear in release evidence and validation output.
   */
  ERROR
}
