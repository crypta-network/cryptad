package network.crypta.platform.devtools;

/**
 * One sanitized check result in a {@code crypta-app test} report.
 *
 * <p>Each instance represents a single developer-facing gate such as bundle validation, UI linting,
 * API compatibility, or dev-server smoke testing. The {@code id} is intentionally stable so JSON
 * consumers can make decisions without parsing human text. The {@code summary} remains
 * human-readable, but it is redacted during construction because failing checks often include paths
 * or session-related strings from lower-level exceptions.
 *
 * <p>The record is immutable after construction. It does not carry raw exceptions, stack traces, or
 * private filesystem paths; callers should convert any diagnostic detail into a short summary
 * before creating a check.
 *
 * @param id stable dotted identifier for the check, for example {@code bundle.validate}
 * @param status normalized pass, warning, or failure status for this individual check
 * @param summary short human-readable result text, sanitized before storage in the report
 */
record AppTestCheck(String id, AppTestStatus status, String summary) {
  /**
   * Validates and sanitizes one check result.
   *
   * <p>The constructor rejects blank identifiers, requires a status value, and normalizes a {@code
   * null} summary to an empty redacted string. This keeps both terminal output and JSON reports
   * deterministic even when a lower-level check omits optional diagnostic text.
   */
  AppTestCheck {
    if (id == null || id.isBlank()) {
      throw new IllegalArgumentException("check id must not be blank");
    }
    java.util.Objects.requireNonNull(status, "status");
    summary = AppTestRedactor.redact(summary == null ? "" : summary);
  }
}
