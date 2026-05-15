package network.crypta.platform.devtools;

import java.util.List;

/**
 * Deterministic report model for {@code crypta-app test}.
 *
 * <p>The report is the in-memory representation of the optional JSON artifact and the source for
 * terminal summaries. It carries only stable fields: schema version, app identity, aggregate
 * status, and ordered check results. The model performs defensive copying and redaction at the
 * boundary so callers cannot accidentally serialize mutable lists, raw local paths, or session
 * values after the suite has finished.
 *
 * <p>Schema version {@code 1} is the only supported shape for PR-225 developer tooling. Rejecting
 * unknown versions in the constructor keeps tests and future migrations honest; a new schema must
 * introduce an explicit model change rather than silently reusing this serializer.
 *
 * @param schemaVersion stable JSON schema version, currently required to be {@code 1}
 * @param appId app identifier from the validated manifest, sanitized before serialization
 * @param version app version from the validated manifest, sanitized before serialization
 * @param status aggregate report status after strict-mode warning promotion is applied
 * @param checks ordered immutable list of individual sanitized check results
 */
record AppTestReport(
    int schemaVersion,
    String appId,
    String version,
    AppTestStatus status,
    List<AppTestCheck> checks) {
  /**
   * Validates the schema version and freezes report content.
   *
   * <p>A {@code null} app id or version becomes an empty redacted value, which is useful when
   * bundle validation fails before a manifest can be trusted. The checklist is copied in order so
   * the JSON report remains deterministic for snapshot-style assertions and release evidence.
   */
  AppTestReport {
    if (schemaVersion != 1) {
      throw new IllegalArgumentException("unsupported app test report schema");
    }
    appId = AppTestRedactor.redact(appId == null ? "" : appId);
    version = AppTestRedactor.redact(version == null ? "" : version);
    java.util.Objects.requireNonNull(status, "status");
    checks = List.copyOf(checks);
  }
}
