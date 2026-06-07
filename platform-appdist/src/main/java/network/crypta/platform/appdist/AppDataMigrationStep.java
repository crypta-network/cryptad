package network.crypta.platform.appdist;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Describes one signed app-data namespace schema migration step declared by an app bundle.
 *
 * <p>Migration steps form the durable-data upgrade contract that is covered by bundle signing and
 * digest verification. Each step advances one namespace from a positive source schema version to a
 * higher target schema version and names a bundle-relative command that can perform the dry-run and
 * apply work. Update planning can combine multiple steps into a bounded path when an installed app
 * is more than one schema version behind the candidate bundle.
 *
 * <p>The rollback and stopped-app flags are operator-facing risk controls. A rollback-incompatible
 * step requires explicit acknowledgement before apply, and a step that requires the app to be
 * stopped cannot run against live, mutating app data. Descriptions are bounded single-line text so
 * they remain safe for manifest files, release certification, and Platform API summaries.
 *
 * @param stepId stable path-safe step identifier within the signed bundle
 * @param namespace normalized durable app-data namespace advanced by this step
 * @param fromSchemaVersion positive source schema version expected before the step runs
 * @param toSchemaVersion positive target schema version produced by the step
 * @param command validated relative bundle command used for dry-run and apply execution
 * @param rollbackCompatible whether post-migration data remains readable by the previous bundle
 * @param requiresStopped whether this step must run only while the app process is stopped
 * @param description bounded operator-facing description of the schema change
 */
public record AppDataMigrationStep(
    String stepId,
    String namespace,
    int fromSchemaVersion,
    int toSchemaVersion,
    AppDataMigrationCommand command,
    boolean rollbackCompatible,
    boolean requiresStopped,
    String description) {
  private static final Pattern STEP_ID_PATTERN =
      Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");
  private static final int MAX_STEP_ID_LENGTH = 96;
  private static final int MAX_DESCRIPTION_LENGTH = 256;

  /**
   * Creates a validated migration step.
   *
   * <p>Step ids are path-safe identifiers that are stable within one bundle. Schema versions are
   * positive and must increase. The command is a signed relative bundle path, and descriptions are
   * bounded single-line operator text.
   *
   * @param stepId stable path-safe step identifier within the signed bundle
   * @param namespace durable app-data namespace advanced by this step
   * @param fromSchemaVersion positive source schema version expected before the step runs
   * @param toSchemaVersion positive target schema version produced by the step
   * @param command relative bundle command already validated as path-safe
   * @param rollbackCompatible whether old bundles can read data after this migration
   * @param requiresStopped whether the app process must be stopped before execution
   * @param description bounded single-line operator description
   */
  public AppDataMigrationStep {
    stepId = normalizeStepId(stepId);
    namespace = AppDataNamespaceSchema.normalizeNamespace(namespace);
    if (fromSchemaVersion <= 0) {
      throw new IllegalArgumentException("app.data migration from version must be positive");
    }
    if (toSchemaVersion <= 0) {
      throw new IllegalArgumentException("app.data migration to version must be positive");
    }
    if (toSchemaVersion <= fromSchemaVersion) {
      throw new IllegalArgumentException("app.data migration target must be greater than source");
    }
    Objects.requireNonNull(command, "command");
    description = normalizeDescription(description);
  }

  /**
   * Normalizes a migration step id from the manifest.
   *
   * <p>The normalized id is lowercase and path-safe. It may be used in public summaries and
   * deterministic plan ordering, so empty values, leading or trailing punctuation, and excessive
   * length are rejected.
   *
   * @param rawValue raw step id from {@code app.data.migrations}
   * @return normalized lowercase step id
   * @throws NullPointerException when {@code rawValue} is {@code null}
   * @throws IllegalArgumentException when the value is blank, too long, or unsafe
   */
  static String normalizeStepId(String rawValue) {
    Objects.requireNonNull(rawValue, "stepId");
    String normalized = rawValue.trim().toLowerCase(java.util.Locale.ROOT);
    if (normalized.isEmpty()
        || normalized.length() > MAX_STEP_ID_LENGTH
        || !STEP_ID_PATTERN.matcher(normalized).matches()) {
      throw new IllegalArgumentException("invalid app.data migration step id: " + rawValue);
    }
    return normalized;
  }

  /**
   * Normalizes bounded operator-facing migration text.
   *
   * @param rawValue raw description from the migration step properties
   * @return trimmed single-line description safe for summaries
   * @throws NullPointerException when {@code rawValue} is {@code null}
   * @throws IllegalArgumentException when the value is blank, multi-line, or too long
   */
  private static String normalizeDescription(String rawValue) {
    Objects.requireNonNull(rawValue, "description");
    String normalized = rawValue.trim();
    if (normalized.isEmpty()) {
      throw new IllegalArgumentException("app.data migration description must not be blank");
    }
    if (normalized.length() > MAX_DESCRIPTION_LENGTH || containsLineBreak(normalized)) {
      throw new IllegalArgumentException(
          "app.data migration description must be bounded single-line text");
    }
    return normalized;
  }

  /**
   * Returns whether a description contains a line separator.
   *
   * @param value normalized description text to inspect
   * @return {@code true} when the text contains carriage return or newline characters
   */
  private static boolean containsLineBreak(String value) {
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      if (character == '\n' || character == '\r') {
        return true;
      }
    }
    return false;
  }
}
