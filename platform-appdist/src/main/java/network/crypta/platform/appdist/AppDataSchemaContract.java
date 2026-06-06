package network.crypta.platform.appdist;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Signed manifest contract for durable app-data schema and migration metadata.
 *
 * <p>The contract is embedded in {@code cryptad-app.properties}, which means bundle digest and
 * signature verification cover the schema version, namespace targets, and migration steps used by
 * the update lifecycle. Older manifests can keep this contract undeclared; the update planner then
 * treats durable app-data schema as unknown and does not invent migration work.
 *
 * <p>When a bundle declares migrations, this aggregate keeps namespace declarations and migration
 * steps immutable, duplicate-free, and ordered by their manifest declaration order. That stable
 * shape matters for deterministic catalog summaries, release-certification evidence, and update
 * planning that compares installed data metadata with candidate bundle expectations.
 *
 * @param currentSchemaVersion optional global app-data schema version expected by the bundle
 * @param namespaces per-namespace current schema declarations from the signed manifest
 * @param migrations signed migration steps available to the update lifecycle
 */
public record AppDataSchemaContract(
    Integer currentSchemaVersion,
    List<AppDataNamespaceSchema> namespaces,
    List<AppDataMigrationStep> migrations) {
  /** Shared no-contract instance used by older manifests and compatibility constructors. */
  private static final AppDataSchemaContract UNDECLARED =
      new AppDataSchemaContract(null, List.of(), List.of());

  /**
   * Creates a normalized app-data schema contract.
   *
   * <p>A {@code null} global schema version means the manifest did not declare a global app-data
   * schema. Namespace declarations and migration steps remain immutable, deterministic, and
   * duplicate-free so writers and update summaries can rely on their order.
   *
   * @param currentSchemaVersion optional positive global schema version
   * @param namespaces per-namespace schema declarations to normalize and copy
   * @param migrations signed migration steps to normalize and copy
   */
  public AppDataSchemaContract {
    if (currentSchemaVersion != null && currentSchemaVersion <= 0) {
      throw new IllegalArgumentException("app.data.schema.current must be positive");
    }
    namespaces = normalizeNamespaces(namespaces);
    migrations = normalizeMigrations(migrations);
  }

  /**
   * Returns the no-contract value used by older manifests.
   *
   * <p>The returned instance has no global version, no namespace declarations, and no migration
   * steps. It is safe to share because the record components are immutable.
   *
   * @return undeclared app-data schema contract for manifests without migration metadata
   */
  public static AppDataSchemaContract undeclared() {
    return UNDECLARED;
  }

  /**
   * Returns whether the manifest declared any app-data schema or migration metadata.
   *
   * @return {@code true} when at least one app-data contract field is present
   */
  public boolean declared() {
    return currentSchemaVersion != null || !namespaces.isEmpty() || !migrations.isEmpty();
  }

  /**
   * Looks up a declared namespace schema.
   *
   * <p>The lookup applies the same namespace normalization as parsing so callers can use manifest
   * text, app-data metadata keys, or migration step namespaces without duplicating comparison
   * logic.
   *
   * @param namespace namespace to normalize and find
   * @return schema declaration, or {@code null} when absent
   */
  public AppDataNamespaceSchema namespace(String namespace) {
    String normalized = AppDataNamespaceSchema.normalizeNamespace(namespace);
    for (AppDataNamespaceSchema schema : namespaces) {
      if (schema.namespace().equals(normalized)) {
        return schema;
      }
    }
    return null;
  }

  /**
   * Normalizes and de-duplicates namespace declarations.
   *
   * <p>The returned list preserves declaration order after normalization. Duplicate namespace
   * declarations are rejected because they would make target schema selection ambiguous.
   *
   * @param namespaces namespace declarations supplied to the contract constructor
   * @return immutable list of unique namespace declarations
   */
  private static List<AppDataNamespaceSchema> normalizeNamespaces(
      List<AppDataNamespaceSchema> namespaces) {
    LinkedHashMap<String, AppDataNamespaceSchema> normalized = new LinkedHashMap<>();
    for (AppDataNamespaceSchema namespace :
        List.copyOf(Objects.requireNonNull(namespaces, "namespaces"))) {
      AppDataNamespaceSchema checked = Objects.requireNonNull(namespace, "namespace schema");
      if (normalized.putIfAbsent(checked.namespace(), checked) != null) {
        throw new IllegalArgumentException(
            "duplicate app.data namespace schema: " + checked.namespace());
      }
    }
    return List.copyOf(normalized.values());
  }

  /**
   * Normalizes and de-duplicates migration step declarations.
   *
   * <p>The returned list preserves declaration order after validating that every step id is unique.
   * Duplicate ids are rejected because update histories, summaries, and path selection all use step
   * ids as stable references.
   *
   * @param migrations migration steps supplied to the contract constructor
   * @return immutable list of unique migration steps
   */
  private static List<AppDataMigrationStep> normalizeMigrations(
      List<AppDataMigrationStep> migrations) {
    Map<String, AppDataMigrationStep> byId = new LinkedHashMap<>();
    for (AppDataMigrationStep migration :
        List.copyOf(Objects.requireNonNull(migrations, "migrations"))) {
      AppDataMigrationStep checked = Objects.requireNonNull(migration, "migration step");
      if (byId.putIfAbsent(checked.stepId(), checked) != null) {
        throw new IllegalArgumentException(
            "duplicate app.data migration step: " + checked.stepId());
      }
    }
    return List.copyOf(byId.values());
  }
}
