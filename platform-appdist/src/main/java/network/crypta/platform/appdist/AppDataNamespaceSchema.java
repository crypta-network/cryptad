package network.crypta.platform.appdist;

import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Declares the current durable app-data schema version for one namespace in a signed bundle.
 *
 * <p>Namespace declarations let app authors scope schema changes to the durable data they actually
 * read and write. The update planner compares these target versions with stored namespace metadata
 * and selects signed migration steps only for namespaces that contain older durable data. A bundle
 * can omit namespace declarations when it has no durable app-data schema contract.
 *
 * <p>The namespace syntax intentionally matches the durable app-data store's path-safe identifier
 * rules. Values are lowercased and bounded before they become signed manifest metadata, which keeps
 * planning deterministic across hosts and filesystems.
 *
 * @param namespace normalized durable app-data namespace declared by the bundle
 * @param currentSchemaVersion positive schema version expected by this bundle for the namespace
 */
public record AppDataNamespaceSchema(String namespace, int currentSchemaVersion) {
  /** Path-safe namespace segment pattern shared by manifest schema declarations. */
  private static final Pattern SAFE_SEGMENT = Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");

  /** Maximum accepted namespace length in signed app-data schema declarations. */
  private static final int MAX_NAMESPACE_LENGTH = 64;

  /**
   * Creates a namespace schema declaration.
   *
   * @param namespace durable app-data namespace to normalize and validate
   * @param currentSchemaVersion positive schema version expected by the bundle
   */
  public AppDataNamespaceSchema {
    namespace = normalizeNamespace(namespace);
    if (currentSchemaVersion <= 0) {
      throw new IllegalArgumentException("app.data namespace schema version must be positive");
    }
  }

  /**
   * Normalizes a namespace declared by app-data schema or migration metadata.
   *
   * <p>The returned value is lowercase, path-safe, and bounded. This method is used by namespace
   * schema declarations and migration steps so both halves of the signed contract use the same
   * comparison key.
   *
   * @param namespace raw namespace text from the manifest
   * @return normalized namespace identifier suitable for deterministic planning
   * @throws NullPointerException when {@code namespace} is {@code null}
   * @throws IllegalArgumentException when the namespace is blank, too long, or unsafe
   */
  static String normalizeNamespace(String namespace) {
    Objects.requireNonNull(namespace, "namespace");
    String normalized = namespace.trim().toLowerCase(Locale.ROOT);
    if (normalized.isEmpty()
        || normalized.length() > MAX_NAMESPACE_LENGTH
        || !SAFE_SEGMENT.matcher(normalized).matches()) {
      throw new IllegalArgumentException("invalid app.data namespace: " + namespace);
    }
    return normalized;
  }
}
