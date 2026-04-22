package network.crypta.platform.appcatalog;

import java.net.URI;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Strict parser for {@code cryptad-app-catalog.properties}.
 *
 * <p>The parser accepts the deterministic key/value sidecar format used by app distribution
 * metadata. It rejects duplicate keys, unsupported schema versions, missing fields, unknown
 * properties, unsafe artifact URIs, invalid hashes, and out-of-order or duplicate entry
 * declarations before any catalog entry can drive an artifact download.
 *
 * <p>The parser is intentionally not a general Java {@link java.util.Properties} reader. It keeps
 * duplicate-key detection, preserves the order from {@code catalog.entries}, and fails closed on
 * unknown fields until the catalog format grows explicit forward-compatibility rules. Signature
 * verification happens outside this class; callers should parse only bytes that have already been
 * authenticated by {@link AppCatalogVerifier}.
 */
public final class AppCatalogParser {
  private AppCatalogParser() {}

  /**
   * Parses catalog properties from exact UTF-8 bytes.
   *
   * <p>The input bytes are decoded as UTF-8, parsed as strict {@code key=value} lines, and
   * converted to immutable catalog records. Entry ids are normalized in the order declared by
   * {@code catalog.entries}; each entry must then declare the same normalized id in its {@code
   * app.*.id} field.
   *
   * @param catalogBytes bytes read from {@code cryptad-app-catalog.properties}
   * @return validated immutable catalog content
   * @throws AppCatalogException if the catalog is malformed or unsupported
   */
  public static AppCatalog parse(byte[] catalogBytes) throws AppCatalogException {
    Map<String, String> properties =
        AppCatalogSidecars.parseKeyValueSidecar(AppCatalogSidecars.utf8(catalogBytes), "catalog");
    int version = parseVersion(removeRequired(properties, "catalog.version"));
    String catalogId = removeRequired(properties, "catalog.id");
    String catalogName = removeRequired(properties, "catalog.name");
    Instant generatedAt = parseInstant(removeRequired(properties, "catalog.generatedAt"));
    List<String> entryIds = parseEntryIds(removeRequired(properties, "catalog.entries"));
    List<AppCatalogEntry> entries = new ArrayList<>(entryIds.size());
    for (String appId : entryIds) {
      entries.add(parseEntry(properties, appId));
    }
    if (!properties.isEmpty()) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported catalog property: " + properties.keySet().iterator().next());
    }
    return new AppCatalog(version, catalogId, catalogName, generatedAt, entries);
  }

  private static int parseVersion(String versionText) throws AppCatalogException {
    try {
      int version = Integer.parseInt(versionText);
      if (version != 1) {
        throw AppCatalogSidecars.invalidEntry("unsupported catalog.version: " + version);
      }
      return version;
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid catalog.version: " + versionText,
          exception);
    }
  }

  private static Instant parseInstant(String text) throws AppCatalogException {
    try {
      return Instant.parse(text);
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid catalog.generatedAt: " + text,
          exception);
    }
  }

  private static List<String> parseEntryIds(String rawEntries) throws AppCatalogException {
    if (rawEntries.isBlank()) {
      return List.of();
    }
    Set<String> entryIds = new LinkedHashSet<>();
    for (String token : rawEntries.split(",", -1)) {
      String normalized = AppCatalogEntry.normalizeAppId(token);
      if (!entryIds.add(normalized)) {
        throw AppCatalogSidecars.invalidEntry("duplicate catalog.entries app id: " + normalized);
      }
    }
    return List.copyOf(entryIds);
  }

  private static AppCatalogEntry parseEntry(Map<String, String> properties, String appId)
      throws AppCatalogException {
    String prefix = "app." + appId + ".";
    String declaredId = removeRequired(properties, prefix + "id");
    String normalizedDeclaredId = AppCatalogEntry.normalizeAppId(declaredId);
    if (!appId.equals(normalizedDeclaredId)) {
      throw AppCatalogSidecars.invalidEntry(
          "catalog.entries id does not match app." + appId + ".id");
    }
    try {
      return new AppCatalogEntry(
          declaredId,
          removeRequired(properties, prefix + "name"),
          removeRequired(properties, prefix + "version"),
          removeRequired(properties, prefix + "summary"),
          URI.create(removeRequired(properties, prefix + "bundle.uri")),
          removeRequired(properties, prefix + "bundle.sha256"),
          parseSize(removeRequired(properties, prefix + "bundle.size.bytes"), appId),
          removeRequired(properties, prefix + "bundle.type"),
          parsePermissions(removeRequired(properties, prefix + "permissions")));
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid app." + appId + ".bundle.uri",
          exception);
    }
  }

  private static long parseSize(String sizeText, String appId) throws AppCatalogException {
    try {
      return Long.parseLong(sizeText);
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid app." + appId + ".bundle.size.bytes: " + sizeText,
          exception);
    }
  }

  private static List<String> parsePermissions(String rawPermissions) {
    if (rawPermissions.isBlank()) {
      return List.of();
    }
    List<String> permissions = new ArrayList<>();
    for (String permission : rawPermissions.split(",", -1)) {
      permissions.add(permission.trim());
    }
    return permissions;
  }

  private static String removeRequired(Map<String, String> properties, String key)
      throws AppCatalogException {
    String value = properties.remove(key);
    if (value == null) {
      throw AppCatalogSidecars.invalidEntry("missing " + key);
    }
    return value;
  }
}
