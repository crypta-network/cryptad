package network.crypta.platform.appcatalog;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;

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
      entries.add(parseEntry(properties, appId, version));
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
      if (!AppCatalog.isSupportedVersion(version)) {
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

  private static AppCatalogEntry parseEntry(
      Map<String, String> properties, String appId, int version) throws AppCatalogException {
    String prefix = "app." + appId + ".";
    String declaredId = removeRequired(properties, prefix + "id");
    String normalizedDeclaredId = AppCatalogEntry.normalizeAppId(declaredId);
    if (!appId.equals(normalizedDeclaredId)) {
      throw AppCatalogSidecars.invalidEntry(
          "catalog.entries id does not match app." + appId + ".id");
    }
    List<String> permissions = parsePermissions(removeRequired(properties, prefix + "permissions"));
    boolean storeMetadataAllowed = version == AppCatalog.VERSION_STORE_METADATA;
    return new AppCatalogEntry(
        declaredId,
        removeRequired(properties, prefix + "name"),
        removeRequired(properties, prefix + "version"),
        removeRequired(properties, prefix + "summary"),
        parseStoreMetadataUri(properties, prefix + "homepage", storeMetadataAllowed),
        parseStoreMetadataUri(properties, prefix + "source", storeMetadataAllowed),
        storeMetadataAllowed ? removeOptional(properties, prefix + "license") : Optional.empty(),
        storeMetadataAllowed
            ? parseCategories(removeOptional(properties, prefix + "categories").orElse(null))
            : List.of(),
        storeMetadataAllowed
            ? new AppCatalogCompatibilityMetadata(
                removeOptional(properties, prefix + "minimumCryptaVersion").orElse(null),
                parseApiCompatibility(properties, prefix))
            : AppCatalogCompatibilityMetadata.EMPTY,
        storeMetadataAllowed ? parseReview(properties, prefix) : AppCatalogReviewMetadata.EMPTY,
        storeMetadataAllowed ? parseChangelog(properties, prefix) : AppCatalogChangelog.EMPTY,
        storeMetadataAllowed ? parseScreenshots(properties, prefix) : List.of(),
        parseUri(removeRequired(properties, prefix + "bundle.uri"), prefix + "bundle.uri"),
        removeRequired(properties, prefix + "bundle.sha256"),
        parseSize(removeRequired(properties, prefix + "bundle.size.bytes"), appId),
        removeRequired(properties, prefix + "bundle.type"),
        permissions,
        storeMetadataAllowed ? parsePermissionRationales(properties, prefix) : Map.of());
  }

  private static Optional<URI> parseStoreMetadataUri(
      Map<String, String> properties, String fieldName, boolean storeMetadataAllowed) {
    if (!storeMetadataAllowed) {
      return Optional.empty();
    }
    return removeOptional(properties, fieldName).map(value -> parseUri(value, fieldName));
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

  private static List<String> parseCategories(String rawCategories) {
    if (rawCategories == null || rawCategories.isBlank()) {
      return List.of();
    }
    List<String> categories = new ArrayList<>();
    for (String category : rawCategories.split(",", -1)) {
      categories.add(category.trim());
    }
    return categories;
  }

  private static AppApiCompatibilityMetadata parseApiCompatibility(
      Map<String, String> properties, String prefix) {
    Integer minimumVersion =
        parseOptionalPositiveInteger(properties, prefix + "api.minimumVersion");
    Integer maximumTestedVersion =
        parseOptionalPositiveInteger(properties, prefix + "api.maximumTestedVersion");
    List<String> optionalCapabilities =
        parseOptionalCapabilities(
            removeOptional(properties, prefix + "api.optionalCapabilities").orElse(null));
    boolean experimentalCapabilitiesAccepted =
        parseExperimentalCapabilitiesAccepted(properties, prefix);
    try {
      return new AppApiCompatibilityMetadata(
          minimumVersion,
          maximumTestedVersion,
          optionalCapabilities,
          experimentalCapabilitiesAccepted);
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.getMessage(), exception);
    }
  }

  private static Integer parseOptionalPositiveInteger(Map<String, String> properties, String key) {
    Optional<String> value = removeOptional(properties, key);
    if (value.isEmpty()) {
      return null;
    }
    try {
      int parsed = Integer.parseInt(value.get());
      if (parsed <= 0) {
        throw AppCatalogSidecars.invalidEntry(key + " must be a positive integer");
      }
      return parsed;
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid " + key + ": " + value.get(),
          exception);
    }
  }

  private static boolean parseExperimentalCapabilitiesAccepted(
      Map<String, String> properties, String prefix) {
    String key = prefix + "api.experimentalCapabilitiesAccepted";
    Optional<String> value = removeOptional(properties, key);
    if (value.isEmpty()) {
      return false;
    }
    String normalized = value.get().toLowerCase(java.util.Locale.ROOT);
    if (normalized.equals("true")) {
      return true;
    }
    if (normalized.equals("false")) {
      return false;
    }
    throw AppCatalogSidecars.invalidEntry("invalid " + key + ": " + value.get());
  }

  private static List<String> parseOptionalCapabilities(String rawCapabilities) {
    if (rawCapabilities == null || rawCapabilities.isBlank()) {
      return List.of();
    }
    List<String> capabilities = new ArrayList<>();
    for (String capability : rawCapabilities.split(",", -1)) {
      capabilities.add(capability.trim());
    }
    return capabilities;
  }

  private static URI parseUri(String rawUri, String fieldName) {
    String value =
        AppCatalogSidecars.requireNonBlankSingleLine(
            rawUri, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    try {
      return new URI(value);
    } catch (URISyntaxException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, "invalid " + fieldName, exception);
    }
  }

  private static AppCatalogReviewMetadata parseReview(
      Map<String, String> properties, String prefix) {
    Optional<String> statusText = removeOptional(properties, prefix + "review.status");
    AppCatalogReviewStatus status =
        statusText
            .map(value -> AppCatalogReviewStatus.parse(value, prefix + "review.status"))
            .orElse(AppCatalogReviewStatus.UNREVIEWED);
    return new AppCatalogReviewMetadata(status, removeOptional(properties, prefix + "review.note"));
  }

  private static AppCatalogChangelog parseChangelog(Map<String, String> properties, String prefix) {
    return new AppCatalogChangelog(
        removeOptional(properties, prefix + "changelog.summary"),
        removeOptional(properties, prefix + "changelog.uri")
            .map(value -> parseUri(value, prefix + "changelog.uri")));
  }

  private static List<URI> parseScreenshots(Map<String, String> properties, String prefix) {
    String screenshotPrefix = prefix + "screenshot.";
    List<String> keys =
        properties.keySet().stream().filter(key -> key.startsWith(screenshotPrefix)).toList();
    if (keys.isEmpty()) {
      return List.of();
    }
    SortedMap<Integer, URI> indexed = new TreeMap<>();
    for (String key : keys) {
      String indexText = key.substring(screenshotPrefix.length());
      if (!isPositiveDecimal(indexText)) {
        throw AppCatalogSidecars.invalidEntry("invalid screenshot index: " + key);
      }
      int index = parsePositiveIndex(indexText, key);
      URI previous = indexed.putIfAbsent(index, parseUri(properties.remove(key), key));
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry("duplicate screenshot index: " + key);
      }
    }
    List<URI> screenshots = new ArrayList<>(indexed.size());
    int expected = 1;
    for (Map.Entry<Integer, URI> entry : indexed.entrySet()) {
      if (entry.getKey() != expected) {
        throw AppCatalogSidecars.invalidEntry(
            "missing "
                + screenshotPrefix
                + expected
                + " before "
                + screenshotPrefix
                + entry.getKey());
      }
      screenshots.add(entry.getValue());
      expected++;
    }
    return List.copyOf(screenshots);
  }

  private static Map<String, String> parsePermissionRationales(
      Map<String, String> properties, String prefix) {
    String rationalePrefix = prefix + "permissions.rationale.";
    List<String> keys =
        properties.keySet().stream().filter(key -> key.startsWith(rationalePrefix)).toList();
    Map<String, String> rationales = new LinkedHashMap<>();
    for (String key : keys) {
      String rawPermission = key.substring(rationalePrefix.length());
      String permission = AppCatalogEntry.normalizePermission(rawPermission, key);
      String previous = rationales.putIfAbsent(permission, properties.remove(key));
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry("duplicate permission rationale for " + permission);
      }
    }
    return rationales;
  }

  private static boolean isPositiveDecimal(String value) {
    if (value.isEmpty() || value.charAt(0) == '0') {
      return false;
    }
    for (int i = 0; i < value.length(); i++) {
      char digit = value.charAt(i);
      if (digit < '0' || digit > '9') {
        return false;
      }
    }
    return true;
  }

  private static int parsePositiveIndex(String value, String key) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, "invalid screenshot index: " + key, exception);
    }
  }

  private static String removeRequired(Map<String, String> properties, String key)
      throws AppCatalogException {
    String value = properties.remove(key);
    if (value == null) {
      throw AppCatalogSidecars.invalidEntry("missing " + key);
    }
    return value;
  }

  private static Optional<String> removeOptional(Map<String, String> properties, String key) {
    return Optional.ofNullable(properties.remove(key));
  }
}
