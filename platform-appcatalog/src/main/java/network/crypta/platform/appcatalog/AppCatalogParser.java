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
  private static final String CHANNEL_PROPERTY = "channel";
  private static final String MINIMUM_CRYPTA_VERSION = "minimumCryptaVersion";
  private static final String MAXIMUM_CRYPTA_VERSION = "maximumCryptaVersion";
  private static final String SUPPORT_STATUS = "support.status";
  private static final String DEPRECATION_STATUS = "deprecation.status";
  private static final String DEPRECATION_MESSAGE = "deprecation.message";
  private static final String REPLACEMENT_APP_ID = "replacementAppId";
  private static final String SECURITY_ADVISORIES = "securityAdvisories";
  private static final String SECURITY_ADVISORY_PREFIX = "securityAdvisory.";
  private static final String SECURITY_ADVISORY_URI_SUFFIX = ".uri";

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
    Instant generatedAt =
        parseInstant(removeRequired(properties, "catalog.generatedAt"), "catalog.generatedAt");
    List<String> entryIds = parseEntryIds(removeRequired(properties, "catalog.entries"));
    AppCatalogSecurityPolicy securityPolicy = parseCatalogSecurityPolicy(properties, version);
    List<AppCatalogEntry> entries = new ArrayList<>(entryIds.size());
    for (String appId : entryIds) {
      entries.add(parseEntry(properties, appId, version));
    }
    if (!properties.isEmpty()) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported catalog property: " + properties.keySet().iterator().next());
    }
    return new AppCatalog(version, catalogId, catalogName, generatedAt, securityPolicy, entries);
  }

  private static int parseVersion(String versionText) throws AppCatalogException {
    try {
      int version = Integer.parseInt(versionText);
      if (AppCatalog.isUnsupportedVersion(version)) {
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

  private static Instant parseInstant(String text, String fieldName) throws AppCatalogException {
    try {
      return Instant.parse(text);
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid " + fieldName + ": " + text,
          exception);
    }
  }

  private static AppCatalogSecurityPolicy parseCatalogSecurityPolicy(
      Map<String, String> properties, int version) {
    if (version < AppCatalog.VERSION_SECURITY_POLICY) {
      return AppCatalogSecurityPolicy.EMPTY;
    }
    List<AppCatalogSecurityAdvisoryRecord> advisories =
        parseCatalogSecurityAdvisoryRecords(properties);
    List<AppCatalogVersionDenylistEntry> denylist = parseCatalogSecurityDenylist(properties);
    return new AppCatalogSecurityPolicy(advisories, denylist);
  }

  private static List<AppCatalogSecurityAdvisoryRecord> parseCatalogSecurityAdvisoryRecords(
      Map<String, String> properties) {
    List<String> advisoryIds = parseSecurityPolicyIds(properties, "catalog.securityAdvisories");
    if (advisoryIds.isEmpty()) {
      return List.of();
    }
    ArrayList<AppCatalogSecurityAdvisoryRecord> advisories = new ArrayList<>(advisoryIds.size());
    for (String advisoryId : advisoryIds) {
      String prefix = "catalog.securityAdvisory." + advisoryId + ".";
      advisories.add(
          new AppCatalogSecurityAdvisoryRecord(
              advisoryId,
              parseUri(removeRequired(properties, prefix + "uri"), prefix + "uri"),
              removeRequired(properties, prefix + "title"),
              AppCatalogSecuritySeverity.parseCatalog(
                  removeRequired(properties, prefix + "severity"), prefix + "severity"),
              AppCatalogSecurityStatus.parse(
                  removeRequired(properties, prefix + "status"), prefix + "status"),
              AppCatalogSecurityAction.parse(
                  removeRequired(properties, prefix + "action"), prefix + "action"),
              removeRequired(properties, prefix + "summary"),
              parseInstant(
                  removeRequired(properties, prefix + "publishedAt"), prefix + "publishedAt"),
              parseInstant(removeRequired(properties, prefix + "updatedAt"), prefix + "updatedAt"),
              removeOptional(properties, prefix + REPLACEMENT_APP_ID),
              removeOptional(properties, prefix + "safeUninstallGuidance")));
    }
    return List.copyOf(advisories);
  }

  private static List<AppCatalogVersionDenylistEntry> parseCatalogSecurityDenylist(
      Map<String, String> properties) {
    List<String> denylistIds = parseSecurityPolicyIds(properties, "catalog.securityDenylist");
    if (denylistIds.isEmpty()) {
      return List.of();
    }
    ArrayList<AppCatalogVersionDenylistEntry> denylist = new ArrayList<>(denylistIds.size());
    for (String denylistId : denylistIds) {
      String prefix = "catalog.securityDenylist." + denylistId + ".";
      denylist.add(
          new AppCatalogVersionDenylistEntry(
              denylistId,
              removeRequired(properties, prefix + "appId"),
              removeRequired(properties, prefix + "version"),
              removeRequired(properties, prefix + "advisoryId"),
              removeRequired(properties, prefix + "reason"),
              removeOptional(properties, prefix + REPLACEMENT_APP_ID),
              removeOptional(properties, prefix + "safeUninstallGuidance")));
    }
    return List.copyOf(denylist);
  }

  private static List<String> parseSecurityPolicyIds(Map<String, String> properties, String key) {
    Optional<String> rawIds = removeOptional(properties, key);
    if (rawIds.isEmpty() || rawIds.orElseThrow().isBlank()) {
      return List.of();
    }
    LinkedHashSet<String> ids = new LinkedHashSet<>();
    for (String rawId : rawIds.orElseThrow().split(",", -1)) {
      String id = AppCatalogSecurityAdvisory.normalizeId(rawId.trim(), key);
      if (!ids.add(id)) {
        throw AppCatalogSidecars.invalidEntry("duplicate " + key + " id: " + id);
      }
    }
    return List.copyOf(ids);
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
    boolean storeMetadataAllowed = version >= AppCatalog.VERSION_STORE_METADATA;
    boolean productionMetadataAllowed = version >= AppCatalog.VERSION_PRODUCTION_CHANNELS;
    String maximumCryptaVersion =
        productionMetadataAllowed
            ? removeOptional(properties, prefix + MAXIMUM_CRYPTA_VERSION).orElse(null)
            : null;
    return new AppCatalogEntry(
        declaredId,
        removeRequired(properties, prefix + "name"),
        removeRequired(properties, prefix + "version"),
        removeRequired(properties, prefix + "summary"),
        parseStoreMetadataUri(properties, prefix + "homepage", storeMetadataAllowed).orElse(null),
        parseStoreMetadataUri(properties, prefix + "source", storeMetadataAllowed).orElse(null),
        storeMetadataAllowed ? removeOptional(properties, prefix + "license").orElse(null) : null,
        storeMetadataAllowed
            ? parseCategories(removeOptional(properties, prefix + "categories").orElse(null))
            : List.of(),
        storeMetadataAllowed
            ? new AppCatalogCompatibilityMetadata(
                removeOptional(properties, prefix + MINIMUM_CRYPTA_VERSION).orElse(null),
                maximumCryptaVersion,
                parseApiCompatibility(properties, prefix))
            : AppCatalogCompatibilityMetadata.EMPTY,
        storeMetadataAllowed ? parseReview(properties, prefix) : AppCatalogReviewMetadata.EMPTY,
        storeMetadataAllowed ? parseReviewReceipt(properties, prefix).orElse(null) : null,
        storeMetadataAllowed ? parseChangelog(properties, prefix) : AppCatalogChangelog.EMPTY,
        storeMetadataAllowed ? parseScreenshots(properties, prefix) : List.of(),
        productionMetadataAllowed
            ? parseProductionMetadata(properties, prefix)
            : AppCatalogProductionMetadata.DEFAULT,
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

  private static AppCatalogProductionMetadata parseProductionMetadata(
      Map<String, String> properties, String prefix) {
    Optional<String> channelText = removeOptional(properties, prefix + CHANNEL_PROPERTY);
    Optional<String> supportStatusText = removeOptional(properties, prefix + SUPPORT_STATUS);
    Optional<String> deprecationStatusText =
        removeOptional(properties, prefix + DEPRECATION_STATUS);
    Optional<String> deprecationMessage = removeOptional(properties, prefix + DEPRECATION_MESSAGE);
    Optional<String> replacementAppId = removeOptional(properties, prefix + REPLACEMENT_APP_ID);
    List<AppCatalogSecurityAdvisory> advisories = parseSecurityAdvisories(properties, prefix);
    boolean declared =
        channelText.isPresent()
            || supportStatusText.isPresent()
            || deprecationStatusText.isPresent()
            || deprecationMessage.isPresent()
            || replacementAppId.isPresent()
            || !advisories.isEmpty();
    return new AppCatalogProductionMetadata(
        channelText
            .map(value -> AppCatalogChannel.parse(value, prefix + CHANNEL_PROPERTY))
            .orElse(null),
        supportStatusText
            .map(value -> AppCatalogSupportStatus.parse(value, prefix + SUPPORT_STATUS))
            .orElse(null),
        deprecationStatusText
            .map(value -> AppCatalogDeprecationStatus.parse(value, prefix + DEPRECATION_STATUS))
            .orElse(null),
        deprecationMessage,
        replacementAppId,
        advisories,
        declared);
  }

  private static List<AppCatalogSecurityAdvisory> parseSecurityAdvisories(
      Map<String, String> properties, String prefix) {
    Optional<String> rawIds = removeOptional(properties, prefix + SECURITY_ADVISORIES);
    if (rawIds.isEmpty() || rawIds.orElseThrow().isBlank()) {
      return List.of();
    }
    List<AppCatalogSecurityAdvisory> advisories = new ArrayList<>();
    for (String rawId : rawIds.orElseThrow().split(",", -1)) {
      String advisoryId =
          AppCatalogSecurityAdvisory.normalizeId(rawId.trim(), prefix + SECURITY_ADVISORIES);
      String uriKey = prefix + SECURITY_ADVISORY_PREFIX + advisoryId + SECURITY_ADVISORY_URI_SUFFIX;
      advisories.add(
          new AppCatalogSecurityAdvisory(
              advisoryId, parseUri(removeRequired(properties, uriKey), uriKey)));
    }
    return List.copyOf(advisories);
  }

  private static Optional<AppReviewReceipt> parseReviewReceipt(
      Map<String, String> properties, String prefix) {
    String receiptPrefix = prefix + "review.receipt.";
    boolean present = properties.keySet().stream().anyMatch(key -> key.startsWith(receiptPrefix));
    if (!present) {
      return Optional.empty();
    }
    return Optional.of(AppReviewReceiptIO.parseProperties(properties, prefix));
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
