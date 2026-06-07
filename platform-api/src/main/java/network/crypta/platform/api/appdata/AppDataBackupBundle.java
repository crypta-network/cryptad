package network.crypta.platform.api.appdata;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import org.jetbrains.annotations.NotNull;

/**
 * Deterministic portable backup bundle for durable app-owned data.
 *
 * <p>An {@code AppDataBackupBundle} is the top-level object returned by the operator backup
 * endpoint and consumed by restore planning. It wraps one or more single-app export payloads in a
 * manifest that describes the backup version, scope, creation time, source daemon version, and
 * encryption mode. The bundle is a user/operator artifact, not a diagnostic artifact. Nested app
 * entries may contain raw app-owned record values under their {@code export} object, so callers
 * must keep serialized bundles out of support bundles, audit logs, release evidence, ordinary Web
 * Shell panels, and exception text.
 *
 * <p>The constructor and parser enforce the invariants needed for safe restore preflight: app
 * entries are sorted by normalized app id, duplicate app ids are rejected, {@code single-app} scope
 * must contain exactly one entry, and unsupported manifest versions or encryption modes fail before
 * the service considers any write. The record is immutable after construction except for object
 * graphs held inside JSON-compatible metadata maps.
 *
 * @param manifest top-level backup manifest metadata that defines scope and envelope support
 * @param apps app entries sorted by app id after validation
 * @see AppDataBackupEntry
 * @see AppDataRestorePlan
 */
public record AppDataBackupBundle(AppDataBackupManifest manifest, List<AppDataBackupEntry> apps) {
  /**
   * Creates a validated backup bundle.
   *
   * <p>The canonical constructor normalizes bundle ordering but does not rewrite app ids inside
   * entries. Each entry is already responsible for proving that its metadata matches the nested
   * app-data export payload. This constructor performs the cross-entry checks that are only visible
   * at bundle scope: no duplicate app id may appear, and a single-app manifest must contain exactly
   * one entry. These checks prevent restore planning from treating duplicate entries as independent
   * quota projections and then committing a partial restore.
   *
   * @throws NullPointerException if the manifest or app list is {@code null}
   * @throws PlatformApiException when the scope does not match the entry set or duplicate app ids
   *     are present
   */
  public AppDataBackupBundle {
    Objects.requireNonNull(manifest, "manifest");
    apps =
        List.copyOf(
            Objects.requireNonNull(apps, "apps").stream()
                .sorted(java.util.Comparator.comparing(AppDataBackupEntry::appId))
                .toList());
    requireUniqueAppIds(apps);
    if (AppDataBackupOptions.SCOPE_SINGLE_APP.equals(manifest.scope()) && apps.size() != 1) {
      throw AppDataBackupManifest.invalidBackupPayload();
    }
  }

  /**
   * Converts this bundle to a deterministic JSON-compatible map.
   *
   * <p>The returned map preserves the manifest's stable field order and appends an {@code apps}
   * list whose entries are already sorted. It is suitable for {@link PlatformApiJsonWriter} and for
   * digest or fixture generation that needs reproducible output. The map may include raw backup
   * values through nested exports, so it should be serialized only for an explicit backup response
   * or restore request.
   *
   * @return backup envelope with manifest fields followed by sorted app entries
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = new LinkedHashMap<>(manifest.toJsonValue());
    json.put("apps", apps.stream().map(AppDataBackupEntry::toJsonValue).toList());
    return json;
  }

  /**
   * Serializes this bundle to deterministic UTF-8 JSON bytes.
   *
   * <p>Callers use these bytes before route-level URL-safe base64 encoding, digest calculation, or
   * operator download handling. The method does not redact nested record values because a backup
   * must preserve user data; metadata-only restore plan and result types provide the redacted view
   * for dashboards and evidence.
   *
   * @return serialized backup bundle containing the full portable app-data payload
   */
  public byte[] toJsonBytes() {
    return PlatformApiJsonWriter.write(toJsonValue()).getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Parses a portable app-data backup bundle.
   *
   * <p>The parser accepts only the current JSON envelope shape and reuses the nested {@link
   * AppDataExportPayload} parser for each app export. Syntax errors, missing required fields,
   * metadata mismatches, duplicate app ids, and unsupported nested payload shapes collapse to
   * stable backup-specific errors. Unsupported backup versions and encryption modes keep their
   * dedicated error codes so operator routes can report the difference between a malformed backup
   * and a future-but-valid format.
   *
   * @param bytes UTF-8 backup JSON bytes after route-level base64 decoding
   * @return validated backup bundle ready for restore planning
   * @throws PlatformApiException when the bundle is malformed or unsupported
   */
  public static AppDataBackupBundle parse(byte[] bytes) {
    Object parsed;
    try {
      parsed = AppDataJsonParser.parse(new String(bytes, StandardCharsets.UTF_8));
    } catch (PlatformApiException _) {
      throw AppDataBackupManifest.invalidBackupPayload();
    }
    Map<?, ?> map = asMap(parsed);
    AppDataBackupManifest manifest =
        new AppDataBackupManifest(
            positiveInt(number(map.get("backupVersion"))),
            string(map.get("kind")),
            string(map.get("scope")),
            instant(string(map.get("createdAt"))),
            stringOrUnknownSourceVersion(map.get("sourceCryptaVersion")),
            objectMap(map.get("encryption")),
            booleanValue(map.get("sensitiveUserData"), true));
    List<AppDataBackupEntry> entries = entries(list(map.get("apps")));
    return new AppDataBackupBundle(manifest, entries);
  }

  @Override
  public @NotNull String toString() {
    return "AppDataBackupBundle[backupVersion="
        + manifest.backupVersion()
        + ", kind="
        + manifest.kind()
        + ", scope="
        + manifest.scope()
        + ", createdAt="
        + manifest.createdAt()
        + ", appCount="
        + apps.size()
        + ", recordCount="
        + apps.stream().mapToInt(AppDataBackupEntry::recordCount).sum()
        + ", totalBytes="
        + apps.stream().mapToLong(AppDataBackupEntry::totalBytes).sum()
        + "]";
  }

  private static List<AppDataBackupEntry> entries(List<?> rawEntries) {
    ArrayList<AppDataBackupEntry> entries = new ArrayList<>();
    for (Object item : rawEntries) {
      entries.add(entry(asMap(item)));
    }
    return entries;
  }

  private static void requireUniqueAppIds(List<AppDataBackupEntry> entries) {
    Set<String> seen = new HashSet<>();
    for (AppDataBackupEntry entry : entries) {
      if (!seen.add(entry.appId())) {
        throw AppDataBackupManifest.invalidBackupPayload();
      }
    }
  }

  private static AppDataBackupEntry entry(Map<?, ?> map) {
    Map<String, Object> exportMap = objectMap(map.get("export"));
    AppDataExportPayload exportPayload;
    try {
      exportPayload =
          AppDataExportPayload.parse(
              PlatformApiJsonWriter.write(exportMap).getBytes(StandardCharsets.UTF_8));
    } catch (PlatformApiException _) {
      throw AppDataBackupManifest.invalidBackupPayload();
    }
    return new AppDataBackupEntry(
        string(map.get("appId")),
        booleanValue(map.get("installed"), false),
        stringOrNull(map.get("appName")),
        stringOrNull(map.get("appVersion")),
        objectMap(map.get("schemaSummary")),
        nonNegativeInt(number(map.get("namespaceCount"))),
        nonNegativeInt(number(map.get("recordCount"))),
        nonNegativeLong(number(map.get("totalBytes"))),
        string(map.get("payloadSha256")),
        exportPayload);
  }

  private static Map<?, ?> asMap(Object item) {
    if (item instanceof Map<?, ?> map) {
      return map;
    }
    throw AppDataBackupManifest.invalidBackupPayload();
  }

  private static Map<String, Object> objectMap(Object item) {
    Map<?, ?> map = asMap(item);
    LinkedHashMap<String, Object> copy = LinkedHashMap.newLinkedHashMap(map.size());
    for (Map.Entry<?, ?> entry : map.entrySet()) {
      if (!(entry.getKey() instanceof String key)) {
        throw AppDataBackupManifest.invalidBackupPayload();
      }
      copy.put(key, entry.getValue());
    }
    return java.util.Collections.unmodifiableMap(copy);
  }

  private static List<?> list(Object item) {
    if (item instanceof List<?> list) {
      return list;
    }
    throw AppDataBackupManifest.invalidBackupPayload();
  }

  private static Number number(Object item) {
    if (item instanceof Number number) {
      return number;
    }
    throw AppDataBackupManifest.invalidBackupPayload();
  }

  private static int positiveInt(Number number) {
    long value = number.longValue();
    if (value <= 0L || value > Integer.MAX_VALUE) {
      throw AppDataBackupManifest.invalidBackupPayload();
    }
    return (int) value;
  }

  private static int nonNegativeInt(Number number) {
    long value = number.longValue();
    if (value < 0L || value > Integer.MAX_VALUE) {
      throw AppDataBackupManifest.invalidBackupPayload();
    }
    return (int) value;
  }

  private static long nonNegativeLong(Number number) {
    long value = number.longValue();
    if (value < 0L) {
      throw AppDataBackupManifest.invalidBackupPayload();
    }
    return value;
  }

  private static String string(Object item) {
    if (item instanceof String value && !value.isBlank()) {
      return value;
    }
    throw AppDataBackupManifest.invalidBackupPayload();
  }

  private static String stringOrNull(Object item) {
    if (item == null) {
      return null;
    }
    if (item instanceof String value && !value.isBlank()) {
      return value;
    }
    throw AppDataBackupManifest.invalidBackupPayload();
  }

  private static String stringOrUnknownSourceVersion(Object item) {
    if (item == null) {
      return "unknown";
    }
    return string(item);
  }

  private static boolean booleanValue(Object item, boolean defaultValue) {
    if (item == null) {
      return defaultValue;
    }
    if (item instanceof Boolean value) {
      return value;
    }
    throw AppDataBackupManifest.invalidBackupPayload();
  }

  private static Instant instant(String value) {
    try {
      return Instant.parse(value);
    } catch (RuntimeException _) {
      throw AppDataBackupManifest.invalidBackupPayload();
    }
  }
}
