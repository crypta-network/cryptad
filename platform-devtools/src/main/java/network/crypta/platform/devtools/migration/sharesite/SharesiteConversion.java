package network.crypta.platform.devtools.migration.sharesite;

import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.regex.Pattern;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.FreenetURI;
import network.crypta.platform.api.appdata.AppDataExportPayload;
import network.crypta.platform.api.appdata.AppDataNamespaceMetadata;
import network.crypta.platform.api.appdata.AppDataRecord;
import network.crypta.platform.api.json.PlatformApiJsonWriter;

/**
 * Projects explicitly selected active pastebin records into private Site Publisher draft data.
 *
 * <p>The format wrapper records Sharesite lineage and never claims to be an installed-app backup.
 * Input and output text are literal UTF-8 without newline or Unicode normalization. Stable draft
 * IDs combine the explicit operation UUID with the original logical ID; map iteration order is
 * ignored.
 *
 * <p>Call {@link #inspect} to review page eligibility, then {@link #convert} with an explicit
 * supported subset. Conversion creates one bounded app-data dataset inside a source-specific
 * provenance wrapper. The wrapper contains private snapshot and literal-text comparison digests;
 * neither the user content nor these bindings belong in public certification reports. The helper is
 * stateless and returns detached bytes. It does not read files, contact a node, grant permissions,
 * import drafts, or schedule publication. Callers retain responsibility for source preservation and
 * owner-only output creation.
 */
public final class SharesiteConversion {
  /**
   * Exact independently inspected upstream source revision.
   *
   * <p>This immutable Git commit identifies the writer semantics recorded by the private wrapper.
   * It is format provenance, not evidence that a real legacy user completed migration.
   */
  public static final String REVISION = "c99ad9c8e83004f904f8ee742ab2861f5751ee3b";

  /**
   * Maximum encoded private wrapper size in bytes accepted by this adapter.
   *
   * <p>The bound includes the outer source lineage and encoded inner app-data representation.
   * Separate limits constrain individual fields and the unencoded draft dataset before this check.
   */
  public static final int MAX_PACKAGE_BYTES = 409600;

  private static final String FIELD_DESCRIPTION = "description";
  private static final String FIELD_REQUEST_SSK = "requestSSK";
  private static final String FIELD_EDITION = "edition";
  private static final String FIELD_INSERT_HOUR = "insertHour";
  private static final String FIELD_OPERATION_ID = "operationId";
  private static final String INVALID_NUMBER = "invalid_number";

  private static final Set<String> ROOT_FIELDS =
      Set.of("keys", "deleted_keys", "increasingCounter", "lastDeletedTime");
  private static final Set<String> PAGE_FIELDS =
      Set.of(
          "name",
          "path",
          FIELD_DESCRIPTION,
          "pastebin",
          "text",
          "css",
          "activelinkUri",
          FIELD_REQUEST_SSK,
          "insertSSK",
          FIELD_EDITION,
          FIELD_INSERT_HOUR,
          "l10nStatus");
  private static final Pattern PAGE = Pattern.compile("collection-(\\d+)/([^/]+)");
  private static final Pattern KEYS = Pattern.compile("(?i)(?:SSK|USK)@[^\\s<>\"']*");
  private static final Pattern SECRET_CREDENTIAL =
      Pattern.compile("(?i)(?:-----BEGIN[^\\r\\n]*PRIVATE KEY|bearer\\s+[a-z0-9._~-]+)");
  private static final Pattern SECRET_MARKER =
      Pattern.compile(
          "(?i)(?:insertssk|private[ _-]?key|(?:inserturi|password|secret|token|seed)\\s*[:=])");
  private static final String APP = "site-publisher";
  private static final String NAMESPACE = "sharesite-drafts";

  private SharesiteConversion() {}

  /**
   * Produces a PRIVATE inspection document containing bounded page metadata and exclusion reasons.
   *
   * <p>The result identifies active supported records and explicit exclusions without creating a
   * selection or import. It can contain user labels and must remain owner-private even when secret
   * markers have been excluded. The private snapshot digest binds the inspection to exact source
   * bytes, including fields omitted from this summary. Invalid root membership or malformed
   * inventory fields fail rather than becoming an empty successful inspection. No source values are
   * modified.
   *
   * @param source immutable decoded private snapshot produced by the strict binary decoder
   * @return UTF-8 private inspection JSON; never print this document into ordinary diagnostics
   */
  public static byte[] inspect(SharesiteSnapshot.Decoded source) {
    Inventory inventory = inventory(source.fields());
    List<Map<String, Object>> pages = new ArrayList<>();
    inventory.pages.forEach(
        (id, fields) -> {
          String reason = reason(fields, inventory.deleted.contains(id));
          pages.add(
              Map.of(
                  "sourceId",
                  id,
                  "name",
                  safeLabel(fields.getOrDefault("name", "")),
                  "status",
                  reason == null ? "supported" : reason));
        });
    return json(
        Map.of(
            "format",
            "crypta.sharesite-inspection.v1",
            "privacy",
            "private-user-data",
            "profile",
            "sharesite-pastebin-v1",
            "snapshotSha256",
            source.snapshotSha256(),
            "pages",
            pages,
            "exclusions",
            exclusions(inventory, Set.of())));
  }

  /**
   * Creates deterministic prospective import bytes for exact local consent.
   *
   * <p>The selection must contain one to sixteen distinct active IDs whose literal fields pass size
   * and prohibited-material checks. Output order follows logical IDs, and fixed epoch metadata
   * keeps repeated conversion deterministic for identical inputs. The wrapper preserves exact
   * private source lineage and text digests, but excludes insertion identity. Failure returns no
   * partially converted package and does not silently rewrite supported text.
   *
   * <p>The size check reserves the ledger entry that Site Publisher adds on import. It ensures the
   * selected dataset fits an empty target; existing target data and current app quota still require
   * a guarded import preview. Conversion itself neither creates that preview nor authorizes commit.
   *
   * @param source immutable decoded snapshot and exact private source comparison digest
   * @param selection explicit original logical IDs, at most sixteen distinct active pages
   * @param operationId explicit local operation UUID used to derive stable draft identities
   * @param provenance private operator description of stopped-writer snapshot preparation
   * @return detached bounded PRIVATE wrapper around the existing app-data interchange
   *     representation
   * @throws IllegalArgumentException with a bounded reason when selection or content is unsupported
   */
  public static byte[] convert(
      SharesiteSnapshot.Decoded source,
      List<Integer> selection,
      UUID operationId,
      String provenance) {
    Inventory inventory = inventory(source.fields());
    Set<Integer> selected = new TreeSet<>(selection);
    require(
        !selected.isEmpty() && selected.size() <= 16 && selected.size() == selection.size(),
        "invalid_selection");
    require(
        provenance != null && !provenance.isBlank() && utf8Length(provenance) <= 4096,
        "provenance_required");
    checkContent(provenance);
    List<Map<String, Object>> drafts = new ArrayList<>();
    Map<String, String> fidelity = new TreeMap<>();
    for (int id : selected) {
      Map<String, String> fields = inventory.pages.get(id);
      if (fields == null || !inventory.active.contains(id)) {
        throw new IllegalArgumentException("sharesite_inactive_selection");
      }
      String reason = reason(fields, false);
      require(reason == null, reason == null ? "invalid_selection" : reason);
      Map<String, Object> draft = new LinkedHashMap<>();
      draft.put("id", operationId + "-" + id);
      draft.put(FIELD_OPERATION_ID, operationId.toString());
      draft.put("sourceId", id);
      draft.put("name", fields.get("name"));
      draft.put(FIELD_DESCRIPTION, fields.get(FIELD_DESCRIPTION));
      draft.put("text", fields.get("text"));
      draft.put("historicalEdition", edition(fields));
      draft.put("logicalPath", fields.getOrDefault("path", fields.get("name")));
      String reference = fields.getOrDefault(FIELD_REQUEST_SSK, "");
      if (!reference.isEmpty()) draft.put("publicReadReference", reference);
      drafts.add(draft);
      fidelity.put(
          Integer.toString(id),
          SharesiteSnapshot.sha256(fields.get("text").getBytes(StandardCharsets.UTF_8)));
    }
    AppDataExportPayload payload = draftPayload(drafts, operationId);
    Map<String, Object> wrapper = new LinkedHashMap<>();
    wrapper.put("format", "crypta.sharesite-migration.v1");
    wrapper.put("privacy", "private-user-data");
    wrapper.put(
        "source",
        Map.of(
            "repository",
            "hyphanet/plugin-sharesite",
            "revision",
            REVISION,
            "profile",
            "sharesite-pastebin-v1",
            "snapshotSha256",
            source.snapshotSha256(),
            "provenance",
            provenance,
            "literalTextSha256",
            fidelity));
    wrapper.put(FIELD_OPERATION_ID, operationId.toString());
    wrapper.put("selectedIds", List.copyOf(selected));
    wrapper.put("exclusions", exclusions(inventory, selected));
    wrapper.put("payload", payload.toJsonValue());
    byte[] result = json(wrapper);
    require(result.length <= MAX_PACKAGE_BYTES, "package_limit");
    return result;
  }

  /**
   * Builds the inner app-data representation after reserving the complete import ledger size.
   *
   * @param drafts validated selected drafts in deterministic logical ID order
   * @param operationId local operation identity used to size the eventual ledger entry
   * @return detached app-data payload with fixed epoch metadata and an empty ledger
   */
  private static AppDataExportPayload draftPayload(
      List<Map<String, Object>> drafts, UUID operationId) {
    byte[] dataset = json(Map.of("schemaVersion", 1, "operations", List.of(), "drafts", drafts));
    // Reserve the complete import ledger size using fixed-width digest placeholders.
    // The exported payload retains an empty ledger until the app commits the import.
    Map<String, Object> importOperation =
        Map.of(
            FIELD_OPERATION_ID,
            operationId.toString(),
            "payloadSha256",
            "0".repeat(64),
            "status",
            "committed",
            "draftIds",
            drafts.stream().map(draft -> draft.get("id")).toList(),
            "originalsSha256",
            "0".repeat(64));
    require((long) dataset.length + json(importOperation).length <= 196608, "dataset_limit");
    Instant at = Instant.EPOCH;
    AppDataRecord datasetRecord =
        new AppDataRecord(
            APP,
            NAMESPACE,
            "dataset",
            new AppDataRecord.Payload("application/json", 1, dataset),
            at,
            at);
    AppDataNamespaceMetadata namespace =
        new AppDataNamespaceMetadata(APP, NAMESPACE, 1, 1, dataset.length, at, at, null, List.of());
    return new AppDataExportPayload(1, APP, at, List.of(namespace), List.of(datasetRecord));
  }

  private static Inventory inventory(Map<String, String> fields) {
    if (fields.isEmpty()) return new Inventory(Set.of(), Set.of(), new TreeMap<>());
    require(fields.keySet().containsAll(ROOT_FIELDS), "missing_root_fields");
    Set<Integer> active = ids(fields.get("keys"));
    Set<Integer> deleted = ids(fields.get("deleted_keys"));
    require(java.util.Collections.disjoint(active, deleted), "ambiguous_membership");
    boundedLong(fields.get("increasingCounter"), 0, Integer.MAX_VALUE);
    boundedLong(fields.get("lastDeletedTime"), 0, Long.MAX_VALUE);
    Map<Integer, Map<String, String>> pages = new TreeMap<>();
    fields.forEach(
        (key, value) -> {
          if (ROOT_FIELDS.contains(key)) return;
          var matcher = PAGE.matcher(key);
          require(matcher.matches(), "unknown_root_field");
          int id = id(matcher.group(1));
          require(active.contains(id) || deleted.contains(id), "orphan_fields");
          pages.computeIfAbsent(id, _ -> new TreeMap<>()).put(matcher.group(2), value);
        });
    require(
        pages.keySet().containsAll(active) && pages.keySet().containsAll(deleted),
        "missing_page_fields");
    return new Inventory(active, deleted, pages);
  }

  private static String reason(Map<String, String> fields, boolean deleted) {
    if (deleted) return "recently_deleted";
    if (!PAGE_FIELDS.containsAll(fields.keySet())) return "unknown_page_field";
    String pastebin = fields.get("pastebin");
    if (pastebin != null && !Set.of("true", "false").contains(pastebin)) return "malformed_boolean";
    if (!"true".equals(pastebin)) return "unsupported_textile";
    if (!fields.keySet().containsAll(Set.of("name", FIELD_DESCRIPTION, "text", FIELD_EDITION)))
      return "broken_record";
    if (utf8Length(fields.get("text")) > 65536) return "text_limit";
    if (utf8Length(fields.get("name")) > 1024
        || utf8Length(fields.get(FIELD_DESCRIPTION)) > 8192
        || utf8Length(fields.getOrDefault("path", "")) > 1024) return "metadata_limit";
    try {
      edition(fields);
      for (String field : List.of("name", FIELD_DESCRIPTION, "text", "path"))
        checkContent(fields.getOrDefault(field, ""));
      String reference = fields.getOrDefault(FIELD_REQUEST_SSK, "");
      if (!reference.isEmpty()) requirePublicReference(reference);
      if (fields.containsKey(FIELD_INSERT_HOUR)) boundedLong(fields.get(FIELD_INSERT_HOUR), -1, 23);
    } catch (IllegalArgumentException exception) {
      return recordFailureReason(exception);
    }
    return null;
  }

  /**
   * Converts bounded adapter exceptions to exclusion codes without exposing rejected content.
   *
   * @param exception validation failure whose message may contain an adapter reason
   * @return recognized reason suffix or the fixed fallback for other failures
   */
  private static String recordFailureReason(IllegalArgumentException exception) {
    String code = exception.getMessage();
    return code != null && code.matches("sharesite_[a-z_]+")
        ? code.substring("sharesite_".length())
        : "invalid_record";
  }

  private static long edition(Map<String, String> fields) {
    return boundedLong(fields.get(FIELD_EDITION), -1, 9007199254740991L);
  }

  private static Map<String, Integer> exclusions(Inventory inventory, Set<Integer> selected) {
    Map<String, Integer> counts = new TreeMap<>();
    inventory.pages.forEach(
        (id, fields) -> {
          String reason = reason(fields, inventory.deleted.contains(id));
          if (reason != null) counts.merge(reason, 1, Integer::sum);
          else if (!selected.contains(id)) counts.merge("not_selected", 1, Integer::sum);
          if (fields.containsKey("insertSSK"))
            counts.merge("private_insert_identity_not_imported", 1, Integer::sum);
          if (!fields.getOrDefault("css", "").isEmpty())
            counts.merge("css_not_imported", 1, Integer::sum);
          if (!fields.getOrDefault("activelinkUri", "").isEmpty())
            counts.merge("external_resource_not_imported", 1, Integer::sum);
          if (fields.containsKey(FIELD_INSERT_HOUR))
            counts.merge("scheduling_not_imported", 1, Integer::sum);
          if (fields.containsKey("l10nStatus"))
            counts.merge("runtime_status_not_imported", 1, Integer::sum);
        });
    return counts;
  }

  private static Set<Integer> ids(String value) {
    Set<Integer> result = new TreeSet<>();
    if (value.isEmpty()) return result;
    require(value.matches("(?:0|[1-9]\\d*+)(?: (?:0|[1-9]\\d*+))*+"), "invalid_id_list");
    String[] tokens = value.split(" ", -1);
    require(tokens.length <= 512, "page_count_limit");
    for (String token : tokens) require(result.add(id(token)), "duplicate_page_id");
    return result;
  }

  private static int id(String value) {
    require(value.matches("0|[1-9]\\d*"), "invalid_page_id");
    return (int) boundedLong(value, 0, Integer.MAX_VALUE);
  }

  private static long boundedLong(String value, long minimum, long maximum) {
    try {
      require(value != null && value.matches("-?(?:0|[1-9]\\d*)"), INVALID_NUMBER);
      long number = Long.parseLong(value);
      require(number >= minimum && number <= maximum, INVALID_NUMBER);
      return number;
    } catch (NumberFormatException _) {
      throw invalid(INVALID_NUMBER);
    }
  }

  private static void checkContent(String value) {
    require(
        !SECRET_CREDENTIAL.matcher(value).find() && !SECRET_MARKER.matcher(value).find(),
        "prohibited_secret_material");
    var matcher = KEYS.matcher(value);
    while (matcher.find()) requirePublicReference(matcher.group());
  }

  private static void requirePublicReference(String value) {
    try {
      require(utf8Length(value) <= 2048, "invalid_public_reference");
      FreenetURI uri = new FreenetURI(value);
      require(uri.isSSK() || uri.isUSK(), "invalid_public_reference");
      new ClientSSK(uri.isUSK() ? uri.sskForUSK() : uri);
    } catch (MalformedURLException | RuntimeException _) {
      throw invalid("prohibited_or_invalid_key");
    }
  }

  private static String safeLabel(String value) {
    try {
      checkContent(value);
      return utf8Length(value) <= 1024 ? value : "";
    } catch (IllegalArgumentException _) {
      return "";
    }
  }

  private static int utf8Length(String value) {
    return value.getBytes(StandardCharsets.UTF_8).length;
  }

  private static byte[] json(Object value) {
    return PlatformApiJsonWriter.write(canonical(value)).getBytes(StandardCharsets.UTF_8);
  }

  private static Object canonical(Object value) {
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> sorted = new TreeMap<>();
      map.forEach((key, item) -> sorted.put((String) key, canonical(item)));
      return sorted;
    }
    if (value instanceof List<?> list)
      return list.stream().map(SharesiteConversion::canonical).toList();
    return value;
  }

  private static void require(boolean condition, String code) {
    if (!condition) throw invalid(code);
  }

  private static IllegalArgumentException invalid(String code) {
    return new IllegalArgumentException("sharesite_" + code);
  }

  private record Inventory(
      Set<Integer> active, Set<Integer> deleted, Map<Integer, Map<String, String>> pages) {}
}
