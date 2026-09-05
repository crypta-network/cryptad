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

  private static final Set<String> ROOT_FIELDS =
      Set.of("keys", "deleted_keys", "increasingCounter", "lastDeletedTime");
  private static final Set<String> PAGE_FIELDS =
      Set.of(
          "name",
          "path",
          "description",
          "pastebin",
          "text",
          "css",
          "activelinkUri",
          "requestSSK",
          "insertSSK",
          "edition",
          "insertHour",
          "l10nStatus");
  private static final Pattern PAGE = Pattern.compile("collection-([0-9]+)/([^/]+)");
  private static final Pattern KEYS = Pattern.compile("(?i)(?:SSK|USK)@[^\\s<>\"']*");
  private static final Pattern SECRET =
      Pattern.compile(
          "(?i)(?:-----BEGIN[^\\r"
              + "\\n"
              + "]*PRIVATE KEY|bearer\\s+[a-z0-9._~-]+|insertssk|private["
              + " _-]?key|(?:inserturi|password|secret|token|seed)\\s*[:=])");
  private static final String APP = "site-publisher";
  private static final String NAMESPACE = "sharesite-drafts";

  private SharesiteConversion() {}

  /**
   * Produces a PRIVATE inspection document containing bounded page metadata and exclusion reasons.
   *
   * <p>The result identifies active supported records and explicit exclusions without creating a
   * selection or import. It can contain user labels and must remain owner-private even when secret
   * markers have been excluded. Invalid root membership or malformed inventory fields fail rather
   * than becoming an empty successful inspection. No source values are modified.
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
   * @param source immutable decoded snapshot and exact private source comparison digest
   * @param selection explicit original logical IDs, at most sixteen
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
      draft.put("operationId", operationId.toString());
      draft.put("sourceId", id);
      draft.put("name", fields.get("name"));
      draft.put("description", fields.get("description"));
      draft.put("text", fields.get("text"));
      draft.put("historicalEdition", edition(fields));
      draft.put("logicalPath", fields.getOrDefault("path", fields.get("name")));
      String reference = fields.getOrDefault("requestSSK", "");
      if (!reference.isEmpty()) draft.put("publicReadReference", reference);
      drafts.add(draft);
      fidelity.put(
          Integer.toString(id),
          SharesiteSnapshot.sha256(fields.get("text").getBytes(StandardCharsets.UTF_8)));
    }
    byte[] dataset = json(Map.of("schemaVersion", 1, "operations", List.of(), "drafts", drafts));
    require(dataset.length <= 196608, "dataset_limit");
    Instant at = Instant.EPOCH;
    AppDataRecord record =
        new AppDataRecord(
            APP,
            NAMESPACE,
            "dataset",
            new AppDataRecord.Payload("application/json", 1, dataset),
            at,
            at);
    AppDataNamespaceMetadata namespace =
        new AppDataNamespaceMetadata(APP, NAMESPACE, 1, 1, dataset.length, at, at, null, List.of());
    AppDataExportPayload payload =
        new AppDataExportPayload(1, APP, at, List.of(namespace), List.of(record));
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
    wrapper.put("operationId", operationId.toString());
    wrapper.put("selectedIds", List.copyOf(selected));
    wrapper.put("exclusions", exclusions(inventory, selected));
    wrapper.put("payload", payload.toJsonValue());
    byte[] result = json(wrapper);
    require(result.length <= MAX_PACKAGE_BYTES, "package_limit");
    return result;
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
    if (!fields.keySet().containsAll(Set.of("name", "description", "text", "edition")))
      return "broken_record";
    if (utf8Length(fields.get("text")) > 65536) return "text_limit";
    if (utf8Length(fields.get("name")) > 1024
        || utf8Length(fields.get("description")) > 8192
        || utf8Length(fields.getOrDefault("path", "")) > 1024) return "metadata_limit";
    try {
      edition(fields);
      for (String field : List.of("name", "description", "text", "path"))
        checkContent(fields.getOrDefault(field, ""));
      String reference = fields.getOrDefault("requestSSK", "");
      if (!reference.isEmpty()) requirePublicReference(reference);
      if (fields.containsKey("insertHour")) boundedLong(fields.get("insertHour"), -1, 23);
    } catch (IllegalArgumentException exception) {
      String code = exception.getMessage();
      return code != null && code.matches("sharesite_[a-z_]+")
          ? code.substring("sharesite_".length())
          : "invalid_record";
    }
    return null;
  }

  private static long edition(Map<String, String> fields) {
    return boundedLong(fields.get("edition"), -1, 9007199254740991L);
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
          if (fields.containsKey("insertHour"))
            counts.merge("scheduling_not_imported", 1, Integer::sum);
          if (fields.containsKey("l10nStatus"))
            counts.merge("runtime_status_not_imported", 1, Integer::sum);
        });
    return counts;
  }

  private static Set<Integer> ids(String value) {
    Set<Integer> result = new TreeSet<>();
    if (value.isEmpty()) return result;
    require(value.matches("(?:0|[1-9][0-9]*)(?: (?:0|[1-9][0-9]*))*"), "invalid_id_list");
    String[] tokens = value.split(" ", -1);
    require(tokens.length <= 512, "page_count_limit");
    for (String token : tokens) require(result.add(id(token)), "duplicate_page_id");
    return result;
  }

  private static int id(String value) {
    require(value.matches("0|[1-9][0-9]*"), "invalid_page_id");
    return (int) boundedLong(value, 0, Integer.MAX_VALUE);
  }

  private static long boundedLong(String value, long minimum, long maximum) {
    try {
      require(value != null && value.matches("-?(?:0|[1-9][0-9]*)"), "invalid_number");
      long number = Long.parseLong(value);
      require(number >= minimum && number <= maximum, "invalid_number");
      return number;
    } catch (NumberFormatException _) {
      throw invalid("invalid_number");
    }
  }

  private static void checkContent(String value) {
    require(!SECRET.matcher(value).find(), "prohibited_secret_material");
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
