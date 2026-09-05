package network.crypta.platform.api.appdata;

import java.net.MalformedURLException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.FreenetURI;

/**
 * Closed literal draft schema and operation-scoped transition checks.
 *
 * <p>Values are private owning-app data. This validator never formats a value in a diagnostic and
 * never treats a logical path or reference as filesystem or network authority. Import preserves
 * existing records, editing preserves lineage, and undo refuses changed imported text. The caller
 * separately binds the entire dataset generation, quota, installed bundle, and consent lifetime.
 *
 * <p>Each validation parses bounded UTF-8 JSON into operation and draft indexes, then compares the
 * complete old and proposed datasets. It has no persistent state and performs no writes. A
 * successful return authorizes only the requested transition shape; the service must still enforce
 * its signed target, quota, consent, and atomic store publication checks. Error messages contain
 * bounded codes rather than rejected values. The helper can be called concurrently with detached
 * record inputs.
 */
final class SharesiteDraftDataset {
  /** Canonical UUID field shared by a ledger entry and its drafts. */
  private static final String FIELD_OPERATION_ID = "operationId";

  /** Ledger state field distinguishing committed imports from local undo tombstones. */
  private static final String FIELD_STATUS = "status";

  /** Ordered draft identities covered by an operation and its undo digest. */
  private static final String FIELD_DRAFT_IDS = "draftIds";

  /** Private canonical digest of the original imported draft set. */
  private static final String FIELD_ORIGINALS_SHA256 = "originalsSha256";

  /** Original nonnegative Sharesite logical page identifier. */
  private static final String FIELD_SOURCE_ID = "sourceId";

  /** Editable literal description retained as private app data. */
  private static final String FIELD_DESCRIPTION = "description";

  /** Bounded historical edition metadata without legacy write authority. */
  private static final String FIELD_HISTORICAL_EDITION = "historicalEdition";

  /** Literal historical path metadata that never grants filesystem authority. */
  private static final String FIELD_LOGICAL_PATH = "logicalPath";

  /** Optional typed public read reference retained only as private metadata. */
  private static final String FIELD_PUBLIC_READ_REFERENCE = "publicReadReference";

  /** Ledger state requiring every referenced draft to remain present. */
  private static final String STATUS_COMMITTED = "committed";

  /** Required fields of the version-one dataset envelope. */
  private static final Set<String> ROOT_FIELDS = Set.of("schemaVersion", "operations", "drafts");

  /** Exact persisted import-ledger fields, including private replay and undo bindings. */
  private static final Set<String> OP_FIELDS =
      Set.of(
          FIELD_OPERATION_ID,
          "payloadSha256",
          FIELD_STATUS,
          FIELD_DRAFT_IDS,
          FIELD_ORIGINALS_SHA256);

  /** Allowed literal draft fields; only the historical public read reference is optional. */
  private static final Set<String> DRAFT_FIELDS =
      Set.of(
          "id",
          FIELD_OPERATION_ID,
          FIELD_SOURCE_ID,
          "name",
          FIELD_DESCRIPTION,
          "text",
          FIELD_HISTORICAL_EDITION,
          FIELD_LOGICAL_PATH,
          FIELD_PUBLIC_READ_REFERENCE);

  /** Markers that block credential-bearing text before it enters a draft dataset. */
  private static final Pattern SECRET_CREDENTIAL =
      Pattern.compile("(?i)(-----BEGIN [^-]*(?:PRIVATE|SECRET)|bearer\\s+[a-z0-9._~-]+)");

  /** Assignment-style markers for secret or insertion-capability fields. */
  private static final Pattern SECRET_ASSIGNMENT =
      Pattern.compile(
          "(?i)(?:private[ _-]?key|insertssk|token|password|secret|seed|inserturi)\\s*[:=]");

  /** Candidate key references that require typed public-read validation. */
  private static final Pattern KEY =
      Pattern.compile("(?:SSK|USK)@[^\\s<>\"']+", Pattern.CASE_INSENSITIVE);

  /** Prevents construction of this stateless validator. */
  private SharesiteDraftDataset() {}

  /**
   * Checks the complete proposed dataset against the requested operation semantics.
   *
   * @param current previous visible record, or null before the first import
   * @param proposed bounded candidate record whose values remain private app data
   * @param mode one of import, restore, edit, or undo
   * @throws network.crypta.platform.api.PlatformApiException if schema or transition checks fail
   */
  static void validateTransition(AppDataRecord current, AppDataRecord proposed, String mode) {
    Dataset next = parse(proposed.value());
    Dataset old = current == null ? new Dataset(Map.of(), Map.of()) : parse(current.value());
    switch (mode) {
      case "import" -> additive(old, next, true);
      case "restore" -> additive(old, next, false);
      case "edit" -> edit(old, next);
      case "undo" -> undo(old, next);
      default -> throw invalid();
    }
  }

  /**
   * Builds bounded indexes after validating schema, literal fields, and operation membership.
   *
   * @param bytes private UTF-8 JSON bytes of one complete dataset
   * @return validated operation and draft indexes for transition comparisons
   */
  private static Dataset parse(byte[] bytes) {
    if (bytes.length > SharesiteDraftWriteGuard.MAX_DATASET_BYTES) {
      throw invalid();
    }
    Map<String, Object> root = parseRoot(bytes);
    Map<String, Map<String, Object>> operations = parseOperations(root.get("operations"));
    Map<String, Map<String, Object>> drafts = parseDrafts(root.get("drafts"), operations);
    validateMembership(operations, drafts);
    return new Dataset(operations, drafts);
  }

  /**
   * Decodes strict UTF-8 and checks the closed version-one root fields.
   *
   * @param bytes size-checked private JSON bytes of the entire dataset
   * @return detached root map after encoding, version, and field checks succeed
   */
  private static Map<String, Object> parseRoot(byte[] bytes) {
    String json;
    try {
      json =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(bytes))
              .toString();
    } catch (CharacterCodingException _) {
      throw invalid();
    }
    Map<String, Object> root = map(AppDataJsonParser.parse(json));
    if (!root.keySet().equals(ROOT_FIELDS) || !Long.valueOf(1).equals(root.get("schemaVersion"))) {
      throw invalid();
    }
    return root;
  }

  /**
   * Validates each ledger entry before indexing its canonical operation identity.
   *
   * @param value parsed ledger array with at most thirty-two operations
   * @return operation index with unique identities and bounded string draft lists
   */
  private static Map<String, Map<String, Object>> parseOperations(Object value) {
    List<?> operations = list(value, 32);
    Map<String, Map<String, Object>> operationMap = new LinkedHashMap<>();
    for (Object item : operations) {
      Map<String, Object> op = map(item);
      if (!op.keySet().equals(OP_FIELDS)) {
        throw invalid();
      }
      String id = uuid(op.get(FIELD_OPERATION_ID));
      digest(op.get("payloadSha256"));
      digest(op.get(FIELD_ORIGINALS_SHA256));
      if (!(STATUS_COMMITTED.equals(op.get(FIELD_STATUS)) || "undone".equals(op.get(FIELD_STATUS)))
          || operationMap.putIfAbsent(id, op) != null) {
        throw invalid();
      }
      List<String> ids = draftIds(op);
      if (ids.isEmpty() || new HashSet<>(ids).size() != ids.size()) {
        throw invalid();
      }
      for (String draftId : ids) {
        if (!draftId.startsWith(id + "-")) {
          throw invalid();
        }
      }
    }
    return operationMap;
  }

  /**
   * Validates literal drafts and requires a committed owning ledger entry.
   *
   * @param value parsed draft array with at most five hundred twelve entries
   * @param operationMap validated ledger index used to check each draft owner
   * @return unique draft index after literal content and lineage validation succeeds
   */
  private static Map<String, Map<String, Object>> parseDrafts(
      Object value, Map<String, Map<String, Object>> operationMap) {
    Map<String, Map<String, Object>> draftMap = new LinkedHashMap<>();
    for (Object item : list(value, 512)) {
      Map<String, Object> draft = map(item);
      if (!DRAFT_FIELDS.containsAll(draft.keySet())
          || !draft
              .keySet()
              .containsAll(
                  Set.of(
                      "id",
                      FIELD_OPERATION_ID,
                      FIELD_SOURCE_ID,
                      "name",
                      FIELD_DESCRIPTION,
                      "text",
                      FIELD_HISTORICAL_EDITION,
                      FIELD_LOGICAL_PATH))) {
        throw invalid();
      }
      String operation = uuid(draft.get(FIELD_OPERATION_ID));
      long sourceId = number(draft.get(FIELD_SOURCE_ID), 0, Integer.MAX_VALUE);
      String id = text(draft.get("id"), 64);
      if (!id.equals(operation + "-" + sourceId) || draftMap.putIfAbsent(id, draft) != null) {
        throw invalid();
      }
      text(draft.get("name"), 4096);
      text(draft.get(FIELD_DESCRIPTION), 16_384);
      text(draft.get(FIELD_LOGICAL_PATH), 4096);
      text(draft.get("text"), 65_536);
      number(draft.get(FIELD_HISTORICAL_EDITION), -1, 9_007_199_254_740_991L);
      if (draft.containsKey(FIELD_PUBLIC_READ_REFERENCE)) {
        publicRead(text(draft.get(FIELD_PUBLIC_READ_REFERENCE), 4096));
      }
      Map<String, Object> op = operationMap.get(operation);
      if (op == null
          || !STATUS_COMMITTED.equals(op.get(FIELD_STATUS))
          || !draftIds(op).contains(id)) {
        throw invalid();
      }
    }
    return draftMap;
  }

  /**
   * Requires all committed drafts to be present and all undone drafts to be absent.
   *
   * @param operationMap validated operation index defining expected draft membership
   * @param draftMap validated draft index whose presence must match ledger states
   */
  private static void validateMembership(
      Map<String, Map<String, Object>> operationMap, Map<String, Map<String, Object>> draftMap) {
    for (Map<String, Object> op : operationMap.values()) {
      for (String id : draftIds(op)) {
        if (STATUS_COMMITTED.equals(op.get(FIELD_STATUS)) != draftMap.containsKey(id)) {
          throw invalid();
        }
      }
    }
  }

  /**
   * Preserves existing entries while checking newly added import or restore operations.
   *
   * @param old previous validated dataset before the proposed addition
   * @param next complete candidate dataset including all existing entries
   * @param singleOperation whether exactly one new committed import is required
   */
  private static void additive(Dataset old, Dataset next, boolean singleOperation) {
    preserve(old.operations(), next.operations());
    preserve(old.drafts(), next.drafts());
    int added = next.operations().size() - old.operations().size();
    if (added < 0 || (singleOperation && added != 1)) {
      throw invalid();
    }
    for (var entry : next.operations().entrySet()) {
      if (!old.operations().containsKey(entry.getKey())) {
        Map<String, Object> op = entry.getValue();
        if (singleOperation && !STATUS_COMMITTED.equals(op.get(FIELD_STATUS))) {
          throw invalid();
        }
        if (singleOperation
            && STATUS_COMMITTED.equals(op.get(FIELD_STATUS))
            && !op.get(FIELD_ORIGINALS_SHA256).equals(originals(next, op))) {
          throw invalid();
        }
      }
    }
  }

  /**
   * Allows literal name, description, and text edits while preserving identity and lineage.
   *
   * @param old previous validated dataset with original lineage fields
   * @param next candidate dataset with the same operation and draft identities
   */
  private static void edit(Dataset old, Dataset next) {
    if (!old.operations().equals(next.operations())
        || !old.drafts().keySet().equals(next.drafts().keySet())) {
      throw invalid();
    }
    for (var entry : old.drafts().entrySet()) {
      Map<String, Object> replacement = next.drafts().get(entry.getKey());
      if (!entry.getValue().keySet().equals(replacement.keySet())) {
        throw invalid();
      }
      for (var field : entry.getValue().entrySet()) {
        if (!Set.of("name", FIELD_DESCRIPTION, "text").contains(field.getKey())
            && !field.getValue().equals(replacement.get(field.getKey()))) {
          throw invalid();
        }
      }
    }
  }

  /**
   * Removes one unchanged import and retains its ledger entry as undone.
   *
   * @param old previous dataset whose original-content binding must still match
   * @param next candidate dataset preserving all unrelated drafts and operations
   */
  private static void undo(Dataset old, Dataset next) {
    if (!old.operations().keySet().equals(next.operations().keySet())) {
      throw invalid();
    }
    int undone = 0;
    Set<String> removed = new HashSet<>();
    for (var entry : old.operations().entrySet()) {
      Map<String, Object> before = entry.getValue();
      Map<String, Object> after = next.operations().get(entry.getKey());
      if (before.equals(after)) {
        continue;
      }
      Map<String, Object> expected = new LinkedHashMap<>(before);
      expected.put(FIELD_STATUS, "undone");
      if (!STATUS_COMMITTED.equals(before.get(FIELD_STATUS))
          || !expected.equals(after)
          || !before.get(FIELD_ORIGINALS_SHA256).equals(originals(old, before))) {
        throw SharesiteDraftWriteGuard.failure("sharesite_undo_requires_manual_recovery");
      }
      undone++;
      removed.addAll(draftIds(before));
    }
    Map<String, Map<String, Object>> remaining = new LinkedHashMap<>(old.drafts());
    removed.forEach(remaining::remove);
    if (undone != 1 || !remaining.equals(next.drafts())) {
      throw invalid();
    }
  }

  /**
   * Computes the private canonical digest for an operation's ordered draft set.
   *
   * @param dataset validated dataset containing the referenced draft values
   * @param operation ledger entry selecting the exact ordered draft identities
   * @return local comparison digest, never a public content-fidelity receipt
   */
  private static String originals(Dataset dataset, Map<String, Object> operation) {
    return SharesiteDraftWriteGuard.canonicalDigest(
        draftIds(operation).stream().map(dataset.drafts()::get).toList());
  }

  /**
   * Rejects any changed or missing existing map entry.
   *
   * @param before existing entries that the operation must preserve exactly
   * @param after candidate entries that may contain additional unrelated identities
   */
  private static void preserve(
      Map<String, Map<String, Object>> before, Map<String, Map<String, Object>> after) {
    before.forEach(
        (id, value) -> {
          if (!value.equals(after.get(id))) {
            throw SharesiteDraftWriteGuard.failure("sharesite_collision");
          }
        });
  }

  /**
   * Validates literal Unicode text, encoded size, credential markers, and embedded keys.
   *
   * @param object candidate scalar whose exact string value must be retained
   * @param maxBytes maximum permitted encoded UTF-8 length in bytes
   * @return unchanged literal string after every local validation succeeds
   */
  private static String text(Object object, int maxBytes) {
    if (!(object instanceof String value)
        || value.length() > maxBytes
        || value.getBytes(StandardCharsets.UTF_8).length > maxBytes
        || SECRET_CREDENTIAL.matcher(value).find()
        || SECRET_ASSIGNMENT.matcher(value).find()) {
      throw invalid();
    }
    validateSurrogates(value);
    var keys = KEY.matcher(value);
    while (keys.find()) {
      publicRead(keys.group());
    }
    return value;
  }

  /**
   * Requires every high surrogate to have exactly one following low surrogate.
   *
   * @param value literal Java string whose UTF-16 code units are checked
   */
  private static void validateSurrogates(String value) {
    boolean expectingLow = false;
    for (int index = 0; index < value.length(); index++) {
      char ch = value.charAt(index);
      if (expectingLow) {
        if (!Character.isLowSurrogate(ch)) {
          throw invalid();
        }
        expectingLow = false;
      } else if (Character.isHighSurrogate(ch)) {
        expectingLow = true;
      } else if (Character.isLowSurrogate(ch)) {
        throw invalid();
      }
    }
    if (expectingLow) {
      throw invalid();
    }
  }

  /**
   * Requires a typed public SSK or USK reference without insertion capability.
   *
   * @param value candidate reference used solely as private historical metadata
   */
  private static void publicRead(String value) {
    try {
      FreenetURI uri = new FreenetURI(value);
      if (uri.isUSK()) {
        new ClientSSK(uri.sskForUSK());
      } else if (uri.isSSK()) {
        new ClientSSK(uri);
      } else {
        throw SharesiteDraftWriteGuard.failure("sharesite_prohibited_key_material");
      }
    } catch (MalformedURLException | IllegalArgumentException _) {
      throw SharesiteDraftWriteGuard.failure("sharesite_prohibited_key_material");
    }
  }

  /**
   * Requires a canonical UUID spelling for an import operation.
   *
   * @param value candidate operation identity from the private dataset
   * @return unchanged canonical UUID string suitable for identity comparisons
   */
  private static String uuid(Object value) {
    if (!(value instanceof String string)) {
      throw invalid();
    }
    try {
      if (!UUID.fromString(string).toString().equals(string)) {
        throw invalid();
      }
      return string;
    } catch (IllegalArgumentException _) {
      throw invalid();
    }
  }

  /**
   * Requires the closed lowercase SHA-256 spelling for private comparison metadata.
   *
   * @param value candidate private digest with exactly sixty-four hexadecimal characters
   */
  private static void digest(Object value) {
    if (!(value instanceof String string) || !string.matches("[0-9a-f]{64}")) {
      throw invalid();
    }
  }

  /**
   * Requires an integer scalar within inclusive historical metadata bounds.
   *
   * @param value parsed JSON scalar that must be a long integer
   * @param minimum inclusive smallest accepted value for this field
   * @param maximum inclusive largest accepted value for this field
   * @return validated integer without normalization or loss of precision
   */
  private static long number(Object value, long minimum, long maximum) {
    if (!(value instanceof Long number) || number < minimum || number > maximum) {
      throw invalid();
    }
    return number;
  }

  /**
   * Requires a JSON object without exposing its contents in failures.
   *
   * @param value parsed private JSON value to check structurally
   * @return detached object map with validated string keys
   */
  private static Map<String, Object> map(Object value) {
    if (!(value instanceof Map<?, ?> raw)) {
      throw invalid();
    }
    Map<String, Object> result = new LinkedHashMap<>();
    raw.forEach(
        (key, item) -> {
          if (!(key instanceof String name)) {
            throw invalid();
          }
          result.put(name, item);
        });
    return result;
  }

  /**
   * Requires a bounded list of string draft identities without coercing other JSON types.
   *
   * @param operation private ledger entry containing the candidate draft identity list
   * @return detached list of at most sixteen unchanged string draft identities
   */
  private static List<String> draftIds(Map<String, Object> operation) {
    return list(operation.get(FIELD_DRAFT_IDS), 16).stream()
        .map(
            item -> {
              if (!(item instanceof String id)) {
                throw invalid();
              }
              return id;
            })
        .toList();
  }

  /**
   * Requires a JSON list within its record-count limit.
   *
   * @param value parsed private JSON value to check structurally
   * @param max inclusive maximum accepted number of list entries
   * @return original bounded list after confirming its structural type
   */
  private static List<?> list(Object value, int max) {
    if (!(value instanceof List<?> list) || list.size() > max) {
      throw invalid();
    }
    return list;
  }

  /**
   * Creates a content-free schema or transition rejection.
   *
   * @return bounded API error containing no private rejected field values
   */
  private static network.crypta.platform.api.PlatformApiException invalid() {
    return SharesiteDraftWriteGuard.failure("sharesite_invalid_dataset");
  }

  /**
   * Carries validation-local indexes; callers do not mutate their entries.
   *
   * @param operations canonical operation identities mapped to private ledger metadata
   * @param drafts exact draft identities mapped to private literal document fields
   */
  private record Dataset(
      Map<String, Map<String, Object>> operations, Map<String, Map<String, Object>> drafts) {}
}
