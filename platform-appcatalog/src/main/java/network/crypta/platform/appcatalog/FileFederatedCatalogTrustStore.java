package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Atomic, closed, file-backed storage for host-owned federated catalog trust bindings.
 *
 * <p>The store owns local catalog admission independently of fetched catalog content. It confines
 * every binding to a normalized private root, verifies canonical self-digests on read, and rejects
 * catalog aliases or signer fingerprints reused across catalog identities. Catalog-scoped lookup
 * isolates unrelated damaged records while still fully authenticating every selected record.
 */
public final class FileFederatedCatalogTrustStore {
  /** Filename suffix for serialized trust bindings. */
  private static final String SUFFIX = ".properties";

  /** Safe placeholder used only to validate record identifiers through the model. */
  private static final String VALIDATION_PROBE = "probe";

  /** Maximum accepted serialized trust-binding size. */
  private static final long MAX_RECORD_BYTES = 64 * 1024L;

  /** Absolute normalized private trust-store root. */
  private final Path root;

  /**
   * Creates a store at the given host-private root.
   *
   * @param root private directory containing catalog trust records
   */
  public FileFederatedCatalogTrustStore(Path root) {
    this.root = root.toAbsolutePath().normalize();
  }

  /**
   * Writes one exact binding with an atomic commit marker.
   *
   * @param binding validated local trust binding to persist
   * @throws IOException if existing records cannot be read or replacement cannot be written
   */
  public synchronized void put(FederatedCatalogTrustBinding binding) throws IOException {
    FederatedCatalogTrustBinding checked = java.util.Objects.requireNonNull(binding, "binding");
    Files.createDirectories(root);
    requireSafeRoot();
    for (FederatedCatalogTrustBinding existing : list()) {
      rejectConflictingBinding(existing, checked);
    }
    Path target = recordPath(checked.bindingId());
    Path temporary = Files.createTempFile(root, ".catalog-trust-", ".tmp");
    try {
      Files.writeString(temporary, checked.canonicalText(), StandardCharsets.UTF_8);
      try {
        Files.move(
            temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      } catch (AtomicMoveNotSupportedException _) {
        Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
      }
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  /**
   * Reads one binding, rejecting symlinked, oversized, or non-canonical records.
   *
   * @param bindingId stable local binding identifier
   * @return validated binding, or empty when its record is absent
   * @throws IOException if an existing record cannot be read
   */
  public synchronized Optional<FederatedCatalogTrustBinding> find(String bindingId)
      throws IOException {
    Path path = recordPath(bindingId);
    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    return Optional.of(read(path));
  }

  /**
   * Lists all bindings deterministically without allowing one record to alias another.
   *
   * @return immutable bindings sorted by record path
   * @throws IOException if the store cannot be enumerated or a record cannot be read
   */
  public synchronized List<FederatedCatalogTrustBinding> list() throws IOException {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }
    requireSafeRoot();
    List<FederatedCatalogTrustBinding> bindings = new ArrayList<>();
    try (var stream = Files.list(root)) {
      for (Path path :
          stream.filter(item -> item.getFileName().toString().endsWith(SUFFIX)).sorted().toList()) {
        bindings.add(read(path));
      }
    }
    rejectAmbiguousBindings(bindings);
    return List.copyOf(bindings);
  }

  /**
   * Finds the unique local binding for a catalog ID.
   *
   * @param catalogId catalog identity to resolve
   * @return unique validated local binding, or empty when absent
   * @throws IOException if catalog-local records cannot be enumerated or read
   */
  public synchronized Optional<FederatedCatalogTrustBinding> findByCatalogId(String catalogId)
      throws IOException {
    String normalized = AppCatalog.normalizeCatalogId(catalogId);
    List<FederatedCatalogTrustBinding> matches = listForCatalog(normalized);
    if (matches.size() > 1) {
      throw invalid("multiple local trust bindings exist for catalog " + normalized);
    }
    return matches.stream().findFirst();
  }

  /**
   * Reads and authenticates records routed to one normalized catalog identity.
   *
   * @param catalogId normalized catalog identity
   * @return immutable catalog-local bindings
   * @throws IOException if candidate records cannot be enumerated or read
   */
  private List<FederatedCatalogTrustBinding> listForCatalog(String catalogId) throws IOException {
    List<FederatedCatalogTrustBinding> bindings = new ArrayList<>();
    for (Path path :
        FederatedPolicyRecordSupport.catalogScopedRecordPaths(root, SUFFIX, catalogId)) {
      FederatedCatalogTrustBinding binding = read(path);
      if (!binding.catalogId().equals(catalogId)) {
        throw invalid("catalog trust record changed during scoped lookup");
      }
      bindings.add(binding);
    }
    rejectAmbiguousBindings(bindings);
    return List.copyOf(bindings);
  }

  /**
   * Parses and validates one canonical trust-binding record.
   *
   * @param path confined record path
   * @return validated trust binding
   * @throws IOException if the record cannot be inspected or read
   */
  private FederatedCatalogTrustBinding read(Path path) throws IOException {
    requireSafeRoot();
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(path)
        || Files.size(path) > MAX_RECORD_BYTES) {
      throw invalid("catalog trust record is not a bounded regular file");
    }
    Map<String, String> fields = parse(Files.readString(path, StandardCharsets.UTF_8));
    int schemaVersion = parseInt(remove(fields, "schemaVersion"), "schemaVersion");
    String bindingId = remove(fields, "bindingId");
    String catalogId = remove(fields, "catalogId");
    FederatedCatalogTrustBinding.Status status =
        FederatedCatalogTrustBinding.Status.parse(remove(fields, "status"));
    int localPriority = parseInt(remove(fields, "localPriority"), "localPriority");
    Instant createdAt = parseInstant(remove(fields, "createdAt"), "createdAt");
    Instant updatedAt = parseInstant(remove(fields, "updatedAt"), "updatedAt");
    String reason = remove(fields, "reason");
    String operatorId = remove(fields, "operatorId");
    Set<AppCatalogChannel> channels = new LinkedHashSet<>();
    for (String value : split(remove(fields, "channels"))) {
      channels.add(AppCatalogChannel.parse(value, "channels"));
    }
    LinkedHashMap<String, String> signers = new LinkedHashMap<>();
    for (String id : split(remove(fields, "signerIds"))) {
      signers.put(id, remove(fields, "signer." + id));
    }
    Optional<String> discovery = Optional.ofNullable(fields.remove("discoveryDigest"));
    Optional<String> reviewer = Optional.ofNullable(fields.remove("reviewerPolicyDigest"));
    Optional<String> publisher = Optional.ofNullable(fields.remove("publisherPolicyDigest"));
    String selfDigest = remove(fields, "selfDigest");
    if (!fields.isEmpty()) {
      throw invalid("unsupported catalog trust property: " + fields.keySet().iterator().next());
    }
    FederatedCatalogTrustBinding binding =
        new FederatedCatalogTrustBinding(
            schemaVersion,
            bindingId,
            catalogId,
            signers,
            status,
            channels,
            localPriority,
            discovery,
            reviewer,
            publisher,
            createdAt,
            updatedAt,
            reason,
            operatorId,
            selfDigest);
    String expectedName = binding.bindingId() + SUFFIX;
    Path fileName = path.getFileName();
    if (fileName == null || !fileName.toString().equals(expectedName)) {
      throw invalid("catalog trust record id does not match file name");
    }
    return binding;
  }

  /**
   * Resolves one model-validated binding identifier below the store root.
   *
   * @param bindingId stable local binding identifier
   * @return confined normalized record path
   */
  private Path recordPath(String bindingId) {
    FederatedCatalogTrustBinding probe =
        FederatedCatalogTrustBinding.create(
            bindingId,
            VALIDATION_PROBE,
            Map.of(VALIDATION_PROBE, "0".repeat(64)),
            FederatedCatalogTrustBinding.Status.PENDING,
            Set.of(AppCatalogChannel.BETA),
            0,
            null,
            null,
            null,
            Instant.EPOCH,
            Instant.EPOCH,
            VALIDATION_PROBE,
            VALIDATION_PROBE);
    Path path = root.resolve(probe.bindingId() + SUFFIX).normalize();
    if (!root.equals(path.getParent())) {
      throw invalid("catalog trust binding path escapes store root");
    }
    return path;
  }

  /** Requires the configured root to be absent or a non-symbolic-link directory. */
  private void requireSafeRoot() {
    if (Files.isSymbolicLink(root)
        || (Files.exists(root, LinkOption.NOFOLLOW_LINKS)
            && !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS))) {
      throw invalid("catalog trust store root is not a directory");
    }
  }

  /**
   * Rejects identity movement, duplicate catalogs, and cross-catalog signer reuse.
   *
   * @param existing persisted binding
   * @param checked proposed binding
   */
  private static void rejectConflictingBinding(
      FederatedCatalogTrustBinding existing, FederatedCatalogTrustBinding checked) {
    boolean sameBinding = existing.bindingId().equals(checked.bindingId());
    boolean sameCatalog = existing.catalogId().equals(checked.catalogId());
    if (sameBinding) {
      if (!sameCatalog) {
        throw invalid("catalog trust binding id cannot move between catalog identities");
      }
      if (!existing.createdAt().equals(checked.createdAt())) {
        throw invalid("catalog trust binding creation timestamp cannot change");
      }
      if (existing.status() == FederatedCatalogTrustBinding.Status.REVOKED
          && checked.status() != FederatedCatalogTrustBinding.Status.REVOKED) {
        throw invalid("revoked catalog trust binding cannot be reactivated");
      }
      return;
    }
    if (sameCatalog) {
      throw invalid("catalog id already has a local trust binding");
    }
    rejectDuplicateSignerFingerprint(existing, checked);
  }

  /**
   * Rejects a signer fingerprint already bound to another catalog identity.
   *
   * @param existing persisted binding for another catalog
   * @param checked proposed binding
   */
  private static void rejectDuplicateSignerFingerprint(
      FederatedCatalogTrustBinding existing, FederatedCatalogTrustBinding checked) {
    for (String fingerprint : checked.signerFingerprints().values()) {
      if (existing.signerFingerprints().containsValue(fingerprint)) {
        throw invalid("catalog signer fingerprint is already bound to another catalog identity");
      }
    }
  }

  /**
   * Parses unique properties from one serialized trust record.
   *
   * @param text serialized UTF-8 record text
   * @return insertion-ordered mutable properties
   */
  private static Map<String, String> parse(String text) {
    LinkedHashMap<String, String> fields = new LinkedHashMap<>();
    for (String line : text.split("\\n", -1)) {
      if (line.isEmpty()) {
        continue;
      }
      int separator = line.indexOf('=');
      if (separator <= 0 || line.indexOf('=', separator + 1) >= 0) {
        throw invalid("invalid catalog trust record line");
      }
      String prior = fields.put(line.substring(0, separator), line.substring(separator + 1));
      if (prior != null) {
        throw invalid("duplicate catalog trust property");
      }
    }
    return fields;
  }

  /**
   * Rejects multiple records claiming the same catalog identity.
   *
   * @param bindings trust bindings to validate together
   */
  private static void rejectAmbiguousBindings(List<FederatedCatalogTrustBinding> bindings) {
    Set<String> catalogIds = new java.util.HashSet<>();
    for (FederatedCatalogTrustBinding binding : bindings) {
      if (!catalogIds.add(binding.catalogId())) {
        throw invalid("multiple local trust bindings exist for one catalog id");
      }
    }
  }

  /**
   * Removes one required property from a parsed record.
   *
   * @param fields remaining parsed properties
   * @param key required property name
   * @return removed property value
   */
  private static String remove(Map<String, String> fields, String key) {
    String value = fields.remove(key);
    if (value == null) {
      throw invalid("missing catalog trust property: " + key);
    }
    return value;
  }

  /**
   * Splits the canonical comma-delimited representation of a closed list.
   *
   * @param value serialized list
   * @return immutable members, or an empty list for blank text
   */
  private static List<String> split(String value) {
    return value.isBlank() ? List.of() : List.of(value.split(",", -1));
  }

  /**
   * Parses a required integer property.
   *
   * @param value serialized integer
   * @param field field name used in failures
   * @return parsed integer
   */
  private static int parseInt(String value, String field) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException exception) {
      throw invalid("invalid " + field, exception);
    }
  }

  /**
   * Parses a required timestamp property.
   *
   * @param value serialized instant
   * @param field field name used in failures
   * @return parsed timestamp
   */
  private static Instant parseInstant(String value, String field) {
    try {
      return Instant.parse(value);
    } catch (RuntimeException exception) {
      throw invalid("invalid " + field, exception);
    }
  }

  /**
   * Creates the stable invalid-store failure.
   *
   * @param message bounded validation explanation
   * @return catalog exception with the stable trust-store error code
   */
  private static AppCatalogException invalid(String message) {
    return new AppCatalogException("invalid_catalog_trust_store", message);
  }

  /**
   * Creates the stable invalid-store failure with its cause.
   *
   * @param message bounded validation explanation
   * @param cause underlying parse failure
   * @return catalog exception with the stable trust-store error code
   */
  private static AppCatalogException invalid(String message, Exception cause) {
    return new AppCatalogException("invalid_catalog_trust_store", message, cause);
  }
}
