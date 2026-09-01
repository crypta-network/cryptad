package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Atomic, path-confined storage for bounded pending catalog discovery recommendations.
 *
 * <p>The store authenticates supplied public descriptor and endorsement bytes before creating one
 * immutable local envelope. Record names are SHA-256 hashes of validated descriptor IDs, writes use
 * a temporary file in the store root followed by an atomic replacement where supported, and reads
 * reject symlinks, oversized files, unknown fields, digest substitution, and filename mismatch. The
 * configured count limit and per-record byte limit bound retained public discovery data.
 *
 * <p>Public methods synchronize access within one store instance. Separate instances remain safe
 * for restart reads, but callers should serialize concurrent writers to the same directory. The
 * store owns pending evidence only: it has no catalog-source, trust-store, publisher-policy,
 * reviewer-policy, application-installation, or remote-discovery authority.
 */
public final class FilePendingCatalogDiscoveryStore {
  /** Default maximum number of pending descriptors retained in one local store. */
  public static final int DEFAULT_MAX_RECORDS = 128;

  /** Filename suffix for retained pending-discovery envelopes. */
  private static final String SUFFIX = ".pending-discovery.json";

  /** Maximum accepted canonical pending-discovery record size. */
  private static final long MAX_RECORD_BYTES = CatalogSignedDocumentSupport.MAX_DOCUMENT_BYTES;

  /** Absolute normalized private discovery-store root. */
  private final Path root;

  /** Maximum number of pending descriptor identities retained by this store. */
  private final int maxRecords;

  /**
   * Creates a store with the default bounded record limit.
   *
   * <p>The constructor normalizes the absolute store path but performs no I/O. The first import
   * creates the directory; read operations return an empty result when it does not exist. Root
   * safety and record confinement are checked again for every operation.
   *
   * @param root host-private directory reserved for pending discovery evidence
   */
  public FilePendingCatalogDiscoveryStore(Path root) {
    this(root, DEFAULT_MAX_RECORDS);
  }

  /**
   * Creates a store with an explicit positive record limit.
   *
   * <p>The configurable bound supports smaller embedded deployments and deterministic tests. A full
   * store rejects new descriptor IDs rather than silently evicting operator-visible evidence.
   * Construction performs no filesystem access and accepts at most {@value #DEFAULT_MAX_RECORDS}
   * records.
   *
   * @param root host-private directory reserved for pending discovery evidence
   * @param maxRecords positive retained-record limit no greater than the default maximum
   */
  public FilePendingCatalogDiscoveryStore(Path root, int maxRecords) {
    this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
    if (maxRecords < 1 || maxRecords > DEFAULT_MAX_RECORDS) {
      throw new IllegalArgumentException(
          "pending discovery record limit must be between 1 and 128");
    }
    this.maxRecords = maxRecords;
  }

  /**
   * Authenticates and atomically retains one pending descriptor and its direct endorsements.
   *
   * <p>No key, source, trust binding, publisher policy, reviewer policy, app, or transitive
   * endorsement is installed by this operation.
   *
   * @param descriptorBytes exact signed public descriptor bytes
   * @param endorsementBytes zero to eight exact signed direct-endorsement documents
   * @param trustedIssuerKeys local public issuer material used only to authenticate the documents
   * @param now local verification and import instant
   * @return immutable pending recommendation retained by the store
   * @throws IOException if the confined atomic write fails
   * @throws AppCatalogException if a document, subject binding, store record, or retention bound is
   *     invalid
   */
  public synchronized PendingCatalogDiscoveryRecommendation importRecommendation(
      byte[] descriptorBytes,
      List<byte[]> endorsementBytes,
      TrustedAppKeys trustedIssuerKeys,
      Instant now)
      throws IOException {
    Objects.requireNonNull(endorsementBytes, "endorsementBytes");
    if (endorsementBytes.size() > PendingCatalogDiscoveryRecommendation.MAX_ENDORSEMENTS) {
      throw invalid("pending discovery endorsement count exceeds the retention limit");
    }
    long totalBytes = Objects.requireNonNull(descriptorBytes, "descriptorBytes").length;
    for (byte[] endorsement : endorsementBytes) {
      totalBytes =
          Math.addExact(totalBytes, Objects.requireNonNull(endorsement, "endorsement").length);
      if (totalBytes > MAX_RECORD_BYTES) {
        throw invalid("pending discovery input exceeds the retained byte limit");
      }
    }
    TrustedAppKeys keys = Objects.requireNonNull(trustedIssuerKeys, "trustedIssuerKeys");
    Instant verifiedAt = Objects.requireNonNull(now, "now");
    CatalogDiscoveryImportResult descriptor =
        CatalogDiscoveryVerifier.verifyForImport(descriptorBytes, keys, verifiedAt);
    List<CatalogEndorsementVerification> endorsements = new ArrayList<>(endorsementBytes.size());
    for (byte[] bytes : endorsementBytes) {
      endorsements.add(CatalogEndorsementVerifier.verifyDirect(bytes, keys, verifiedAt));
    }
    PendingCatalogDiscoveryRecommendation recommendation =
        PendingCatalogDiscoveryRecommendation.create(descriptor, endorsements);
    put(recommendation);
    return recommendation;
  }

  /**
   * Reads one structurally intact pending record without activating any trust.
   *
   * @param descriptorId stable descriptor identifier
   * @return the retained pending record, or empty when the ID is unknown
   * @throws IOException if the store cannot be read safely
   */
  public synchronized Optional<PendingCatalogDiscoveryRecommendation> find(String descriptorId)
      throws IOException {
    Path path = recordPath(descriptorId);
    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    return Optional.of(read(path));
  }

  /**
   * Discards one pending recommendation without changing any catalog or trust state.
   *
   * <p>The record is validated before deletion so a substituted path or symlink cannot be treated
   * as the requested descriptor. This is an explicit local retention action; no automatic expiry
   * job, remote notification, or trust revocation is implied.
   *
   * @param descriptorId stable descriptor identifier
   * @return {@code true} when an intact pending record was removed
   * @throws IOException if the store cannot be read or changed safely
   */
  public synchronized boolean discard(String descriptorId) throws IOException {
    Path path = recordPath(descriptorId);
    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
      return false;
    }
    PendingCatalogDiscoveryRecommendation recommendation = read(path);
    if (!recommendation.descriptorId().equals(descriptorId)) {
      throw invalid("pending discovery descriptor id does not match the discard request");
    }
    Files.delete(path);
    return true;
  }

  /**
   * Lists all pending records deterministically, failing closed on duplicate descriptor IDs.
   *
   * @return immutable list ordered by descriptor ID
   * @throws IOException if any record cannot be read safely
   */
  public synchronized List<PendingCatalogDiscoveryRecommendation> list() throws IOException {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }
    requireSafeRoot();
    List<PendingCatalogDiscoveryRecommendation> records = new ArrayList<>();
    try (var stream = Files.list(root)) {
      for (Path path :
          stream.filter(item -> item.getFileName().toString().endsWith(SUFFIX)).sorted().toList()) {
        records.add(read(path));
      }
    }
    if (records.size() > maxRecords) {
      throw invalid("pending discovery store exceeds its record limit");
    }
    Set<String> descriptorIds = new HashSet<>();
    for (PendingCatalogDiscoveryRecommendation recommendation : records) {
      if (!descriptorIds.add(recommendation.descriptorId())) {
        throw invalid("duplicate pending discovery descriptor id");
      }
    }
    return records.stream()
        .sorted(java.util.Comparator.comparing(PendingCatalogDiscoveryRecommendation::descriptorId))
        .toList();
  }

  /**
   * Atomically retains one authenticated pending recommendation.
   *
   * @param recommendation immutable verified recommendation envelope
   * @throws IOException if the confined record cannot be read or written
   */
  private void put(PendingCatalogDiscoveryRecommendation recommendation) throws IOException {
    byte[] bytes = recommendation.canonicalRecordBytes();
    if (bytes.length > MAX_RECORD_BYTES) {
      throw invalid("pending discovery record exceeds the retained byte limit");
    }
    Files.createDirectories(root);
    requireSafeRoot();
    Path target = recordPath(recommendation.descriptorId());
    Optional<PendingCatalogDiscoveryRecommendation> existing =
        Files.exists(target, LinkOption.NOFOLLOW_LINKS)
            ? Optional.of(read(target))
            : Optional.empty();
    if (existing.isPresent()) {
      if (existing.get().equals(recommendation)) {
        return;
      }
      throw invalid("pending discovery descriptor id already exists with different evidence");
    }
    if (list().size() >= maxRecords) {
      throw invalid("pending discovery store has reached its record limit");
    }
    Path temporary = Files.createTempFile(root, ".pending-discovery-", ".tmp");
    try {
      Files.write(temporary, bytes);
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
   * Reads and validates one canonical pending-discovery envelope.
   *
   * @param path confined record path
   * @return validated pending recommendation
   * @throws IOException if the record cannot be inspected or read
   */
  private PendingCatalogDiscoveryRecommendation read(Path path) throws IOException {
    requireSafeRoot();
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(path)
        || Files.size(path) == 0
        || Files.size(path) > MAX_RECORD_BYTES) {
      throw invalid("pending discovery record is not a bounded regular file");
    }
    PendingCatalogDiscoveryRecommendation recommendation =
        PendingCatalogDiscoveryRecommendation.parse(Files.readAllBytes(path));
    Path fileName = path.getFileName();
    if (fileName == null
        || !fileName.toString().equals(recordFileName(recommendation.descriptorId()))) {
      throw invalid("pending discovery descriptor id does not match its record name");
    }
    return recommendation;
  }

  /**
   * Resolves one validated descriptor identity below the store root.
   *
   * @param descriptorId stable descriptor identifier
   * @return confined normalized record path
   */
  private Path recordPath(String descriptorId) {
    String checked =
        CatalogSignedDocumentSupport.requireId(
            descriptorId, "descriptorId", PendingCatalogDiscoveryRecommendation.INVALID_STORE);
    Path path = root.resolve(recordFileName(checked)).normalize();
    if (!root.equals(path.getParent())) {
      throw invalid("pending discovery record path escapes the store root");
    }
    return path;
  }

  /**
   * Derives the non-identifying record filename for one descriptor ID.
   *
   * @param descriptorId validated stable descriptor identifier
   * @return SHA-256-routed filename with the store suffix
   */
  private static String recordFileName(String descriptorId) {
    return CatalogSignedDocumentSupport.sha256(
            descriptorId.getBytes(java.nio.charset.StandardCharsets.UTF_8))
        + SUFFIX;
  }

  /** Requires the configured root to be absent or a non-symbolic-link directory. */
  private void requireSafeRoot() {
    if (Files.isSymbolicLink(root)
        || (Files.exists(root, LinkOption.NOFOLLOW_LINKS)
            && !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS))) {
      throw invalid("pending discovery store root is not a directory");
    }
  }

  /**
   * Creates the stable invalid-pending-store failure.
   *
   * @param message bounded validation explanation
   * @return catalog exception with the stable pending-store error code
   */
  private static AppCatalogException invalid(String message) {
    return new AppCatalogException(PendingCatalogDiscoveryRecommendation.INVALID_STORE, message);
  }
}
