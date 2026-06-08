package network.crypta.platform.api.appdata;

import java.io.IOException;
import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Process-local app-data store used by tests and reduced embeddings.
 *
 * <p>The implementation keeps the same app/namespace/key validation as the file-backed store but
 * does not provide restart durability. It is useful for router and service tests that need a
 * deterministic store without filesystem setup.
 *
 * <p>The store keeps separate maps for namespace metadata and records so tests exercise the same
 * service behavior as the file store: namespace totals are derived from current records, deletes
 * can leave metadata updates visible, and app-level cleanup removes both metadata and values. It
 * does not simulate crash-safety, symlink handling, or atomic filesystem publication.
 *
 * <p>Methods are synchronized to match the simple consistency boundary expected by {@link
 * AppDataService}. The implementation is still process-local and should not be used as a durable
 * production store.
 */
public final class InMemoryAppDataStore implements AppDataStore {
  private final Map<String, Map<String, AppDataNamespaceMetadata>> namespaces =
      new LinkedHashMap<>();
  private final Map<String, Map<String, Map<String, AppDataRecord>>> records =
      new LinkedHashMap<>();

  /**
   * Creates an empty in-memory store.
   *
   * <p>The store starts with no namespaces or records and keeps all subsequent writes in process
   * memory. It is synchronized at the method level to match the simple consistency expectations of
   * service and router tests.
   */
  public InMemoryAppDataStore() {
    // Intentionally empty: the backing maps are initialized at declaration.
  }

  /**
   * {@inheritDoc}
   *
   * <p>The in-memory store reports any app id that owns namespace metadata or records, including
   * preserved app-data state for apps that are no longer installed in the test embedding.
   */
  @Override
  public synchronized List<String> listAppIds() {
    return java.util.stream.Stream.concat(namespaces.keySet().stream(), records.keySet().stream())
        .distinct()
        .sorted()
        .toList();
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned namespace metadata includes counts, byte totals, and update timestamps derived
   * from the current in-memory record map.
   */
  @Override
  public synchronized List<AppDataNamespaceMetadata> listNamespaces(String appId) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    return namespaceMap(normalizedAppId).values().stream()
        .map(this::withDerivedTotals)
        .sorted(Comparator.comparing(AppDataNamespaceMetadata::namespace))
        .toList();
  }

  /**
   * {@inheritDoc}
   *
   * <p>Metadata is treated as absent when no namespace entry exists. Current totals are derived
   * before the value is returned.
   */
  @Override
  public synchronized Optional<AppDataNamespaceMetadata> readNamespace(
      String appId, String namespace) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace = AppDataRecord.normalizeNamespace(namespace);
    AppDataNamespaceMetadata metadata = namespaceMap(normalizedAppId).get(normalizedNamespace);
    return metadata == null ? Optional.empty() : Optional.of(withDerivedTotals(metadata));
  }

  /**
   * {@inheritDoc}
   *
   * <p>The metadata is stored by normalized app id and namespace. Record totals remain derived at
   * read time.
   */
  @Override
  public synchronized void writeNamespace(AppDataNamespaceMetadata metadata) {
    namespaceMap(metadata.appId()).put(metadata.namespace(), metadata);
  }

  /**
   * {@inheritDoc}
   *
   * <p>The in-memory implementation returns full record objects because no filesystem value read is
   * involved. Callers that need metadata-only behavior can still use the default summary method
   * from {@link AppDataStore}.
   */
  @Override
  public synchronized List<AppDataRecord> listRecords(String appId, String namespace) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace =
        namespace == null ? null : AppDataRecord.normalizeNamespace(namespace);
    return recordsForApp(normalizedAppId).entrySet().stream()
        .filter(entry -> normalizedNamespace == null || entry.getKey().equals(normalizedNamespace))
        .flatMap(entry -> entry.getValue().values().stream())
        .sorted(Comparator.comparing(AppDataRecord::namespace).thenComparing(AppDataRecord::key))
        .toList();
  }

  /**
   * {@inheritDoc}
   *
   * <p>Lookups are scoped by normalized app id, namespace, and key. No cross-app fallback exists.
   */
  @Override
  public synchronized Optional<AppDataRecord> readRecord(
      String appId, String namespace, String key) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace = AppDataRecord.normalizeNamespace(namespace);
    String normalizedKey = AppDataRecord.normalizeKey(key);
    return Optional.ofNullable(
        recordsForApp(normalizedAppId)
            .getOrDefault(normalizedNamespace, Map.of())
            .get(normalizedKey));
  }

  /**
   * {@inheritDoc}
   *
   * <p>Records are stored under the app id, namespace, and key already normalized by {@link
   * AppDataRecord}.
   */
  @Override
  public synchronized void writeRecord(AppDataRecord appDataRecord) {
    recordsForNamespace(appDataRecord.appId(), appDataRecord.namespace())
        .put(appDataRecord.key(), appDataRecord);
  }

  /**
   * {@inheritDoc}
   *
   * <p>Deleting a record removes only the value entry; namespace metadata remains until explicitly
   * updated or deleted by the service.
   */
  @Override
  public synchronized boolean deleteRecord(String appId, String namespace, String key) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace = AppDataRecord.normalizeNamespace(namespace);
    String normalizedKey = AppDataRecord.normalizeKey(key);
    Map<String, AppDataRecord> namespaceRecords =
        recordsForApp(normalizedAppId).get(normalizedNamespace);
    return namespaceRecords != null && namespaceRecords.remove(normalizedKey) != null;
  }

  /**
   * {@inheritDoc}
   *
   * <p>Namespace deletion removes both metadata and all record values for the namespace.
   */
  @Override
  public synchronized void deleteNamespace(String appId, String namespace) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace = AppDataRecord.normalizeNamespace(namespace);
    namespaceMap(normalizedAppId).remove(normalizedNamespace);
    recordsForApp(normalizedAppId).remove(normalizedNamespace);
  }

  /**
   * {@inheritDoc}
   *
   * <p>App cleanup removes every namespace and record map owned by the normalized app id.
   */
  @Override
  public synchronized void deleteAllForApp(String appId) throws IOException {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    namespaces.remove(normalizedAppId);
    records.remove(normalizedAppId);
  }

  private AppDataNamespaceMetadata withDerivedTotals(AppDataNamespaceMetadata metadata) {
    List<AppDataRecord> namespaceRecords = listRecords(metadata.appId(), metadata.namespace());
    long totalBytes = namespaceRecords.stream().mapToLong(AppDataRecord::valueBytes).sum();
    Instant updatedAt = metadata.updatedAt();
    for (AppDataRecord recordSummarySource : namespaceRecords) {
      if (recordSummarySource.updatedAt().isAfter(updatedAt)) {
        updatedAt = recordSummarySource.updatedAt();
      }
    }
    return metadata.withTotals(namespaceRecords.size(), totalBytes, updatedAt);
  }

  private Map<String, AppDataNamespaceMetadata> namespaceMap(String appId) {
    return namespaces.computeIfAbsent(
        AppDataRecord.normalizeAppId(appId), _ -> new LinkedHashMap<>());
  }

  private Map<String, Map<String, AppDataRecord>> recordsForApp(String appId) {
    return records.computeIfAbsent(AppDataRecord.normalizeAppId(appId), _ -> new LinkedHashMap<>());
  }

  private Map<String, AppDataRecord> recordsForNamespace(String appId, String namespace) {
    return recordsForApp(appId)
        .computeIfAbsent(AppDataRecord.normalizeNamespace(namespace), _ -> new LinkedHashMap<>());
  }
}
