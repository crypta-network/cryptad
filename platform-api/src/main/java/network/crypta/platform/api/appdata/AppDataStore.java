package network.crypta.platform.api.appdata;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * Minimal persistence contract for app-scoped durable data records.
 *
 * <p>Implementations scope every operation by normalized app id and never accept host filesystem
 * paths from app requests. The contract is deliberately small: service code owns validation,
 * quotas, export/import semantics, and schema policy, while stores own durable read/write/delete
 * mechanics and path safety for their backing medium.
 *
 * <p>Callers should treat {@link IOException} as a store availability failure, not as a missing
 * record. Implementations may ignore corrupt or semantically invalid metadata only when they can do
 * so without hiding an I/O failure. They must not include root paths, temporary file names, symlink
 * targets, or host configuration details in exception messages that can surface through API error
 * handling.
 *
 * <p>The interface supports both value-bearing and summary-only read paths. Summary paths are
 * important for status, namespace listing, quota preflight, and record-list routes because those
 * operations should remain bounded by metadata even when an app owns many valid records.
 */
public interface AppDataStore {
  /**
   * Lists app ids with durable app-data state known to this store.
   *
   * <p>The result is intended for host/operator backup flows, not app-principal routing. Store
   * implementations should discover only ids that are safely contained by their managed app-data
   * scope, skip malformed or unsafe entries, and keep the output sorted deterministically. Missing
   * app-data roots should return an empty list rather than creating state.
   *
   * @return normalized app ids with known durable app-data state
   * @throws IOException when durable state cannot be inspected
   */
  List<String> listAppIds() throws IOException;

  /**
   * Lists namespace metadata for one app.
   *
   * <p>The returned metadata should include derived record counts and byte totals when the backing
   * store can compute them cheaply. The service may sort or derive additional values, but store
   * implementations should keep their own output deterministic for tests and evidence collectors.
   *
   * @param appId normalized owner app id
   * @return namespace metadata sorted deterministically
   * @throws IOException when durable state cannot be inspected
   */
  List<AppDataNamespaceMetadata> listNamespaces(String appId) throws IOException;

  /**
   * Reads one namespace metadata record.
   *
   * <p>Missing metadata returns {@link Optional#empty()}. Permission errors, transient read errors,
   * and incomplete durable state should be reported as {@link IOException} so callers do not
   * mistake an outage for a deleted namespace.
   *
   * @param appId normalized owner app id
   * @param namespace normalized namespace label
   * @return metadata when the namespace exists
   * @throws IOException when durable state cannot be inspected
   */
  Optional<AppDataNamespaceMetadata> readNamespace(String appId, String namespace)
      throws IOException;

  /**
   * Writes namespace metadata.
   *
   * <p>Implementations should make metadata updates durable enough for local app state before the
   * method returns. File-backed implementations should write through a temporary file in the same
   * directory and publish the new metadata atomically where the platform supports it.
   *
   * @param metadata metadata to persist for its normalized app and namespace
   * @throws IOException when durable state cannot be written
   */
  void writeNamespace(AppDataNamespaceMetadata metadata) throws IOException;

  /**
   * Lists records for an app, optionally constrained to a namespace.
   *
   * <p>This method returns full records and therefore may read value bytes. Summary callers should
   * use {@link #listRecordSummaries(String, String)} so large valid stores do not force unnecessary
   * value allocation.
   *
   * @param appId normalized owner app id
   * @param namespace normalized namespace label, or {@code null} for all namespaces
   * @return records sorted deterministically
   * @throws IOException when durable state cannot be inspected
   */
  List<AppDataRecord> listRecords(String appId, String namespace) throws IOException;

  /**
   * Lists record summaries for an app without requiring callers to materialize record values.
   *
   * <p>File-backed stores should override this method with metadata-only reads so status, namespace
   * totals, quota checks, and paged record-list routes remain bounded by metadata rather than total
   * value bytes. The default implementation preserves compatibility for simple stores.
   *
   * @param appId normalized owner app id
   * @param namespace normalized namespace label, or {@code null} for all namespaces
   * @return record summaries sorted deterministically
   * @throws IOException when durable state cannot be inspected
   */
  default List<AppDataRecordSummary> listRecordSummaries(String appId, String namespace)
      throws IOException {
    return listRecords(appId, namespace).stream()
        .map(AppDataRecordSummary::from)
        .sorted(
            Comparator.comparing(AppDataRecordSummary::namespace)
                .thenComparing(AppDataRecordSummary::key))
        .toList();
  }

  /**
   * Reads one app-owned record.
   *
   * <p>Implementations must enforce their configured record-size bounds before loading a value into
   * memory. If metadata claims a value exists but the value cannot be read or validated, report
   * {@link IOException} rather than treating the record as absent.
   *
   * @param appId normalized owner app id
   * @param namespace normalized namespace label
   * @param key normalized logical record key
   * @return record when present
   * @throws IOException when durable state cannot be inspected
   */
  Optional<AppDataRecord> readRecord(String appId, String namespace, String key) throws IOException;

  /**
   * Creates or replaces one durable app-owned record.
   *
   * <p>Stores receive records only after service-level quota and precondition checks pass. The
   * store is still responsible for crash-safe publication of value bytes and metadata so readers
   * never observe a partially committed record as successful.
   *
   * @param appDataRecord record to persist under its normalized app, namespace, and key
   * @throws IOException when durable state cannot be written
   */
  void writeRecord(AppDataRecord appDataRecord) throws IOException;

  /**
   * Deletes one app-owned record.
   *
   * <p>Deleting a missing record should return {@code false}. Deletion errors should propagate as
   * {@link IOException}, and implementations must keep deletion scoped to the managed app-data tree
   * or equivalent backing store namespace.
   *
   * @param appId normalized owner app id
   * @param namespace normalized namespace label
   * @param key normalized logical record key
   * @return {@code true} when a record was removed
   * @throws IOException when durable state cannot be mutated
   */
  boolean deleteRecord(String appId, String namespace, String key) throws IOException;

  /**
   * Deletes all records and metadata for one namespace.
   *
   * <p>This operation is used for app-requested namespace cleanup and replace-import workflows. It
   * must not follow caller-controlled paths or escape the app's store scope.
   *
   * @param appId normalized owner app id
   * @param namespace normalized namespace label
   * @throws IOException when durable state cannot be mutated
   */
  void deleteNamespace(String appId, String namespace) throws IOException;

  /**
   * Deletes all durable app-data state for one app.
   *
   * <p>This operation supports uninstall cleanup when the operator chooses not to preserve app
   * data. Implementations should remove only state owned by the normalized app id.
   *
   * @param appId normalized owner app id
   * @throws IOException when durable state cannot be mutated
   */
  void deleteAllForApp(String appId) throws IOException;
}
