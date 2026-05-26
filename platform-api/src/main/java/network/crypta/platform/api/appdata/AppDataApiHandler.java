package network.crypta.platform.api.appdata;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Thin Platform API handler for app-owned durable data routes.
 *
 * <p>This class is the JSON-envelope adapter between {@code PlatformApiAppDataRoutes} and {@link
 * AppDataService}. It does not parse HTTP bodies, authorize capabilities, or choose an app id. The
 * router supplies the already-authenticated app principal id, and every method forwards that id to
 * the service layer as the scope for the requested operation.
 *
 * <p>The handler intentionally stays small. Validation of namespaces, keys, schema versions, import
 * payloads, record sizes, and quota limits lives in {@link AppDataService}, where the same rules
 * apply to router tests and any future non-HTTP caller. The only transformation performed here is
 * wrapping service return values in the stable response key used by the Platform API contract.
 *
 * <p>No method accepts a host filesystem path or a caller-supplied target app id. That keeps route
 * handling aligned with the app-data security model: an app can observe and mutate only its own
 * durable records.
 */
public final class AppDataApiHandler {
  private static final String ENVELOPE_NAMESPACE = "namespace";
  private static final String ENVELOPE_RECORD = "record";

  private final AppDataService service;

  /**
   * Creates a handler around the shared app-data service.
   *
   * <p>The service instance should be the same process-local service used by other app-data routes
   * in the router. Passing {@code null} is rejected immediately so optional service availability is
   * handled by the route family before a handler is constructed.
   *
   * @param service app-data service for the current router and daemon runtime
   */
  public AppDataApiHandler(AppDataService service) {
    this.service = Objects.requireNonNull(service, "service");
  }

  /**
   * Returns status for the calling app.
   *
   * <p>The status response reports counts, bytes, configured limits, and sanitized quota state for
   * the authenticated app. It is a metadata endpoint: it does not include record values, store root
   * paths, staging paths, or host-specific directory names.
   *
   * @param appId authenticated app id from the Platform API principal, not a request parameter
   * @return response envelope containing bounded store and quota status metadata
   */
  public Map<String, Object> status(String appId) {
    return envelope("status", service.status(appId));
  }

  /**
   * Lists namespaces for the calling app.
   *
   * <p>The list includes namespace-level metadata such as schema version, record counts, byte
   * totals, and migration timestamps. It remains a summary endpoint and therefore does not include
   * raw record values or app-provided migration summaries beyond the bounded metadata exposed by
   * the service.
   *
   * @param appId authenticated app id from the Platform API principal, not a request parameter
   * @return response envelope containing namespace metadata summaries for the app
   */
  public Map<String, Object> listNamespaces(String appId) {
    return envelope("namespaces", service.listNamespaces(appId));
  }

  /**
   * Reads one namespace for the calling app.
   *
   * <p>The namespace string is still normalized and validated by the service. Callers receive the
   * stored namespace metadata plus bounded migration history, which is useful for app-side schema
   * upgrades without making the platform execute app migration code.
   *
   * @param appId authenticated app id from the Platform API principal, not a request parameter
   * @param namespace logical namespace segment supplied in the route path
   * @return response envelope containing namespace metadata and bounded migration history
   */
  public Map<String, Object> getNamespace(String appId, String namespace) {
    return envelope(ENVELOPE_NAMESPACE, service.getNamespace(appId, namespace));
  }

  /**
   * Records namespace schema metadata for the calling app.
   *
   * <p>The service records the declared schema transition and summary after validating the version
   * ordering and configured migration-history limit. The platform does not execute transformation
   * code and does not inspect record values for schema compatibility; apps remain responsible for
   * updating their own records before or after calling this endpoint.
   *
   * @param appId authenticated app id from the Platform API principal, not a request parameter
   * @param namespace logical namespace segment supplied in the route path
   * @param parameters decoded form fields for the schema transition metadata
   * @return response envelope containing the updated namespace metadata
   */
  public Map<String, Object> updateSchema(
      String appId, String namespace, Map<String, List<String>> parameters) {
    return envelope(ENVELOPE_NAMESPACE, service.updateSchema(appId, namespace, parameters));
  }

  /**
   * Clears one namespace for the calling app.
   *
   * <p>Clearing a namespace removes its records and metadata within the authenticated app scope.
   * The route-level permission check must require write access before this method is reached; this
   * method preserves the stable response shape for successful deletions.
   *
   * @param appId authenticated app id from the Platform API principal, not a request parameter
   * @param namespace logical namespace segment supplied in the route path
   * @return response envelope containing metadata for the cleared namespace
   */
  public Map<String, Object> deleteNamespace(String appId, String namespace) {
    return envelope(ENVELOPE_NAMESPACE, service.deleteNamespace(appId, namespace));
  }

  /**
   * Lists record summaries for the calling app.
   *
   * <p>Record list responses are intentionally metadata-only. They include keys, content type,
   * schema version, byte count, digest, and timestamps, but never inline values. That lets browser
   * apps build sync and restore UIs without causing summary routes to materialize every stored
   * value.
   *
   * @param appId authenticated app id from the Platform API principal, not a request parameter
   * @param parameters decoded query fields such as namespace, limit, and cursor
   * @return response containing bounded record summaries without raw values
   */
  public Map<String, Object> listRecords(String appId, Map<String, List<String>> parameters) {
    return service.listRecords(appId, parameters);
  }

  /**
   * Reads one record for the calling app.
   *
   * <p>Unlike summary routes, this endpoint returns the stored value for one normalized
   * namespace/key pair. The service enforces configured value-size bounds and integrity checks
   * before returning the value representation to the owning app.
   *
   * @param appId authenticated app id from the Platform API principal, not a request parameter
   * @param namespace logical namespace segment supplied in the route path
   * @param key logical record key supplied in the route path
   * @return response envelope containing record metadata plus the bounded value
   */
  public Map<String, Object> getRecord(String appId, String namespace, String key) {
    return envelope(ENVELOPE_RECORD, service.getRecord(appId, namespace, key));
  }

  /**
   * Creates or replaces one record for the calling app.
   *
   * <p>Writes accept decoded form/query parameters from the router and delegate all value parsing
   * to the service. The service accepts text, JSON, or base64 input, applies per-record and total
   * quota checks, and performs the store write before this method wraps the committed record.
   *
   * @param appId authenticated app id from the Platform API principal, not a request parameter
   * @param parameters decoded form fields for namespace, key, schema, type, value, and precondition
   * @return response envelope containing the committed record metadata and value
   */
  public Map<String, Object> putRecord(String appId, Map<String, List<String>> parameters) {
    return envelope(ENVELOPE_RECORD, service.putRecord(appId, parameters));
  }

  /**
   * Deletes one record for the calling app.
   *
   * <p>Deleting a record is scoped to the authenticated app and updates namespace metadata through
   * the service. Missing records are reported by the service using the app-data error vocabulary
   * rather than by leaking store layout details.
   *
   * @param appId authenticated app id from the Platform API principal, not a request parameter
   * @param namespace logical namespace segment supplied in the route path
   * @param key logical record key supplied in the route path
   * @return response envelope containing deletion metadata
   */
  public Map<String, Object> deleteRecord(String appId, String namespace, String key) {
    return envelope(ENVELOPE_RECORD, service.deleteRecord(appId, namespace, key));
  }

  /**
   * Exports bounded app data for the calling app.
   *
   * <p>Exports are intended for backup, restore, and app-version migration workflows. The service
   * preflights the projected serialized size and returns a structured payload containing metadata
   * plus base64 values only for the authenticated app.
   *
   * @param appId authenticated app id from the Platform API principal, not a request parameter
   * @param parameters decoded query fields such as namespace and export format
   * @return response envelope containing the structured export payload
   */
  public Map<String, Object> exportData(String appId, Map<String, List<String>> parameters) {
    return envelope("export", service.exportData(appId, parameters));
  }

  /**
   * Imports bounded app data for the calling app.
   *
   * <p>Imports accept the structured payload produced by the export endpoint, subject to configured
   * import-size, quota, namespace, record-count, and migration-history bounds. Payloads that name a
   * different app id are rejected by the service before any write is committed.
   *
   * @param appId authenticated app id from the Platform API principal, not a request parameter
   * @param parameters decoded form fields containing payload and import mode
   * @return response envelope containing the import result summary
   */
  public Map<String, Object> importData(String appId, Map<String, List<String>> parameters) {
    return envelope("import", service.importData(appId, parameters));
  }

  private static Map<String, Object> envelope(String key, Object value) {
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put(key, value);
    return envelope;
  }
}
