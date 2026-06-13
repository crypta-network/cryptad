package network.crypta.platform.api.networkbudget;

import java.util.Locale;
import java.util.Objects;

/**
 * Network-initiating app operations covered by the shared app-network budget service.
 *
 * <p>The JSON values are the stable labels used in durable budget metadata and tests. They are
 * intentionally small, path-safe tokens and never include content URIs, request bodies, source
 * labels, app-data keys, queue details, tokens, signatures, or local filesystem paths.
 *
 * <p>Most values describe the caller-visible operation that requested network work. A few values
 * are internal aggregate counters used by the service to make related operations share capacity.
 * For example, subscription polls and Trust Graph import-by-URI also charge the global
 * content-fetch family so they cannot bypass foreground fetch limits.
 */
public enum AppNetworkBudgetOperation {
  /**
   * Foreground app request through {@code POST /api/v1/content/fetch}.
   *
   * <p>This operation covers app-initiated bounded content fetches after source validation and
   * before the runtime content-fetch port is called. It charges both per-app foreground fetch
   * limits and the global content-fetch family.
   */
  FOREGROUND_CONTENT_FETCH("foreground_content_fetch"),

  /**
   * Scheduler-delegated poll of one app-owned content subscription.
   *
   * <p>The scheduler uses this value only after queue pressure permits polling. It charges the
   * subscription budget family and the global content-fetch family, so scheduled polls stay bounded
   * by both app subscription policy and node-wide fetch capacity.
   */
  SUBSCRIPTION_POLL("subscription_poll"),

  /**
   * Manual app refresh of one content subscription.
   *
   * <p>Manual refreshes share subscription counters with scheduled polls. This keeps refresh
   * buttons and scripted app calls from becoming a separate network path with higher capacity than
   * the scheduler.
   */
  SUBSCRIPTION_MANUAL_REFRESH("subscription_manual_refresh"),

  /**
   * Direct import of one Trust Graph statement document.
   *
   * <p>This operation covers local import of a supplied statement body. It does not charge the
   * content-fetch family because the statement has already arrived at the Platform API boundary,
   * but it still uses Trust Graph import rate and concurrency limits.
   */
  TRUST_GRAPH_IMPORT("trust_graph_import"),

  /**
   * Content-fetch portion of Trust Graph import by URI.
   *
   * <p>Trust Graph import-by-URI first performs a non-consuming Trust Graph import precheck, then
   * charges this value for the bounded content fetch, and finally acquires the real Trust Graph
   * import lease before parsing/importing the fetched statement. The service maps this value onto
   * content-fetch counters rather than maintaining an independent URI-import fetch quota.
   */
  TRUST_GRAPH_IMPORT_URI("trust_graph_import_uri"),

  /**
   * Internal shared global content-fetch family counter.
   *
   * <p>This value is not requested directly by app route handlers. It is persisted under the
   * reserved global budget scope to account for foreground fetches, subscription polls, manual
   * subscription refreshes, and Trust Graph import-by-URI fetches as one bounded family.
   */
  CONTENT_FETCH_GLOBAL("content_fetch_global");

  private final String jsonValue;

  AppNetworkBudgetOperation(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable durable label for this operation.
   *
   * <p>The returned value is safe to use as a metadata token or filename stem. It is intentionally
   * not derived from app input, request URIs, source labels, or route paths, which keeps durable
   * budget records redacted and migration-friendly.
   *
   * @return path-safe operation label used in budget metadata
   */
  public String jsonValue() {
    return jsonValue;
  }

  static AppNetworkBudgetOperation fromJsonValue(String value) {
    String normalized = Objects.requireNonNull(value, "value").trim().toLowerCase(Locale.ROOT);
    for (AppNetworkBudgetOperation operation : values()) {
      if (operation.jsonValue.equals(normalized)) {
        return operation;
      }
    }
    throw new IllegalArgumentException("unknown app network budget operation");
  }
}
