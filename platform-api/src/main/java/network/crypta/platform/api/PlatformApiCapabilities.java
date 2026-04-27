package network.crypta.platform.api;

import java.util.List;
import java.util.Set;

/**
 * Central app-principal capability matrix for Platform API v1.
 *
 * <p>Host/operator requests bypass this matrix to preserve the existing local-management model. App
 * principals are default-deny: a request must match one of the route rules below and the app
 * principal must carry every required manifest permission.
 *
 * <p>The matrix is intentionally explicit instead of reflection- or annotation-driven. Each helper
 * mirrors one top-level endpoint family so reviewers can see which routes grant read access and
 * which routes require write or manage authority. Unrecognized methods, unsupported sub-routes, and
 * malformed route shapes return no action and are denied for app principals before endpoint
 * dispatch.
 */
final class PlatformApiCapabilities {
  /** Manifest permission that allows app principals to read node identity and status endpoints. */
  static final String NODE_READ = "node.read";

  /** Manifest permission that allows app principals to read connectivity diagnostics. */
  static final String CONNECTIVITY_READ = "connectivity.read";

  /** Manifest permission that allows app principals to read queue pages and completion state. */
  static final String QUEUE_READ = "queue.read";

  /** Manifest permission that allows app principals to mutate existing queue entries. */
  static final String QUEUE_WRITE = "queue.write";

  /** Manifest permission that allows app principals to create local file or directory inserts. */
  static final String CONTENT_INSERT = "content.insert";

  /** Manifest permission that allows app principals to read peer summaries and peer details. */
  static final String PEERS_READ = "peers.read";

  /** Manifest permission that allows app principals to add, update, annotate, or remove peers. */
  static final String PEERS_WRITE = "peers.write";

  /** Manifest permission that allows app principals to read configuration projections. */
  static final String CONFIG_READ = "config.read";

  /** Manifest permission that allows app principals to change or persist configuration values. */
  static final String CONFIG_WRITE = "config.write";

  /** Manifest permission that allows app principals to read security-level state. */
  static final String SECURITY_READ = "security.read";

  /** Manifest permission that allows app principals to change security-level settings. */
  static final String SECURITY_WRITE = "security.write";

  /** Manifest permission that allows app principals to read core update state. */
  static final String UPDATES_READ = "updates.read";

  /** Manifest permission that allows app principals to trigger core update actions. */
  static final String UPDATES_WRITE = "updates.write";

  /** Manifest permission that allows app principals to read first-time wizard state. */
  static final String WIZARD_READ = "wizard.read";

  /** Manifest permission that allows app principals to submit first-time wizard choices. */
  static final String WIZARD_WRITE = "wizard.write";

  /** Manifest permission that allows app principals to read current runtime alerts. */
  static final String ALERTS_READ = "alerts.read";

  /** Manifest permission that allows app principals to dismiss operator-visible alerts. */
  static final String ALERTS_WRITE = "alerts.write";

  /** Manifest permission that allows app principals to read runtime diagnostic summaries. */
  static final String DIAGNOSTICS_READ = "diagnostics.read";

  /** Manifest permission that allows app principals to read installed app summaries. */
  static final String APPS_READ = "apps.read";

  /**
   * Manifest permission that allows app principals to install, update, start, stop, or remove apps.
   */
  static final String APPS_MANAGE = "apps.manage";

  /**
   * Manifest permission that allows app principals to read signed app-catalog sources and entries.
   */
  static final String CATALOGS_READ = "catalogs.read";

  /** Manifest permission that allows app principals to add, refresh, or install from catalogs. */
  static final String CATALOGS_MANAGE = "catalogs.manage";

  private static final String FAMILY_ALERTS = "alerts";
  private static final String FAMILY_APP_CATALOGS = "app-catalogs";
  private static final String FAMILY_APPS = "apps";
  private static final String FAMILY_CONFIG = "config";
  private static final String FAMILY_PEERS = "peers";
  private static final String FAMILY_QUEUE = "queue";
  private static final String FAMILY_SECURITY_LEVELS = "security-levels";
  private static final String FAMILY_UPDATES = "updates";
  private static final String FAMILY_WIZARD = "wizard";

  /** Prevents construction of this stateless capability-mapping utility. */
  private PlatformApiCapabilities() {}

  /**
   * Authorizes one transport-neutral Platform API request.
   *
   * <p>Host/operator principals are allowed immediately because the HTTP bridge has already
   * enforced the legacy local management checks. App principals must match a route rule and must
   * contain every capability required by that action. Unsupported app routes are denied with an
   * unmapped action so the audit log can still record which endpoint family was attempted.
   *
   * @param request request metadata with an already established principal
   * @return capability decision used by the router before endpoint dispatch
   */
  static PlatformApiAuthorizationDecision authorize(PlatformApiRequest request) {
    if (!request.principal().isApp()) {
      return PlatformApiAuthorizationDecision.hostAllowed();
    }

    PlatformApiAction action = actionFor(request);
    if (action == null) {
      return PlatformApiAuthorizationDecision.denied(unknownAction(request), "unmapped_route");
    }
    Set<String> permissions = Set.copyOf(request.principal().permissions());
    if (permissions.containsAll(action.requiredCapabilities())) {
      return PlatformApiAuthorizationDecision.allowed(action);
    }
    return PlatformApiAuthorizationDecision.denied(action, "missing_capability");
  }

  /**
   * Resolves the route/action descriptor for one request.
   *
   * <p>The first path segment selects the endpoint family. Each family helper is responsible for
   * checking method and route shape. Returning {@code null} is deliberate: app principals treat
   * every unmatched route as default-deny rather than falling through to handler-level 404 or 405
   * responses.
   *
   * @param request request metadata whose path is relative to the Platform API v1 prefix
   * @return matched action descriptor, or {@code null} when no app capability rule applies
   */
  private static PlatformApiAction actionFor(PlatformApiRequest request) {
    List<String> segments = request.pathSegments();
    if (segments.isEmpty()) {
      return null;
    }
    String family = segments.getFirst();
    String method = request.method();
    return switch (family) {
      case "node" -> nodeAction(method, segments);
      case "connectivity" ->
          exactGet(method, family, CONNECTIVITY_READ, CONNECTIVITY_READ, segments.size() == 1);
      case "diagnostics" ->
          exactGet(method, family, DIAGNOSTICS_READ, DIAGNOSTICS_READ, segments.size() == 1);
      case FAMILY_ALERTS -> alertsAction(method, segments);
      case FAMILY_CONFIG -> configAction(method, segments);
      case FAMILY_SECURITY_LEVELS -> securityAction(method, segments);
      case FAMILY_UPDATES -> updatesAction(method, segments);
      case FAMILY_WIZARD -> wizardAction(method, segments);
      case FAMILY_QUEUE -> queueAction(method, segments);
      case FAMILY_PEERS -> peersAction(method, segments);
      case FAMILY_APPS -> appsAction(method, segments);
      case FAMILY_APP_CATALOGS -> catalogsAction(method, segments);
      default -> null;
    };
  }

  /**
   * Maps the node identity and reference reads.
   *
   * <p>The router exposes only named node read resources, not a generic node subtree. Unsupported
   * child paths therefore stay unmapped for app principals.
   *
   * @param method normalized HTTP-style method name
   * @param segments decoded route segments beneath the API v1 prefix
   * @return matched node read action, or {@code null} for unsupported node routes
   */
  private static PlatformApiAction nodeAction(String method, List<String> segments) {
    return exactGet(
        method,
        "node",
        NODE_READ,
        NODE_READ,
        segments.size() == 2
            && ("greeting".equals(segments.get(1)) || "reference".equals(segments.get(1))));
  }

  /**
   * Maps alert feed and dismissal routes.
   *
   * <p>All alert reads require {@link #ALERTS_READ}. The only current alert mutation exposed
   * through Platform API v1 is dismissal, which requires {@link #ALERTS_WRITE}.
   *
   * @param method normalized HTTP-style method name
   * @param segments decoded route segments beneath the API v1 prefix
   * @return matched alerts action, or {@code null} for unsupported alert routes
   */
  private static PlatformApiAction alertsAction(String method, List<String> segments) {
    if ("GET".equals(method) && segments.size() == 1) {
      return action(FAMILY_ALERTS, ALERTS_READ, ALERTS_READ);
    }
    if ("POST".equals(method) && segments.size() == 3 && "dismiss".equals(segments.get(2))) {
      return action(FAMILY_ALERTS, "alerts.dismiss", ALERTS_WRITE);
    }
    return null;
  }

  /**
   * Maps configuration read and write routes.
   *
   * <p>The root configuration export requires {@link #CONFIG_READ}. Writes are limited to the
   * explicit override and persist endpoints and require {@link #CONFIG_WRITE}; unsupported shapes
   * remain unmapped for app principals.
   *
   * @param method normalized HTTP-style method name
   * @param segments decoded route segments beneath the API v1 prefix
   * @return matched configuration action, or {@code null} for unsupported config routes
   */
  private static PlatformApiAction configAction(String method, List<String> segments) {
    if ("GET".equals(method) && segments.size() == 1) {
      return action(FAMILY_CONFIG, CONFIG_READ, CONFIG_READ);
    }
    if ("POST".equals(method)
        && segments.size() == 2
        && ("overrides".equals(segments.get(1)) || "persist".equals(segments.get(1)))) {
      return action(FAMILY_CONFIG, "config." + segments.get(1), CONFIG_WRITE);
    }
    return null;
  }

  /**
   * Maps security-level read and mutation routes.
   *
   * <p>Security-level reads require {@link #SECURITY_READ}. Mutations are restricted to the network
   * and physical threat-level endpoints and require {@link #SECURITY_WRITE}. Keeping every allowed
   * route name explicit avoids granting future security routes by accident.
   *
   * @param method normalized HTTP-style method name
   * @param segments decoded route segments beneath the API v1 prefix
   * @return matched security action, or {@code null} for unsupported security routes
   */
  private static PlatformApiAction securityAction(String method, List<String> segments) {
    if ("GET".equals(method)) {
      return securityReadAction(segments);
    }
    if ("POST".equals(method)
        && segments.size() == 2
        && ("network".equals(segments.get(1)) || "physical".equals(segments.get(1)))) {
      return action(FAMILY_SECURITY_LEVELS, "security." + segments.get(1), SECURITY_WRITE);
    }
    return null;
  }

  private static PlatformApiAction securityReadAction(List<String> segments) {
    if (segments.size() == 1) {
      return action(FAMILY_SECURITY_LEVELS, SECURITY_READ, SECURITY_READ);
    }
    if (segments.size() == 2 && "network-warning".equals(segments.get(1))) {
      return action(FAMILY_SECURITY_LEVELS, "security.network-warning", SECURITY_READ);
    }
    return null;
  }

  /**
   * Maps core update read and trigger routes.
   *
   * <p>Update status reads require {@link #UPDATES_READ}. The current write surface is the core
   * package download trigger, which requires {@link #UPDATES_WRITE}. Other updater operations stay
   * host/operator-only until they are deliberately added to this matrix.
   *
   * @param method normalized HTTP-style method name
   * @param segments decoded route segments beneath the API v1 prefix
   * @return matched updater action, or {@code null} for unsupported updater routes
   */
  private static PlatformApiAction updatesAction(String method, List<String> segments) {
    if ("GET".equals(method) && segments.size() == 2 && "core".equals(segments.get(1))) {
      return action(FAMILY_UPDATES, UPDATES_READ, UPDATES_READ);
    }
    if ("POST".equals(method)
        && segments.size() == 3
        && "core".equals(segments.get(1))
        && "download".equals(segments.get(2))) {
      return action(FAMILY_UPDATES, "updates.core.download", UPDATES_WRITE);
    }
    return null;
  }

  /**
   * Maps first-time wizard read and apply routes.
   *
   * <p>Wizard reads require {@link #WIZARD_READ}. Applying submitted wizard choices is the only
   * mapped mutation and requires {@link #WIZARD_WRITE}. The path check includes the {@code
   * first-time} segment so future wizard families do not inherit this permission accidentally.
   *
   * @param method normalized HTTP-style method name
   * @param segments decoded route segments beneath the API v1 prefix
   * @return matched wizard action, or {@code null} for unsupported wizard routes
   */
  private static PlatformApiAction wizardAction(String method, List<String> segments) {
    if ("GET".equals(method) && segments.size() == 2 && "first-time".equals(segments.get(1))) {
      return action(FAMILY_WIZARD, WIZARD_READ, WIZARD_READ);
    }
    if ("POST".equals(method)
        && segments.size() == 3
        && "first-time".equals(segments.get(1))
        && "apply".equals(segments.get(2))) {
      return action(FAMILY_WIZARD, "wizard.first-time.apply", WIZARD_WRITE);
    }
    return null;
  }

  /**
   * Maps queue read, download, insert, cleanup, and request-control routes.
   *
   * <p>Queue reads require {@link #QUEUE_READ}. Mutations that operate on existing requests require
   * {@link #QUEUE_WRITE}. Insert creation is stricter because it can publish local content, so file
   * and directory insert routes require both {@link #CONTENT_INSERT} and {@link #QUEUE_WRITE}.
   *
   * @param method normalized HTTP-style method name
   * @param segments decoded route segments beneath the API v1 prefix
   * @return matched queue action, or {@code null} for unsupported queue routes
   */
  private static PlatformApiAction queueAction(String method, List<String> segments) {
    if ("GET".equals(method)) {
      return queueReadAction(segments);
    }
    if (!"POST".equals(method)) {
      return null;
    }
    if (segments.size() == 2 && "downloads".equals(segments.get(1))) {
      return action(FAMILY_QUEUE, "queue.downloads.create", QUEUE_WRITE);
    }
    if (segments.size() != 3) {
      return null;
    }
    String resource = segments.get(1);
    String action = segments.get(2);
    if ("inserts".equals(resource) && ("file".equals(action) || "directory".equals(action))) {
      return queueInsertAction("queue.inserts." + action);
    }
    if ("requests".equals(resource)
        && ("remove".equals(action) || "restart".equals(action) || "priority".equals(action))) {
      return action(FAMILY_QUEUE, "queue.requests." + action, QUEUE_WRITE);
    }
    if ("cleanup".equals(resource) && ("uploads".equals(action) || "downloads".equals(action))) {
      return action(FAMILY_QUEUE, "queue.cleanup." + action, QUEUE_WRITE);
    }
    return null;
  }

  /**
   * Maps explicit read-only queue routes.
   *
   * <p>The queue family also contains mutation-shaped resources such as {@code requests/remove} and
   * creation resources such as {@code downloads}. Those routes are not valid GET reads, so app
   * principals must not receive a blanket {@code queue.read} grant for every queue path.
   *
   * @param segments decoded route segments beneath the API v1 prefix
   * @return queue read action for supported read shapes, or {@code null} for unsupported routes
   */
  private static PlatformApiAction queueReadAction(List<String> segments) {
    if (segments.size() == 1
        || (segments.size() == 2
            && ("count".equals(segments.get(1)) || "keys".equals(segments.get(1))))) {
      return action(FAMILY_QUEUE, QUEUE_READ, QUEUE_READ);
    }
    return null;
  }

  /**
   * Maps peer read and peer-management routes.
   *
   * <p>Peer reads require {@link #PEERS_READ}. Adding peers and changing an existing peer's
   * settings, note, or removal state require {@link #PEERS_WRITE}. The helper intentionally checks
   * exact terminal route names because peer identifiers occupy the middle segment.
   *
   * @param method normalized HTTP-style method name
   * @param segments decoded route segments beneath the API v1 prefix
   * @return matched peer action, or {@code null} for unsupported peer routes
   */
  private static PlatformApiAction peersAction(String method, List<String> segments) {
    if ("GET".equals(method) && (segments.size() == 1 || segments.size() == 2)) {
      return action(FAMILY_PEERS, PEERS_READ, PEERS_READ);
    }
    if ("POST".equals(method) && segments.size() == 2 && "add".equals(segments.get(1))) {
      return action(FAMILY_PEERS, "peers.add", PEERS_WRITE);
    }
    if ("POST".equals(method)
        && segments.size() == 3
        && ("settings".equals(segments.get(2))
            || "note".equals(segments.get(2))
            || "remove".equals(segments.get(2)))) {
      return action(FAMILY_PEERS, "peers." + segments.get(2), PEERS_WRITE);
    }
    return null;
  }

  /**
   * Maps installed-app inventory and lifecycle routes.
   *
   * <p>Reading app summaries, permissions, audit entries, logs, and runtime state all fall under
   * {@link #APPS_READ}. Lifecycle and installation actions require {@link #APPS_MANAGE}. This route
   * family is powerful because it can affect other apps, so new mutations should be added here only
   * when they are intended for app principals.
   *
   * @param method normalized HTTP-style method name
   * @param segments decoded route segments beneath the API v1 prefix
   * @return matched app-management action, or {@code null} for unsupported app routes
   */
  private static PlatformApiAction appsAction(String method, List<String> segments) {
    if ("GET".equals(method)) {
      return appsReadAction(segments);
    }
    if ("DELETE".equals(method) && segments.size() == 2) {
      return action(FAMILY_APPS, "apps.uninstall", APPS_MANAGE);
    }
    if (!"POST".equals(method)) {
      return null;
    }
    if (segments.size() == 2 && "install".equals(segments.get(1))) {
      return action(FAMILY_APPS, "apps.install", APPS_MANAGE);
    }
    if (segments.size() == 3
        && ("start".equals(segments.get(2))
            || "stop".equals(segments.get(2))
            || "update".equals(segments.get(2)))) {
      return action(FAMILY_APPS, "apps." + segments.get(2), APPS_MANAGE);
    }
    return null;
  }

  /**
   * Maps explicit read-only app routes.
   *
   * <p>GET is deliberately not treated as a blanket grant for {@code /apps/**}. Lifecycle action
   * names such as {@code start} and unsupported child resources must stay unmapped for app
   * principals so the router records a default-deny authorization decision instead of allowing the
   * request to reach handler-level 404 or 405 handling.
   *
   * @param segments decoded route segments beneath the API v1 prefix
   * @return app read action for supported read shapes, or {@code null} for unsupported routes
   */
  private static PlatformApiAction appsReadAction(List<String> segments) {
    if (segments.size() == 1 || segments.size() == 2) {
      return action(FAMILY_APPS, APPS_READ, APPS_READ);
    }
    if (segments.size() == 3
        && ("runtime".equals(segments.get(2))
            || "logs".equals(segments.get(2))
            || "permissions".equals(segments.get(2))
            || "audit".equals(segments.get(2)))) {
      return action(FAMILY_APPS, APPS_READ, APPS_READ);
    }
    return null;
  }

  /**
   * Maps signed app-catalog read and management routes.
   *
   * <p>Catalog source and entry reads require {@link #CATALOGS_READ}. Adding, refreshing, removing,
   * installing from, or updating from a catalog requires {@link #CATALOGS_MANAGE}. The installation
   * and update route shape includes both catalog id and app id, so this helper checks the fixed
   * structural segments and ignores identifier values.
   *
   * @param method normalized HTTP-style method name
   * @param segments decoded route segments beneath the API v1 prefix
   * @return matched catalog action, or {@code null} for unsupported catalog routes
   */
  private static PlatformApiAction catalogsAction(String method, List<String> segments) {
    if ("GET".equals(method)) {
      return catalogsReadAction(segments);
    }
    if ("DELETE".equals(method) && segments.size() == 2) {
      return action(FAMILY_APP_CATALOGS, "catalogs.remove", CATALOGS_MANAGE);
    }
    if (!"POST".equals(method)) {
      return null;
    }
    if (segments.size() == 2 && "add".equals(segments.get(1))) {
      return action(FAMILY_APP_CATALOGS, "catalogs.add", CATALOGS_MANAGE);
    }
    if (segments.size() == 3 && "refresh".equals(segments.get(2))) {
      return action(FAMILY_APP_CATALOGS, "catalogs.refresh", CATALOGS_MANAGE);
    }
    if (segments.size() == 5
        && "apps".equals(segments.get(2))
        && ("install".equals(segments.get(4)) || "update".equals(segments.get(4)))) {
      return action(FAMILY_APP_CATALOGS, "catalogs.apps." + segments.get(4), CATALOGS_MANAGE);
    }
    return null;
  }

  /**
   * Maps explicit read-only app-catalog routes.
   *
   * <p>The catalog family has management resources such as {@code /app-catalogs/{catalogId}} and
   * action resources such as {@code refresh}. Those are not valid GET reads in the router, so app
   * principals must not receive a blanket {@code catalogs.read} grant for every catalog path.
   *
   * @param segments decoded route segments beneath the API v1 prefix
   * @return catalog read action for supported read shapes, or {@code null} for unsupported routes
   */
  private static PlatformApiAction catalogsReadAction(List<String> segments) {
    if (segments.size() == 1 || isCatalogAppRead(segments)) {
      return action(FAMILY_APP_CATALOGS, CATALOGS_READ, CATALOGS_READ);
    }
    return null;
  }

  private static boolean isCatalogAppRead(List<String> segments) {
    return (segments.size() == 3 || segments.size() == 4) && "apps".equals(segments.get(2));
  }

  /**
   * Builds an action only when the request method is {@code GET} and the route shape is supported.
   *
   * <p>Read-only endpoint families use this helper after checking the exact route shape.
   * Unsupported methods or shapes return {@code null} so app principals are denied before dispatch
   * rather than reaching a handler-level method or not-found check.
   *
   * @param method normalized HTTP-style method name
   * @param endpointFamily top-level endpoint family used in audit output
   * @param label deterministic action label used in audit output
   * @param capability single required manifest capability
   * @param routeMatches whether the request path is one supported read route
   * @return read action for supported {@code GET} routes, or {@code null} otherwise
   */
  private static PlatformApiAction exactGet(
      String method, String endpointFamily, String label, String capability, boolean routeMatches) {
    return "GET".equals(method) && routeMatches ? action(endpointFamily, label, capability) : null;
  }

  /**
   * Builds an action requiring one capability.
   *
   * @param endpointFamily top-level endpoint family used in audit output
   * @param label deterministic action label used in audit output
   * @param capability required manifest capability for the action
   * @return action descriptor with one required capability
   */
  private static PlatformApiAction action(String endpointFamily, String label, String capability) {
    return PlatformApiAction.of(endpointFamily, label, List.of(capability));
  }

  /**
   * Builds the action for queue insert routes.
   *
   * <p>Queue inserts are intentionally stricter than ordinary queue mutations: a manifest must
   * grant both permission to insert content and permission to mutate the local queue. Keeping the
   * fixed family and capability pair here makes that policy visible at the route helper boundary
   * while the action record still sorts the capabilities for deterministic audit output.
   *
   * @param label deterministic queue insert action label used in audit output
   * @return action descriptor requiring both content insertion and queue mutation capabilities
   */
  private static PlatformApiAction queueInsertAction(String label) {
    return PlatformApiAction.of(FAMILY_QUEUE, label, List.of(CONTENT_INSERT, QUEUE_WRITE));
  }

  /**
   * Builds the synthetic action used for default-deny app routes.
   *
   * <p>The returned action is not grantable by a normal manifest permission. Its purpose is to
   * provide audit entries with an endpoint family and an {@code unmapped} capability label when an
   * app principal attempts a route that the matrix does not intentionally expose.
   *
   * @param request request whose first path segment identifies the attempted endpoint family
   * @return synthetic unmapped action for denied app-principal audit events
   */
  private static PlatformApiAction unknownAction(PlatformApiRequest request) {
    List<String> segments = request.pathSegments();
    String endpointFamily = segments.isEmpty() ? "unknown" : segments.getFirst();
    String label = segments.isEmpty() ? "unmapped" : endpointFamily + ".unmapped";
    return PlatformApiAction.of(endpointFamily, label, List.of("unmapped"));
  }
}
