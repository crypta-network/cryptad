package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import network.crypta.platform.api.alerts.AlertsApiHandler;
import network.crypta.platform.api.connectivity.ConnectivityApiHandler;
import network.crypta.platform.api.diagnostics.DiagnosticsApiHandler;
import network.crypta.platform.api.node.NodeApiHandler;
import network.crypta.platform.api.updates.UpdatesApiHandler;
import network.crypta.platform.api.wizard.FirstTimeWizardApiHandler;
import network.crypta.runtime.spi.LegacyAdminUsagePort;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Routes daemon-operational Platform API endpoint families.
 *
 * <p>These routes report and mutate local node operational state rather than app-owned state:
 * {@code /node}, {@code /connectivity}, {@code /diagnostics}, {@code /updates}, {@code /wizard},
 * and {@code /alerts}. Keeping them together gives the top-level router one cohesive operational
 * collaborator while leaving app, content, data, service, queue, peer, config, security-level, and
 * Trust Graph routes in their existing specialized branches.
 *
 * <p>The class is intentionally transport-neutral. It receives already-decoded Platform API
 * requests, performs only method/path dispatch, and delegates all runtime-specific behavior to the
 * detached handler classes created from {@link RuntimePorts}.
 */
final class PlatformApiOperationalRoutes {
  /** Shared method token for routes that read operational state. */
  private static final String METHOD_GET = "GET";

  /** Shared method token for routes that mutate operational state. */
  private static final String METHOD_POST = "POST";

  /** Shared 405 message for routes that only support GET. */
  private static final String GET_ONLY_MESSAGE = "Platform API v1 supports GET requests only.";

  /** Shared 405 message for routes that only support POST. */
  private static final String POST_ONLY_MESSAGE = "Platform API v1 supports POST requests only.";

  /** Route segment for app-update lifecycle responses. */
  private static final String UPDATES_ROUTE_SEGMENT = "updates";

  /** Handler for node greeting/reference routes. */
  private final NodeApiHandler nodeApiHandler;

  /** Handler for connectivity status routes. */
  private final ConnectivityApiHandler connectivityApiHandler;

  /** Handler for diagnostics routes. */
  private final DiagnosticsApiHandler diagnosticsApiHandler;

  /** Handler for core update routes. */
  private final UpdatesApiHandler updatesApiHandler;

  /** Handler for first-time wizard routes. */
  private final FirstTimeWizardApiHandler firstTimeWizardApiHandler;

  /** Handler for alert list and mutation routes. */
  private final AlertsApiHandler alertsApiHandler;

  /**
   * Creates operational routes backed by detached runtime ports.
   *
   * @param runtimePorts detached runtime-port aggregate used to construct operational handlers
   * @param legacyAdminUsage optional process-local legacy-admin usage source for diagnostics
   */
  PlatformApiOperationalRoutes(RuntimePorts runtimePorts, LegacyAdminUsagePort legacyAdminUsage) {
    nodeApiHandler = new NodeApiHandler(runtimePorts.nodeInfo());
    connectivityApiHandler = new ConnectivityApiHandler(runtimePorts.connectivity());
    updatesApiHandler = new UpdatesApiHandler(runtimePorts.coreUpdateAction());
    firstTimeWizardApiHandler = new FirstTimeWizardApiHandler(runtimePorts.firstTimeWizard());
    alertsApiHandler = new AlertsApiHandler(runtimePorts.alertFeed(), runtimePorts.alertMutation());
    diagnosticsApiHandler = new DiagnosticsApiHandler(runtimePorts.diagnostic(), legacyAdminUsage);
  }

  /**
   * Routes one operational request.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including method and query parameters
   * @return JSON response for the selected operational endpoint
   */
  PlatformApiResponse route(List<String> segments, PlatformApiRequest request) {
    String firstSegment = segments.getFirst();
    return switch (firstSegment) {
      case "node" -> routeNodeRequest(segments, request);
      case "connectivity" -> routeConnectivityRequest(segments, request);
      case "diagnostics" -> routeDiagnosticsRequest(segments, request);
      case UPDATES_ROUTE_SEGMENT -> routeUpdatesRequest(segments, request);
      case "wizard" -> routeWizardRequest(segments, request);
      case "alerts" -> routeAlertsRequest(segments, request);
      default -> throw notFound();
    };
  }

  /**
   * Returns the current daemon build number used in app-management summaries.
   *
   * @return current build number as text, or {@code null} when no node greeting is available
   */
  String currentCryptaVersion() {
    var greeting = nodeApiHandler.rawGreeting();
    return greeting == null ? null : Integer.toString(greeting.buildNumber());
  }

  private PlatformApiResponse routeConnectivityRequest(
      List<String> segments, PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    if (segments.size() == 1) {
      return PlatformApiResponse.ok(connectivityApiHandler.snapshot(request.queryParameters()));
    }
    throw notFound();
  }

  private PlatformApiResponse routeDiagnosticsRequest(
      List<String> segments, PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    if (segments.size() == 1) {
      return PlatformApiResponse.ok(diagnosticsApiHandler.snapshot());
    }
    throw notFound();
  }

  private PlatformApiResponse routeAlertsRequest(
      List<String> segments, PlatformApiRequest request) {
    return switch (segments.size()) {
      case 1 -> routeAlertsCollection(request);
      case 3 -> routeAlertAction(segments.get(1), segments.get(2), request);
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeAlertsCollection(PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(alertsApiHandler.list());
  }

  private PlatformApiResponse routeAlertAction(
      String alertIdSegment, String action, PlatformApiRequest request) {
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    if ("dismiss".equals(action)) {
      return PlatformApiResponse.ok(alertsApiHandler.dismiss(alertIdSegment));
    }
    throw notFound();
  }

  private PlatformApiResponse routeUpdatesRequest(
      List<String> segments, PlatformApiRequest request) {
    if (segments.size() == 2 && "core".equals(segments.get(1))) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(updatesApiHandler.coreSnapshot());
    }
    if (segments.size() == 3
        && "core".equals(segments.get(1))
        && "download".equals(segments.get(2))) {
      if (!METHOD_POST.equals(request.method())) {
        return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(updatesApiHandler.startCoreDownload());
    }
    throw notFound();
  }

  private PlatformApiResponse routeWizardRequest(
      List<String> segments, PlatformApiRequest request) {
    if (segments.size() == 2 && "first-time".equals(segments.get(1))) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(firstTimeWizardApiHandler.snapshot());
    }
    if (segments.size() == 3
        && "first-time".equals(segments.get(1))
        && "apply".equals(segments.get(2))) {
      if (!METHOD_POST.equals(request.method())) {
        return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(firstTimeWizardApiHandler.apply(request.queryParameters()));
    }
    throw notFound();
  }

  private PlatformApiResponse routeNodeRequest(List<String> segments, PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    if (segments.size() == 2 && "greeting".equals(segments.get(1))) {
      return PlatformApiResponse.ok(nodeApiHandler.greeting());
    }
    if (segments.size() == 2 && "reference".equals(segments.get(1))) {
      return PlatformApiResponse.ok(nodeApiHandler.reference(request.queryParameters()));
    }
    throw notFound();
  }

  private static PlatformApiResponse methodNotAllowed(String allow, String message) {
    return PlatformApiResponse.error(405, Map.of("Allow", allow), "method_not_allowed", message);
  }

  private static PlatformApiException notFound() {
    return new PlatformApiException(404, "not_found", "Platform API route not found.");
  }
}
