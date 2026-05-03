package network.crypta.platform.api;

import java.util.List;
import java.util.Set;

/**
 * App-principal capability policy for Platform API v1.
 *
 * <p>Host/operator requests bypass this matrix to preserve the existing local-management model. App
 * principals are default-deny: a request must match one of the endpoint descriptors in {@link
 * PlatformApiContract#current()} and the app principal must carry every required manifest
 * permission. The published contract descriptors are therefore the source of truth for both
 * developer-facing compatibility metadata and runtime app authorization.
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

  /** Manifest permission that allows app principals to read the public compatibility contract. */
  static final String PLATFORM_CONTRACT_READ = "platform.contract.read";

  private PlatformApiCapabilities() {}

  /**
   * Authorizes one transport-neutral Platform API request.
   *
   * <p>Host/operator principals are allowed immediately because the HTTP bridge has already
   * enforced the legacy local management checks. App principals must match a public contract
   * endpoint and must contain every capability required by that descriptor.
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

  private static PlatformApiAction actionFor(PlatformApiRequest request) {
    PlatformApiEndpointDescriptor endpoint =
        PlatformApiContract.current()
            .endpointFor(request.method(), request.pathSegments(), request.principal().type());
    return endpoint == null ? null : endpoint.toAction();
  }

  /**
   * Builds the synthetic action used for default-deny app routes.
   *
   * <p>The returned action is not grantable by a normal manifest permission. Its purpose is to
   * provide audit entries with an endpoint family and an {@code unmapped} capability label when an
   * app principal attempts a route that the contract does not intentionally expose.
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
