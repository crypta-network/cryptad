package network.crypta.platform.api.appservices;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.PlatformApiPrincipal;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppSnapshot;

/**
 * Coordinates local app-service discovery, grant lifecycle, invocation, and audit.
 *
 * <p>This service is the authorization boundary for PR-243 app-to-app calls. It discovers only
 * signed installed-manifest metadata, requires explicit app capabilities plus an active local
 * grant, and dispatches only to registered in-process adapters. It never proxies arbitrary
 * localhost servers or exposes provider app data, installed paths, process tokens, raw request
 * bodies, private insert URIs, or Trust Graph store files.
 *
 * <p>Callers should treat the coordinator as a request-scoped policy engine backed by a durable
 * grant store. Discovery is derived from the current AppHost installed-app snapshot, while grant
 * records are read from the configured store at request time. That split is intentional: app
 * update, uninstall, and manifest permission changes affect future invocations immediately without
 * rewriting every stored grant. Public responses are deterministic, bounded, and safe for operator
 * UI display.
 *
 * <p>Context handling is part of that boundary. Services with declared contexts require a request
 * and an invocation to name one supported context explicitly. Services with no declared contexts
 * are unscoped; grants for those services must also carry no contexts, and invocation removes any
 * supplied context before adapter dispatch.
 *
 * <p>The coordinator is synchronized because the file-backed store is process-local and grant use
 * counts are updated read-modify-write. It is not a distributed lock and does not provide
 * cross-node authorization. The current app-service layer is strictly local to one Cryptad node.
 */
public final class AppServiceCoordinator {
  /** Manifest permission that allows app principals to request grants and invoke services. */
  public static final String CAPABILITY_APP_SERVICES_CALL = "app.services.call";

  private static final String AUDIT_EVENT_SERVICE_INVOCATION_DENIED = "service_invocation_denied";
  private static final String AUDIT_STATUS_DENIED = "denied";
  private static final System.Logger LOG = System.getLogger(AppServiceCoordinator.class.getName());
  private static final String PARAM_BUNDLE_ALIAS = "bundleAlias";
  private static final String PARAM_CONSUMER_APP_ID = "consumerAppId";
  private static final String PARAM_CONTEXT = "context";
  private static final String PARAM_CONTEXTS = "contexts";
  private static final String FIELD_STATUS = "status";
  private static final String PARAM_INCLUDE_OPTIONAL = "includeOptional";
  private static final String PARAM_PROVIDER_APP_ID = "providerAppId";
  private static final String PARAM_PURPOSE = "purpose";
  private static final String PARAM_SCOPE = "scope";
  private static final String PARAM_SCOPES = "scopes";
  private static final String PARAM_SERVICE_ID = "serviceId";
  private static final String PARAM_SUBJECT_URI = "subjectUri";
  private static final String REQUIRED_TRUST_SCORE_SCOPE = "score.read";
  private static final String SUPPORTED_SERVICE_KIND = "platform-adapter";
  private static final int DEFAULT_AUDIT_LIMIT = 50;
  private static final Duration MAX_BUNDLE_GRANT_DURATION = Duration.ofDays(30);
  private static final HexFormat HEX = HexFormat.of();

  private final AppHost appHost;
  private final AppServiceGrantStore store;
  private final Clock clock;
  private final Map<String, AppServiceAdapter> adapters;
  private final Set<String> cleanupFailedAppIds = new HashSet<>();
  private final String auditEventRunId = UUID.randomUUID().toString();
  private final AtomicLong auditEventSequence = new AtomicLong();

  /**
   * Creates a coordinator.
   *
   * <p>The adapter list is copied into an immutable map keyed by adapter id. If two adapters report
   * the same id, the later entry wins; runtime wiring should avoid duplicates and keep the list
   * small. Passing a {@code null} AppHost creates an unavailable discovery surface, useful only for
   * reduced embeddings that should fail app-service requests consistently.
   *
   * @param appHost AppHost used for installed-manifest discovery and permission checks
   * @param store durable or in-memory grant and audit store
   * @param clock timestamp source used for grant and audit records
   * @param adapters explicit built-in service adapters allowed for invocation
   */
  public AppServiceCoordinator(
      AppHost appHost, AppServiceGrantStore store, Clock clock, List<AppServiceAdapter> adapters) {
    this.appHost = appHost;
    this.store = Objects.requireNonNull(store, "store");
    this.clock = Objects.requireNonNull(clock, "clock");
    LinkedHashMap<String, AppServiceAdapter> byId = LinkedHashMap.newLinkedHashMap(adapters.size());
    for (AppServiceAdapter adapter : adapters) {
      byId.put(adapter.adapterId(), adapter);
    }
    this.adapters = java.util.Collections.unmodifiableMap(byId);
  }

  /**
   * Returns an in-memory coordinator useful for tests.
   *
   * <p>The helper keeps storage process-local and uses the system UTC clock. Production runtime
   * wiring should prefer an explicitly constructed coordinator with a file-backed store so grant
   * decisions survive node restarts.
   *
   * @param appHost AppHost used for installed-app discovery
   * @param trustGraphAdapter optional adapter for Trust Graph score invocations
   * @return coordinator with process-local storage and optional Trust Graph adapter
   */
  @SuppressWarnings("unused")
  public static AppServiceCoordinator inMemory(
      AppHost appHost, AppServiceAdapter trustGraphAdapter) {
    return new AppServiceCoordinator(
        appHost,
        new InMemoryAppServiceGrantStore(),
        Clock.systemUTC(),
        trustGraphAdapter == null ? List.of() : List.of(trustGraphAdapter));
  }

  /**
   * Lists advertised services visible to the caller.
   *
   * <p>Descriptors are rebuilt from installed app manifests on every call. The result includes
   * provider and service metadata, supported scopes, supported contexts, stability, and
   * availability. It excludes manifest file paths, process launch tokens, data roots, and any
   * provider-private state.
   *
   * @return public service descriptor JSON in deterministic provider/service order
   */
  public synchronized List<Map<String, Object>> listServices() {
    return installedServices().stream().map(AppServiceDescriptor::toJson).toList();
  }

  /**
   * Lists manifest-declared service requests visible to the caller.
   *
   * <p>Host/operator principals see every installed app's service-request metadata for review. App
   * principals see only requests declared by their own app. The request metadata is transparency
   * data only; it never creates or approves a grant.
   *
   * @param principal request principal used for app-scoped filtering
   * @return public request descriptor JSON in deterministic app/provider/service order
   */
  public synchronized List<Map<String, Object>> listRequests(PlatformApiPrincipal principal) {
    String callerAppId = principal.isApp() ? principal.appId() : null;
    return installedServiceRequests().stream()
        .filter(request -> callerAppId == null || request.consumerAppId().equals(callerAppId))
        .map(AppServiceRequestDescriptor::toJson)
        .toList();
  }

  /**
   * Returns the caller-visible app-service dependency graph.
   *
   * <p>Host/operator principals see every installed app node. App principals see only their own app
   * and dependency edges. The graph is rebuilt from signed manifests, current provider descriptors,
   * and current grant state on each call. It contains review metadata only and no local paths,
   * request bodies, subject URIs, tokens, private insert URIs, or raw Trust Graph data.
   *
   * @param principal request principal used for app scoping
   * @return deterministic graph JSON
   */
  public synchronized Map<String, Object> dependencyGraph(PlatformApiPrincipal principal) {
    return dependencyGraph(principal, null);
  }

  /**
   * Returns the dependency graph for a single consumer app.
   *
   * @param principal request principal used for app scoping
   * @param consumerAppId requested consumer app id
   * @return deterministic graph JSON
   */
  public synchronized Map<String, Object> dependencyGraph(
      PlatformApiPrincipal principal, String consumerAppId) {
    String callerAppId = principal.isApp() ? principal.appId() : null;
    String selectedAppId =
        consumerAppId == null
            ? callerAppId
            : AppServiceManifestParser.normalizeAppId(consumerAppId);
    if (callerAppId != null && !callerAppId.equals(selectedAppId)) {
      throw new PlatformApiException(
          403, "forbidden", "App principals can read only their own dependencies.");
    }
    List<InstalledAppSnapshot> apps = installedApps();
    List<AppServiceRequestDescriptor> requests = installedServiceRequests();
    List<AppServiceDescriptor> services = installedServices();
    List<AppServiceGrant> grants = readGrants();
    LinkedHashMap<String, Object> graph = LinkedHashMap.newLinkedHashMap(2);
    graph.put("apps", dependencyAppNodes(apps, requests, services, grants, selectedAppId));
    graph.put("edges", dependencyEdges(requests, apps, services, grants, selectedAppId));
    return graph;
  }

  /**
   * Lists caller-visible grant-bundle review records.
   *
   * @param principal request principal used for app scoping
   * @return deterministic bundle JSON list
   */
  public synchronized List<Map<String, Object>> listBundles(PlatformApiPrincipal principal) {
    String callerAppId = principal.isApp() ? principal.appId() : null;
    try {
      List<AppServiceRequestDescriptor> requests = installedServiceRequests();
      List<AppServiceDescriptor> services = installedServices();
      List<AppServiceGrant> grants = store.listGrants();
      return store.listBundles().stream()
          .filter(bundle -> callerAppId == null || bundle.consumerAppId().equals(callerAppId))
          .map(bundle -> bundleJson(bundle, requests, services, grants))
          .toList();
    } catch (IOException _) {
      throw unavailable();
    }
  }

  /**
   * Creates or reuses a pending grant-bundle proposal for one consumer app.
   *
   * <p>Apps can request only their own bundle. Host/operator callers can create a review bundle for
   * a named installed app. The proposal does not create grants or approve access.
   *
   * @param principal request principal
   * @param parameters decoded form parameters
   * @return pending bundle JSON
   */
  public synchronized Map<String, Object> requestBundle(
      PlatformApiPrincipal principal, Map<String, List<String>> parameters) {
    String consumerAppId = bundleConsumerAppId(principal, parameters);
    ensureConsumerCanCall(consumerAppId);
    String bundleAlias =
        optionalAlias(PlatformApiParameters.readOptionalString(parameters, PARAM_BUNDLE_ALIAS));
    boolean includeOptional =
        PlatformApiParameters.readBoolean(parameters, PARAM_INCLUDE_OPTIONAL, true);
    String purpose =
        AppServiceManifestParser.optionalSafeText(
            PlatformApiParameters.readOptionalString(parameters, PARAM_PURPOSE), 512);
    if (purpose == null) {
      purpose = "Review app-service dependencies for " + consumerAppId + ".";
    }
    List<AppServiceRequestDescriptor> dependencies =
        selectedBundleDependencies(consumerAppId, bundleAlias, includeOptional);
    if (dependencies.isEmpty()) {
      throw new PlatformApiException(
          400,
          "app_service_bundle_empty",
          "No declared app-service dependencies match this bundle request.");
    }
    List<String> aliases = dependencies.stream().map(AppServiceRequestDescriptor::alias).toList();
    List<String> dependencyFingerprints = dependencyFingerprints(dependencies);
    Instant now = clock.instant();
    try {
      Optional<AppServiceGrantBundle> existing =
          store.listBundles().stream()
              .filter(bundle -> bundle.consumerAppId().equals(consumerAppId))
              .filter(bundle -> Objects.equals(bundle.bundleAlias(), bundleAlias))
              .filter(bundle -> bundle.status() == AppServiceGrantBundleStatus.PENDING)
              .filter(bundle -> sameTokens(bundle.dependencyAliases(), aliases))
              .filter(bundle -> bundle.dependencyFingerprints().equals(dependencyFingerprints))
              .findFirst();
      if (existing.isPresent()) {
        return bundleJson(
            existing.get(), installedServiceRequests(), installedServices(), store.listGrants());
      }
      AppServiceGrantBundle bundle =
          new AppServiceGrantBundle(
              newBundleId(consumerAppId, bundleAlias, aliases, now),
              consumerAppId,
              bundleAlias,
              aliases,
              dependencyFingerprints,
              includeOptional,
              purpose,
              AppServiceGrantBundleStatus.PENDING,
              now,
              now,
              null,
              null,
              null,
              null,
              List.of());
      store.writeBundle(bundle);
      return bundleJson(
          bundle, installedServiceRequests(), installedServices(), store.listGrants());
    } catch (IOException _) {
      throw unavailable();
    }
  }

  /** Approves a pending grant bundle. */
  public synchronized Map<String, Object> approveBundle(
      PlatformApiPrincipal principal, String bundleId) {
    requireHostOperator(principal, "App principals cannot approve app-service grant bundles.");
    AppServiceGrantBundle bundle = bundleRequired(bundleId);
    if (bundle.status() != AppServiceGrantBundleStatus.PENDING) {
      throw new PlatformApiException(
          409,
          "app_service_bundle_not_pending",
          "Only pending app-service grant bundles can be approved.");
    }
    return approveOrRenewBundle(bundle, false);
  }

  /** Rejects a pending grant bundle without creating active grants. */
  public synchronized Map<String, Object> rejectBundle(
      PlatformApiPrincipal principal, String bundleId) {
    requireHostOperator(principal, "App principals cannot reject app-service grant bundles.");
    AppServiceGrantBundle bundle = bundleRequired(bundleId);
    if (bundle.status() != AppServiceGrantBundleStatus.PENDING) {
      throw new PlatformApiException(
          409,
          "app_service_bundle_not_pending",
          "Only pending app-service grant bundles can be rejected.");
    }
    Instant now = clock.instant();
    AppServiceGrantBundle rejected =
        bundle.withStatus(
            AppServiceGrantBundleStatus.REJECTED,
            now,
            bundle.approvedAt(),
            now,
            bundle.expiresAt(),
            bundle.renewedAt(),
            List.of());
    try {
      store.writeBundle(rejected);
      return bundleJson(
          rejected, installedServiceRequests(), installedServices(), store.listGrants());
    } catch (IOException _) {
      throw unavailable();
    }
  }

  /** Renews or revalidates an approved grant bundle after explicit operator action. */
  public synchronized Map<String, Object> renewBundle(
      PlatformApiPrincipal principal, String bundleId) {
    requireHostOperator(principal, "App principals cannot renew app-service grant bundles.");
    AppServiceGrantBundle bundle = bundleRequired(bundleId);
    AppServiceGrantBundleStatus effective = effectiveBundleStatus(bundle, readGrants());
    if (effective != AppServiceGrantBundleStatus.APPROVED
        && effective != AppServiceGrantBundleStatus.EXPIRED
        && effective != AppServiceGrantBundleStatus.REVALIDATION_REQUIRED) {
      throw new PlatformApiException(
          409,
          "app_service_bundle_not_renewable",
          "Only approved, expired, or revalidation-required bundles can be renewed.");
    }
    return approveOrRenewBundle(bundle, true);
  }

  /**
   * Lists services for one provider.
   *
   * <p>The provider must currently be installed. A provider that is installed but has invalid or
   * absent service metadata returns an empty list rather than exposing raw manifest parse errors to
   * app callers.
   *
   * @param providerAppId provider app id path segment supplied by the route
   * @return descriptor JSON list for the installed provider
   */
  public synchronized List<Map<String, Object>> listProviderServices(String providerAppId) {
    String provider = AppServiceManifestParser.normalizeAppId(providerAppId);
    ensureProviderInstalled(provider);
    return installedServices().stream()
        .filter(service -> service.providerAppId().equals(provider))
        .map(AppServiceDescriptor::toJson)
        .toList();
  }

  /**
   * Reads one advertised service.
   *
   * <p>The provider and service id are normalized before lookup. Missing providers and missing
   * service descriptors produce stable Platform API errors so SDK callers can distinguish
   * uninstall/update drift from ordinary malformed input.
   *
   * @param providerAppId provider app id path segment supplied by the route
   * @param serviceId public service id path segment supplied by the route
   * @return descriptor JSON for the advertised provider service
   */
  public synchronized Map<String, Object> getService(String providerAppId, String serviceId) {
    return serviceRequired(providerAppId, serviceId).toJson();
  }

  /**
   * Lists grants with app scoping for app principals and full visibility for host/operator.
   *
   * <p>The stored status is combined with current installed-service state before serialization. An
   * active grant is reported as {@code inactive} when the provider is removed or stops advertising
   * the service, when the stored scopes or contexts no longer match the current descriptor, or when
   * the consumer app no longer declares {@code app.services.call}. App principals cannot enumerate
   * grants belonging to other consumer apps.
   *
   * @param principal request principal used to scope app-visible grants
   * @return public grant JSON list with effective status values
   */
  public synchronized List<Map<String, Object>> listGrants(PlatformApiPrincipal principal) {
    try {
      String callerAppId = principal.isApp() ? principal.appId() : null;
      return store.listGrants().stream()
          .filter(grant -> callerAppId == null || grant.consumerAppId().equals(callerAppId))
          .map(grant -> grant.toJson(effectiveStatus(grant)))
          .toList();
    } catch (IOException _) {
      throw unavailable();
    }
  }

  /**
   * Requests a new grant for the authenticated consumer app.
   *
   * <p>Grant creation is app-only and never auto-approves access. The consumer app must still be
   * installed and declare {@code app.services.call}; the provider must be installed and advertise
   * the requested service; scopes and contexts must be supported by that descriptor. Contextual
   * services require an explicit context so the operator sees the narrow requested boundary.
   * Unscoped services reject requested contexts rather than treating them as a wildcard. Repeated
   * requests for the same consumer, provider, service, scope set, and context set return the
   * existing pending or active grant instead of creating unbounded durable records.
   *
   * @param principal authenticated app principal requesting access
   * @param parameters decoded form parameters containing provider, service, scopes, context, and
   *     purpose
   * @return public pending grant JSON safe for app and operator display
   */
  public synchronized Map<String, Object> requestGrant(
      PlatformApiPrincipal principal, Map<String, List<String>> parameters) {
    String consumerAppId = requireAppPrincipal(principal);
    ensureConsumerCanCall(consumerAppId);
    String providerAppId =
        AppServiceManifestParser.normalizeAppId(
            PlatformApiParameters.requireString(parameters, PARAM_PROVIDER_APP_ID));
    String serviceId =
        AppServiceManifestParser.normalizeServiceId(
            PlatformApiParameters.requireString(parameters, PARAM_SERVICE_ID));
    AppServiceDescriptor descriptor = serviceRequired(providerAppId, serviceId);
    ensureDescriptorSupported(descriptor);
    List<String> scopes =
        AppServiceManifestParser.commaList(
            PlatformApiParameters.requireString(parameters, PARAM_SCOPES), PARAM_SCOPES);
    List<String> contexts = requestedContexts(parameters);
    ensureNoFailedCleanup(consumerAppId, providerAppId);
    if (descriptor.hasUnsupportedScopes(scopes)) {
      throw new PlatformApiException(
          400,
          "app_service_scope_unsupported",
          "The service does not support the requested scopes.");
    }
    if (!descriptor.contexts().isEmpty() && contexts.isEmpty()) {
      throw new PlatformApiException(
          400,
          "app_service_context_required",
          "The service requires an explicit requested context.");
    }
    if (descriptor.contexts().isEmpty() && !contexts.isEmpty()) {
      throw new PlatformApiException(
          400,
          "app_service_context_unsupported",
          "The service does not support requested contexts.");
    }
    for (String context : contexts) {
      if (!descriptor.supportsContext(context)) {
        throw new PlatformApiException(
            400,
            "app_service_context_unsupported",
            "The service does not support the requested context.");
      }
    }
    Instant now = clock.instant();
    try {
      Optional<AppServiceGrant> existing =
          existingReusableGrant(consumerAppId, providerAppId, serviceId, scopes, contexts);
      if (existing.isPresent()) {
        AppServiceGrant grant = existing.get();
        return grant.toJson(effectiveStatus(grant));
      }
      AppServiceGrant grant =
          new AppServiceGrant(
              newGrantId(consumerAppId, providerAppId, serviceId, scopes, contexts, now),
              consumerAppId,
              providerAppId,
              serviceId,
              scopes,
              contexts,
              AppServiceManifestParser.requiredPurposeText(
                  PlatformApiParameters.requireString(parameters, PARAM_PURPOSE)),
              AppServiceGrantStatus.PENDING,
              now,
              now,
              null,
              null,
              null,
              0,
              null);
      store.writeGrant(grant);
      appendAudit("grant_requested", grant, null, null, "pending", "grant_pending", null);
      return grant.toJson();
    } catch (IOException _) {
      throw unavailable();
    }
  }

  /**
   * Approves one pending grant. Only host/operator callers may use this method.
   *
   * <p>Approval revalidates current provider advertisement and consumer manifest permissions before
   * changing state. Revoked, inactive, active, or expired records are not reactivated by this path;
   * callers must create a fresh pending request when the old grant is no longer pending.
   *
   * @param principal host/operator principal authorizing the grant
   * @param grantId stable local grant id selected by the operator
   * @return active grant JSON after successful approval
   */
  public synchronized Map<String, Object> approveGrant(
      PlatformApiPrincipal principal, String grantId) {
    requireHostOperator(principal, "App principals cannot approve app-service grants.");
    AppServiceGrant grant = grantRequired(grantId);
    if (grant.status() != AppServiceGrantStatus.PENDING) {
      throw new PlatformApiException(
          409, "app_service_grant_not_pending", "Only pending app-service grants can be approved.");
    }
    AppServiceDescriptor descriptor = serviceRequired(grant.providerAppId(), grant.serviceId());
    ensureDescriptorSupported(descriptor);
    ensureGrantSupportedByDescriptor(grant, descriptor);
    ensureConsumerCanCall(grant.consumerAppId());
    ensureNoFailedCleanup(grant.consumerAppId(), grant.providerAppId());
    Instant now = clock.instant();
    AppServiceGrant approved =
        grant.withApprovalMetadata(
            now,
            grant.bundleId(),
            grant.expiresAt(),
            grant.renewedAt(),
            descriptor.compatibilityFingerprint(),
            descriptor.version());
    try {
      store.writeGrant(approved);
      appendAudit("grant_approved", approved, null, null, "ok", "grant_active", null);
      return approved.toJson();
    } catch (IOException _) {
      throw unavailable();
    }
  }

  /**
   * Revokes one grant. Host/operator can revoke any grant; an app can revoke only its own grant.
   *
   * <p>Revocation takes effect for future invocations because {@link #invoke} reads the active
   * grant set at call time. The method is idempotent with respect to security: revoking an already
   * revoked grant keeps it non-authorizing and updates the public record timestamp.
   *
   * @param principal request principal, either host/operator or the owning consumer app
   * @param grantId stable local grant id to revoke
   * @return revoked grant JSON safe for app and operator display
   */
  public synchronized Map<String, Object> revokeGrant(
      PlatformApiPrincipal principal, String grantId) {
    AppServiceGrant grant = grantRequired(grantId);
    if (principal.isApp() && !grant.consumerAppId().equals(principal.appId())) {
      throw new PlatformApiException(
          403, "forbidden", "App principals can revoke only their own app-service grants.");
    }
    AppServiceGrant revoked = grant.withStatus(AppServiceGrantStatus.REVOKED, clock.instant());
    try {
      store.writeGrant(revoked);
      appendAudit("grant_revoked", revoked, null, null, "revoked", "grant_revoked", null);
      return revoked.toJson();
    } catch (IOException _) {
      throw unavailable();
    }
  }

  /**
   * Invokes one local app service through an active grant.
   *
   * <p>Invocation is checked at the moment of the call. The consumer must be an app principal,
   * remain installed, still declare {@code app.services.call}, and hold an active grant matching
   * provider, service, scope, and the descriptor context when the service is context-scoped. The
   * provider must remain installed and advertise the service. The descriptor's adapter id must
   * resolve to a registered built-in adapter; no arbitrary localhost or remote URL is invoked.
   * Unscoped services do not require a {@code context} parameter and match only grants that were
   * approved without contexts.
   *
   * @param principal authenticated consumer app principal making the call
   * @param providerAppId provider app id path segment supplied by the route
   * @param serviceId public service id path segment supplied by the route
   * @param parameters decoded invocation parameters for the selected adapter
   * @return service-call envelope JSON containing metadata and redacted adapter result
   */
  public synchronized Map<String, Object> invoke(
      PlatformApiPrincipal principal,
      String providerAppId,
      String serviceId,
      Map<String, List<String>> parameters) {
    String consumerAppId = requireAppPrincipal(principal);
    ensureConsumerCanCall(consumerAppId);
    AppServiceDescriptor descriptor = serviceRequired(providerAppId, serviceId);
    ensureDescriptorSupported(descriptor);
    ensureNoFailedCleanup(consumerAppId, descriptor.providerAppId());
    String context = requestedContext(parameters, descriptor);
    Map<String, List<String>> normalizedParameters = withInvocationContext(parameters, context);
    String scope = requestedScope(parameters, descriptor);
    AppServiceGrant grant =
        activeGrant(consumerAppId, descriptor, scope, context, normalizedParameters);
    AppServiceAdapter adapter = adapters.get(descriptor.adapter());
    if (adapter == null) {
      appendAudit(
          AUDIT_EVENT_SERVICE_INVOCATION_DENIED,
          grant,
          scope,
          context,
          AUDIT_STATUS_DENIED,
          "adapter_missing",
          normalizedParameters);
      throw new PlatformApiException(
          404,
          "app_service_adapter_missing",
          "No platform adapter is registered for this service.");
    }
    Instant invokedAt = clock.instant();
    try {
      Map<String, Object> result = adapter.invoke(descriptor, grant, normalizedParameters);
      AppServiceGrant used = grant.recordUse(invokedAt);
      store.writeGrant(used);
      appendAudit(
          "service_invoked",
          used,
          scope,
          context,
          "ok",
          "invocation_allowed",
          normalizedParameters);
      return serviceCallEnvelope(descriptor, used, invokedAt, result);
    } catch (PlatformApiException exception) {
      appendAudit(
          AUDIT_EVENT_SERVICE_INVOCATION_DENIED,
          grant,
          scope,
          context,
          AUDIT_STATUS_DENIED,
          exception.errorCode(),
          normalizedParameters);
      throw exception;
    } catch (IOException _) {
      throw unavailable();
    }
  }

  /**
   * Lists recent redacted audit events. Host/operator only.
   *
   * <p>Audit listing is intentionally not app-visible. The result is bounded by the {@code limit}
   * query parameter, capped to 200 entries, and contains only the redacted fields stored in {@link
   * AppServiceAuditEvent}.
   *
   * @param principal request principal, which must be host/operator
   * @param parameters decoded query parameters, optionally including {@code limit}
   * @return audit event JSON list ordered by the backing store's recent-event policy
   */
  public synchronized List<Map<String, Object>> audit(
      PlatformApiPrincipal principal, Map<String, List<String>> parameters) {
    requireHostOperator(principal, "App principals cannot list app-service audit history.");
    int limit = readLimit(parameters);
    try {
      return store.listAuditEvents(limit).stream().map(AppServiceAuditEvent::toJson).toList();
    } catch (IOException _) {
      throw unavailable();
    }
  }

  /**
   * Marks grants involving one app inactive after uninstall or cleanup.
   *
   * <p>The method is a runtime hook for AppHost state changes. It does not delete historical grants
   * or audit events; it changes active relationships into non-authorizing records and appends a
   * redacted audit event for each affected grant. Invalid app ids are rejected through the same
   * normalizer used by route inputs. If durable cleanup cannot be persisted, the app id is kept in
   * a process-local fail-closed set and future grant approval or invocation involving that app id
   * fails until a later cleanup attempt succeeds.
   *
   * @param appId provider or consumer app id whose local service state was cleared
   */
  public synchronized void clearAppState(String appId) {
    String normalizedAppId = AppServiceManifestParser.normalizeAppId(appId);
    cleanupFailedAppIds.add(normalizedAppId);
    try {
      Instant now = clock.instant();
      for (AppServiceGrant grant : store.listGrants()) {
        if (grant.consumerAppId().equals(normalizedAppId)
            || grant.providerAppId().equals(normalizedAppId)) {
          AppServiceGrant inactive = grant.withStatus(AppServiceGrantStatus.INACTIVE, now);
          store.writeGrant(inactive);
          appendAudit(
              "grant_inactivated", inactive, null, null, "inactive", "app_state_cleared", null);
        }
      }
      cleanupFailedAppIds.remove(normalizedAppId);
    } catch (IOException exception) {
      LOG.log(System.Logger.Level.WARNING, "Failed to clear app-service state", exception);
      throw unavailable();
    }
  }

  private List<Map<String, Object>> dependencyAppNodes(
      List<InstalledAppSnapshot> apps,
      List<AppServiceRequestDescriptor> requests,
      List<AppServiceDescriptor> services,
      List<AppServiceGrant> grants,
      String selectedAppId) {
    return apps.stream()
        .filter(snapshot -> selectedAppId == null || snapshot.appId().equals(selectedAppId))
        .sorted(Comparator.comparing(InstalledAppSnapshot::appId))
        .map(
            snapshot -> {
              Map<String, Object> app = LinkedHashMap.newLinkedHashMap(4);
              app.put("appId", snapshot.appId());
              app.put("name", snapshot.manifest().appName());
              app.put("version", snapshot.manifest().appVersion());
              app.put(
                  "dependencies",
                  requests.stream()
                      .filter(request -> request.consumerAppId().equals(snapshot.appId()))
                      .sorted(Comparator.comparing(AppServiceRequestDescriptor::alias))
                      .map(request -> dependencyJson(request, apps, services, grants))
                      .toList());
              return app;
            })
        .toList();
  }

  private List<Map<String, Object>> dependencyEdges(
      List<AppServiceRequestDescriptor> requests,
      List<InstalledAppSnapshot> apps,
      List<AppServiceDescriptor> services,
      List<AppServiceGrant> grants,
      String selectedAppId) {
    return requests.stream()
        .filter(request -> selectedAppId == null || request.consumerAppId().equals(selectedAppId))
        .sorted(
            Comparator.comparing(AppServiceRequestDescriptor::consumerAppId)
                .thenComparing(AppServiceRequestDescriptor::providerAppId)
                .thenComparing(AppServiceRequestDescriptor::serviceId)
                .thenComparing(AppServiceRequestDescriptor::alias))
        .map(
            request -> {
              DependencyEvaluation evaluation = evaluateDependency(request, apps, services, grants);
              Map<String, Object> edge = LinkedHashMap.newLinkedHashMap(5);
              edge.put(PARAM_CONSUMER_APP_ID, request.consumerAppId());
              edge.put(PARAM_PROVIDER_APP_ID, request.providerAppId());
              edge.put(PARAM_SERVICE_ID, request.serviceId());
              edge.put("alias", request.alias());
              edge.put(FIELD_STATUS, evaluation.status().jsonValue());
              return edge;
            })
        .toList();
  }

  private Map<String, Object> dependencyJson(
      AppServiceRequestDescriptor request,
      List<InstalledAppSnapshot> apps,
      List<AppServiceDescriptor> services,
      List<AppServiceGrant> grants) {
    AppServiceDependencyDescriptor dependency = request.dependency();
    DependencyEvaluation evaluation = evaluateDependency(request, apps, services, grants);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(18);
    json.put("alias", request.alias());
    json.put(PARAM_PROVIDER_APP_ID, request.providerAppId());
    json.put(PARAM_SERVICE_ID, request.serviceId());
    json.put("kind", dependency.kind().jsonValue());
    json.put("featureId", dependency.featureId());
    json.put("featureName", dependency.featureName());
    json.put("required", dependency.required());
    json.put(PARAM_SCOPES, request.scopes());
    json.put(PARAM_CONTEXTS, request.contexts());
    json.put(
        "versionRange",
        dependency.versionRange() == null ? null : dependency.versionRange().toJson());
    json.put(FIELD_STATUS, evaluation.status().jsonValue());
    json.put("degradeBehavior", dependency.degradeBehavior().jsonValue());
    json.put("reason", dependency.reason() == null ? request.purpose() : dependency.reason());
    json.put("grantBundle", dependency.grantBundle());
    json.put(
        "grantExpiresAfter",
        dependency.grantExpiresAfter() == null ? null : dependency.grantExpiresAfter().toString());
    json.put("grantId", evaluation.grant() == null ? null : evaluation.grant().grantId());
    json.put(
        "blocking",
        dependency.required() && evaluation.status() != AppServiceDependencyStatus.GRANT_ACTIVE);
    json.put(
        "providerServiceVersion",
        evaluation.descriptor() == null ? null : evaluation.descriptor().version());
    return json;
  }

  private DependencyEvaluation evaluateDependency(
      AppServiceRequestDescriptor request,
      List<InstalledAppSnapshot> apps,
      List<AppServiceDescriptor> services,
      List<AppServiceGrant> grants) {
    if (apps.stream().noneMatch(snapshot -> snapshot.appId().equals(request.providerAppId()))) {
      return new DependencyEvaluation(AppServiceDependencyStatus.MISSING_PROVIDER, null, null);
    }
    Optional<AppServiceDescriptor> descriptor =
        services.stream()
            .filter(service -> service.providerAppId().equals(request.providerAppId()))
            .filter(service -> service.serviceId().equals(request.serviceId()))
            .findFirst();
    if (descriptor.isEmpty()) {
      return new DependencyEvaluation(AppServiceDependencyStatus.MISSING_SERVICE, null, null);
    }
    AppServiceDescriptor service = descriptor.get();
    if (!service.satisfiesVersionRange(request.dependency().versionRange())) {
      return new DependencyEvaluation(AppServiceDependencyStatus.VERSION_MISMATCH, service, null);
    }
    if (service.hasUnsupportedScopes(request.scopes())) {
      return new DependencyEvaluation(AppServiceDependencyStatus.SCOPE_MISMATCH, service, null);
    }
    if (!contextsSupported(service, request.contexts())) {
      return new DependencyEvaluation(AppServiceDependencyStatus.CONTEXT_MISMATCH, service, null);
    }
    if (descriptorUnsupported(service)) {
      return new DependencyEvaluation(AppServiceDependencyStatus.UNAVAILABLE, service, null);
    }
    Optional<AppServiceGrant> grant = matchingGrantForRequest(request, grants);
    if (grant.isEmpty()) {
      return new DependencyEvaluation(AppServiceDependencyStatus.AVAILABLE, service, null);
    }
    AppServiceGrantStatus status = effectiveStatus(grant.get());
    if (status == AppServiceGrantStatus.PENDING) {
      return new DependencyEvaluation(
          AppServiceDependencyStatus.GRANT_PENDING, service, grant.get());
    }
    if (status == AppServiceGrantStatus.ACTIVE) {
      return new DependencyEvaluation(
          AppServiceDependencyStatus.GRANT_ACTIVE, service, grant.get());
    }
    if (status == AppServiceGrantStatus.EXPIRED) {
      return new DependencyEvaluation(
          AppServiceDependencyStatus.GRANT_EXPIRED, service, grant.get());
    }
    if (status == AppServiceGrantStatus.REVALIDATION_REQUIRED) {
      return new DependencyEvaluation(
          AppServiceDependencyStatus.REVALIDATION_REQUIRED, service, grant.get());
    }
    return new DependencyEvaluation(AppServiceDependencyStatus.AVAILABLE, service, null);
  }

  private Optional<AppServiceGrant> matchingGrantForRequest(
      AppServiceRequestDescriptor request, List<AppServiceGrant> grants) {
    return grants.stream()
        .filter(grant -> grant.consumerAppId().equals(request.consumerAppId()))
        .filter(grant -> grant.providerAppId().equals(request.providerAppId()))
        .filter(grant -> grant.serviceId().equals(request.serviceId()))
        .filter(grant -> sameTokens(grant.scopes(), request.scopes()))
        .filter(grant -> sameTokens(grant.contexts(), request.contexts()))
        .filter(
            grant ->
                grant.status() == AppServiceGrantStatus.ACTIVE
                    || grant.status() == AppServiceGrantStatus.PENDING)
        .map(grant -> new GrantMatch(grant, effectiveStatus(grant)))
        .filter(match -> dependencyGrantStatusRank(match.status()) < Integer.MAX_VALUE)
        .min(
            Comparator.comparingInt((GrantMatch match) -> dependencyGrantStatusRank(match.status()))
                .thenComparing(match -> match.grant().createdAt())
                .thenComparing(match -> match.grant().grantId()))
        .map(GrantMatch::grant);
  }

  private static int dependencyGrantStatusRank(AppServiceGrantStatus status) {
    return switch (status) {
      case ACTIVE -> 0;
      case PENDING -> 1;
      case REVALIDATION_REQUIRED -> 2;
      case EXPIRED -> 3;
      default -> Integer.MAX_VALUE;
    };
  }

  private boolean contextsSupported(AppServiceDescriptor descriptor, List<String> contexts) {
    if (descriptor.contexts().isEmpty()) {
      return contexts.isEmpty();
    }
    return !contexts.isEmpty() && contexts.stream().allMatch(descriptor::supportsContext);
  }

  private Map<String, Object> bundleJson(
      AppServiceGrantBundle bundle,
      List<AppServiceRequestDescriptor> requests,
      List<AppServiceDescriptor> services,
      List<AppServiceGrant> grants) {
    List<InstalledAppSnapshot> apps = installedApps();
    List<AppServiceRequestDescriptor> matchingRequests =
        requests.stream()
            .filter(request -> request.consumerAppId().equals(bundle.consumerAppId()))
            .filter(request -> bundle.dependencyAliases().contains(request.alias()))
            .sorted(Comparator.comparing(AppServiceRequestDescriptor::alias))
            .toList();
    List<Map<String, Object>> dependencies =
        matchingRequests.stream()
            .map(request -> dependencyJson(request, apps, services, grants))
            .toList();
    AppServiceGrantBundleStatus status = effectiveBundleStatus(bundle, grants);
    if (bundleManifestDriftRequiresRevalidation(bundle, matchingRequests, status)) {
      status = AppServiceGrantBundleStatus.REVALIDATION_REQUIRED;
    }
    return bundle.toJson(status, dependencies);
  }

  private static boolean bundleManifestDriftRequiresRevalidation(
      AppServiceGrantBundle bundle,
      List<AppServiceRequestDescriptor> matchingRequests,
      AppServiceGrantBundleStatus effectiveStatus) {
    return effectiveStatus == AppServiceGrantBundleStatus.APPROVED
        && bundleDependencyFingerprintsChanged(bundle, matchingRequests);
  }

  private AppServiceGrantBundleStatus effectiveBundleStatus(
      AppServiceGrantBundle bundle, List<AppServiceGrant> grants) {
    if (bundle.status() != AppServiceGrantBundleStatus.APPROVED) {
      return bundle.status();
    }
    if (isExpired(bundle.expiresAt())) {
      return AppServiceGrantBundleStatus.EXPIRED;
    }
    List<AppServiceGrantStatus> grantStatuses =
        grants.stream()
            .filter(grant -> bundle.grantIds().contains(grant.grantId()))
            .map(this::effectiveStatus)
            .toList();
    if (grantStatuses.size() != bundle.grantIds().size()) {
      return AppServiceGrantBundleStatus.REVALIDATION_REQUIRED;
    }
    if (grantStatuses.stream().anyMatch(status -> status == AppServiceGrantStatus.EXPIRED)) {
      return AppServiceGrantBundleStatus.EXPIRED;
    }
    boolean allActive =
        grantStatuses.stream().allMatch(status -> status == AppServiceGrantStatus.ACTIVE);
    return allActive
        ? AppServiceGrantBundleStatus.APPROVED
        : AppServiceGrantBundleStatus.REVALIDATION_REQUIRED;
  }

  private String bundleConsumerAppId(
      PlatformApiPrincipal principal, Map<String, List<String>> parameters) {
    if (principal.isApp()) {
      return principal.appId();
    }
    return AppServiceManifestParser.normalizeAppId(
        PlatformApiParameters.requireString(parameters, PARAM_CONSUMER_APP_ID));
  }

  private List<AppServiceRequestDescriptor> selectedBundleDependencies(
      String consumerAppId, String bundleAlias, boolean includeOptional) {
    return installedServiceRequests().stream()
        .filter(request -> request.consumerAppId().equals(consumerAppId))
        .filter(
            request ->
                bundleAlias == null
                    || bundleAlias.equals(request.dependency().grantBundle())
                    || bundleAlias.equals(request.alias()))
        .filter(request -> includeOptional || request.dependency().required())
        .sorted(Comparator.comparing(AppServiceRequestDescriptor::alias))
        .toList();
  }

  private void ensureBundleDependenciesStillReviewed(
      AppServiceGrantBundle bundle, List<AppServiceRequestDescriptor> dependencies) {
    if (bundleDependencyFingerprintsChanged(bundle, dependencies)) {
      throw new PlatformApiException(
          409,
          "app_service_bundle_manifest_stale",
          "The bundled app-service dependencies changed after operator review.");
    }
  }

  private static boolean bundleDependencyFingerprintsChanged(
      AppServiceGrantBundle bundle, List<AppServiceRequestDescriptor> dependencies) {
    return bundle.dependencyFingerprints().isEmpty()
        || !bundle.dependencyFingerprints().equals(dependencyFingerprints(dependencies));
  }

  private static List<String> dependencyFingerprints(
      List<AppServiceRequestDescriptor> dependencies) {
    return dependencies.stream()
        .sorted(Comparator.comparing(AppServiceRequestDescriptor::alias))
        .map(AppServiceCoordinator::dependencyFingerprint)
        .toList();
  }

  private static String dependencyFingerprint(AppServiceRequestDescriptor request) {
    StringBuilder builder = new StringBuilder();
    appendFingerprintField(builder, request.alias());
    appendFingerprintField(builder, request.providerAppId());
    appendFingerprintField(builder, request.serviceId());
    appendFingerprintList(builder, request.scopes());
    appendFingerprintList(builder, request.contexts());
    appendFingerprintField(builder, request.purpose());
    AppServiceDependencyDescriptor dependency = request.dependency();
    appendFingerprintField(builder, dependency.kind().jsonValue());
    appendFingerprintField(builder, Boolean.toString(dependency.required()));
    AppServiceVersionRange range = dependency.versionRange();
    appendFingerprintField(builder, range == null ? null : range.min());
    appendFingerprintField(builder, range == null ? null : range.max());
    appendFingerprintField(builder, dependency.reason());
    appendFingerprintField(builder, dependency.degradeBehavior().jsonValue());
    appendFingerprintField(builder, dependency.featureId());
    appendFingerprintField(builder, dependency.featureName());
    appendFingerprintField(builder, dependency.grantBundle());
    appendFingerprintField(
        builder,
        dependency.grantExpiresAfter() == null ? null : dependency.grantExpiresAfter().toString());
    return "sha256:" + hashHex(builder.toString());
  }

  private static void appendFingerprintList(StringBuilder builder, List<String> values) {
    appendFingerprintField(builder, Integer.toString(values.size()));
    for (String value : values) {
      appendFingerprintField(builder, value);
    }
  }

  private static void appendFingerprintField(StringBuilder builder, String value) {
    if (value == null) {
      builder.append("-1:|");
      return;
    }
    builder.append(value.length()).append(':').append(value).append('|');
  }

  private Map<String, Object> approveOrRenewBundle(AppServiceGrantBundle bundle, boolean renewal) {
    ensureConsumerCanCall(bundle.consumerAppId());
    List<AppServiceRequestDescriptor> requests = installedServiceRequests();
    List<AppServiceDescriptor> services = installedServices();
    List<InstalledAppSnapshot> apps = installedApps();
    List<AppServiceRequestDescriptor> dependencies =
        requests.stream()
            .filter(request -> request.consumerAppId().equals(bundle.consumerAppId()))
            .filter(request -> bundle.dependencyAliases().contains(request.alias()))
            .sorted(Comparator.comparing(AppServiceRequestDescriptor::alias))
            .toList();
    if (dependencies.size() != bundle.dependencyAliases().size()) {
      throw new PlatformApiException(
          409,
          "app_service_bundle_manifest_stale",
          "The consumer manifest no longer declares every bundled dependency.");
    }
    ensureBundleDependenciesStillReviewed(bundle, dependencies);
    Instant now = clock.instant();
    try {
      List<AppServiceGrant> currentGrants = store.listGrants();
      BundleApprovalPlan plan =
          buildBundleApprovalPlan(
              bundle, renewal, dependencies, apps, services, currentGrants, now);
      store.writeBundle(plan.bundle());
      persistBundleApprovalGrants(bundle, currentGrants, plan.grants(), now);
      for (AppServiceGrant grant : plan.grants()) {
        appendAudit(
            renewal ? "grant_renewed" : "grant_bundle_approved",
            grant,
            null,
            null,
            "ok",
            renewal ? "grant_renewed" : "grant_active",
            null);
      }
      return bundleJson(
          plan.bundle(), installedServiceRequests(), installedServices(), store.listGrants());
    } catch (IOException _) {
      throw unavailable();
    }
  }

  private BundleApprovalPlan buildBundleApprovalPlan(
      AppServiceGrantBundle bundle,
      boolean renewal,
      List<AppServiceRequestDescriptor> dependencies,
      List<InstalledAppSnapshot> apps,
      List<AppServiceDescriptor> services,
      List<AppServiceGrant> currentGrants,
      Instant now) {
    ArrayList<String> grantIds = new ArrayList<>();
    ArrayList<AppServiceGrant> grants = new ArrayList<>();
    Instant bundleExpiresAt = null;
    List<AppServiceGrant> effectiveGrants = currentGrants;
    HashSet<String> plannedGrantIds = new HashSet<>();
    for (AppServiceRequestDescriptor dependency : dependencies) {
      DependencyEvaluation evaluation =
          evaluateDependency(dependency, apps, services, effectiveGrants);
      if (evaluation.descriptor() == null || !bundleApprovalEligible(evaluation.status())) {
        throw new PlatformApiException(
            409,
            "app_service_dependency_unavailable",
            "A bundled app-service dependency is not currently compatible.");
      }
      AppServiceDescriptor descriptor = evaluation.descriptor();
      ensureDescriptorSupported(descriptor);
      ensureNoFailedCleanup(dependency.consumerAppId(), dependency.providerAppId());
      Instant expiresAt = grantExpiresAt(dependency.dependency(), now);
      BundleGrantApprovalContext approvalContext =
          new BundleGrantApprovalContext(
              bundle, effectiveGrants, expiresAt, now, renewal, plannedGrantIds);
      AppServiceGrant grant = grantForBundleApproval(dependency, descriptor, approvalContext);
      if (grant.expiresAt() != null
          && (bundleExpiresAt == null || grant.expiresAt().isBefore(bundleExpiresAt))) {
        bundleExpiresAt = grant.expiresAt();
      }
      grants.add(grant);
      grantIds.add(grant.grantId());
      plannedGrantIds.add(grant.grantId());
      effectiveGrants = grantsWithReplacement(effectiveGrants, grant);
    }
    AppServiceGrantBundle approved =
        bundle.withStatus(
            AppServiceGrantBundleStatus.APPROVED,
            now,
            bundle.approvedAt() == null ? now : bundle.approvedAt(),
            bundle.rejectedAt(),
            bundleExpiresAt,
            renewal ? now : bundle.renewedAt(),
            grantIds);
    return new BundleApprovalPlan(approved, List.copyOf(grants));
  }

  private void persistBundleApprovalGrants(
      AppServiceGrantBundle originalBundle,
      List<AppServiceGrant> originalGrants,
      List<AppServiceGrant> approvedGrants,
      Instant now)
      throws IOException {
    ArrayList<AppServiceGrant> written = new ArrayList<>();
    try {
      for (AppServiceGrant grant : approvedGrants) {
        store.writeGrant(grant);
        written.add(grant);
      }
    } catch (IOException exception) {
      rollbackBundleApprovalWrites(originalBundle, originalGrants, written, now, exception);
      throw exception;
    }
  }

  private void rollbackBundleApprovalWrites(
      AppServiceGrantBundle originalBundle,
      List<AppServiceGrant> originalGrants,
      List<AppServiceGrant> written,
      Instant now,
      IOException cause) {
    try {
      store.writeBundle(originalBundle);
    } catch (IOException exception) {
      cause.addSuppressed(exception);
      LOG.log(
          System.Logger.Level.WARNING,
          "Failed to roll back app-service grant bundle after approval write failure",
          exception);
    }
    Map<String, AppServiceGrant> originalsById =
        LinkedHashMap.newLinkedHashMap(originalGrants.size());
    for (AppServiceGrant original : originalGrants) {
      originalsById.put(original.grantId(), original);
    }
    for (AppServiceGrant grant : written.reversed()) {
      AppServiceGrant replacement =
          originalsById.getOrDefault(
              grant.grantId(), grant.withStatus(AppServiceGrantStatus.INACTIVE, now));
      try {
        store.writeGrant(replacement);
      } catch (IOException exception) {
        cause.addSuppressed(exception);
        LOG.log(
            System.Logger.Level.WARNING,
            "Failed to roll back app-service grant after approval write failure",
            exception);
      }
    }
  }

  private static List<AppServiceGrant> grantsWithReplacement(
      List<AppServiceGrant> grants, AppServiceGrant replacement) {
    return Stream.concat(
            grants.stream().filter(grant -> !grant.grantId().equals(replacement.grantId())),
            Stream.of(replacement))
        .toList();
  }

  private AppServiceGrant grantForBundleApproval(
      AppServiceRequestDescriptor dependency,
      AppServiceDescriptor descriptor,
      BundleGrantApprovalContext approvalContext) {
    Optional<AppServiceGrant> existing =
        approvalContext.currentGrants().stream()
            .filter(grant -> grant.consumerAppId().equals(dependency.consumerAppId()))
            .filter(grant -> grant.providerAppId().equals(dependency.providerAppId()))
            .filter(grant -> grant.serviceId().equals(dependency.serviceId()))
            .filter(grant -> sameTokens(grant.scopes(), dependency.scopes()))
            .filter(grant -> sameTokens(grant.contexts(), dependency.contexts()))
            .filter(
                grant ->
                    grant.status() == AppServiceGrantStatus.PENDING
                        || grant.status() == AppServiceGrantStatus.ACTIVE)
            .findFirst();
    boolean reusePlannedGrant =
        existing
            .map(grant -> approvalContext.plannedGrantIds().contains(grant.grantId()))
            .orElse(false);
    AppServiceGrant grant =
        existing.orElseGet(
            () ->
                new AppServiceGrant(
                    newGrantId(
                        dependency.consumerAppId(),
                        dependency.providerAppId(),
                        dependency.serviceId(),
                        dependency.scopes(),
                        dependency.contexts(),
                        approvalContext.now()),
                    dependency.consumerAppId(),
                    dependency.providerAppId(),
                    dependency.serviceId(),
                    dependency.scopes(),
                    dependency.contexts(),
                    dependency.purpose(),
                    AppServiceGrantStatus.PENDING,
                    approvalContext.now(),
                    approvalContext.now(),
                    null,
                    null,
                    null,
                    0,
                    null));
    ensureGrantSupportedByDescriptor(grant, descriptor);
    Instant approvedExpiresAt =
        approvedGrantExpiresAt(
            grant, approvalContext.expiresAt(), approvalContext.renewal(), reusePlannedGrant);
    return grant.withApprovalMetadata(
        approvalContext.now(),
        approvalContext.bundle().bundleId(),
        approvedExpiresAt,
        approvalContext.renewal() ? approvalContext.now() : grant.renewedAt(),
        descriptor.compatibilityFingerprint(),
        descriptor.version());
  }

  private Instant approvedGrantExpiresAt(
      AppServiceGrant grant,
      Instant requestedExpiresAt,
      boolean renewal,
      boolean reusePlannedGrant) {
    if (renewal && !reusePlannedGrant) {
      return requestedExpiresAt;
    }
    if (!reusePlannedGrant && isExpired(grant.expiresAt())) {
      return requestedExpiresAt;
    }
    return mostRestrictiveExpiresAt(grant.expiresAt(), requestedExpiresAt);
  }

  private static Instant mostRestrictiveExpiresAt(Instant first, Instant second) {
    if (first == null) {
      return second;
    }
    if (second == null) {
      return first;
    }
    return first.isBefore(second) ? first : second;
  }

  private boolean bundleApprovalEligible(AppServiceDependencyStatus status) {
    return status == AppServiceDependencyStatus.AVAILABLE
        || status == AppServiceDependencyStatus.GRANT_PENDING
        || status == AppServiceDependencyStatus.GRANT_ACTIVE
        || status == AppServiceDependencyStatus.GRANT_EXPIRED
        || status == AppServiceDependencyStatus.REVALIDATION_REQUIRED;
  }

  private Instant grantExpiresAt(AppServiceDependencyDescriptor dependency, Instant now) {
    if (dependency.grantExpiresAfter() == null) {
      return null;
    }
    Duration capped =
        dependency.grantExpiresAfter().compareTo(MAX_BUNDLE_GRANT_DURATION) > 0
            ? MAX_BUNDLE_GRANT_DURATION
            : dependency.grantExpiresAfter();
    return now.plus(capped);
  }

  private AppServiceGrantBundle bundleRequired(String bundleId) {
    try {
      Optional<AppServiceGrantBundle> bundle = store.readBundle(bundleId);
      return bundle.orElseThrow(
          () ->
              new PlatformApiException(
                  404,
                  "app_service_bundle_not_found",
                  "The app-service grant bundle was not found."));
    } catch (IOException _) {
      throw unavailable();
    }
  }

  private List<AppServiceGrant> readGrants() {
    try {
      return store.listGrants();
    } catch (IOException _) {
      throw unavailable();
    }
  }

  private List<AppServiceDescriptor> installedServices() {
    return installedApps().stream()
        .flatMap(this::providedServices)
        .sorted(
            Comparator.comparing(AppServiceDescriptor::providerAppId)
                .thenComparing(AppServiceDescriptor::serviceId))
        .toList();
  }

  private List<AppServiceRequestDescriptor> installedServiceRequests() {
    return installedApps().stream()
        .flatMap(this::serviceRequests)
        .sorted(
            Comparator.comparing(AppServiceRequestDescriptor::consumerAppId)
                .thenComparing(AppServiceRequestDescriptor::providerAppId)
                .thenComparing(AppServiceRequestDescriptor::serviceId))
        .toList();
  }

  private List<InstalledAppSnapshot> installedApps() {
    if (appHost == null) {
      throw new PlatformApiException(
          503, "app_services_unavailable", "App-service discovery is unavailable.");
    }
    try {
      return appHost.listInstalled();
    } catch (IOException _) {
      throw unavailable();
    }
  }

  private Stream<AppServiceDescriptor> providedServices(InstalledAppSnapshot snapshot) {
    try {
      return AppServiceManifestParser.parseProvidedServices(
          snapshot.manifest(), snapshot.paths().manifestFile())
          .stream();
    } catch (IOException | PlatformApiException exception) {
      LOG.log(
          System.Logger.Level.WARNING, "Ignoring invalid app-service provider metadata", exception);
      return Stream.empty();
    }
  }

  private Stream<AppServiceRequestDescriptor> serviceRequests(InstalledAppSnapshot snapshot) {
    try {
      return AppServiceManifestParser.parseServiceRequests(
          snapshot.manifest(), snapshot.paths().manifestFile())
          .stream();
    } catch (IOException | PlatformApiException exception) {
      LOG.log(
          System.Logger.Level.WARNING, "Ignoring invalid app-service request metadata", exception);
      return Stream.empty();
    }
  }

  private AppServiceDescriptor serviceRequired(String providerAppId, String serviceId) {
    String provider = AppServiceManifestParser.normalizeAppId(providerAppId);
    String service = AppServiceManifestParser.normalizeServiceId(serviceId);
    ensureProviderInstalled(provider);
    return installedServices().stream()
        .filter(
            descriptor ->
                descriptor.providerAppId().equals(provider)
                    && descriptor.serviceId().equals(service))
        .findFirst()
        .orElseThrow(
            () ->
                new PlatformApiException(
                    404, "app_service_not_found", "The requested app service is not advertised."));
  }

  private void ensureProviderInstalled(String providerAppId) {
    if (installedApps().stream().noneMatch(snapshot -> snapshot.appId().equals(providerAppId))) {
      throw new PlatformApiException(
          404, "provider_app_not_found", "The provider app is not installed.");
    }
  }

  private void ensureConsumerCanCall(String consumerAppId) {
    InstalledAppSnapshot consumer =
        installedApps().stream()
            .filter(snapshot -> snapshot.appId().equals(consumerAppId))
            .findFirst()
            .orElseThrow(
                () ->
                    new PlatformApiException(
                        403, "consumer_app_not_installed", "The consumer app is not installed."));
    if (!consumer.manifest().permissions().contains(CAPABILITY_APP_SERVICES_CALL)) {
      throw new PlatformApiException(
          403,
          "app_services_call_permission_missing",
          "The consumer app manifest no longer declares app.services.call.");
    }
  }

  private AppServiceGrant grantRequired(String grantId) {
    try {
      Optional<AppServiceGrant> grant = store.readGrant(grantId);
      return grant.orElseThrow(
          () ->
              new PlatformApiException(
                  404, "app_service_grant_not_found", "The app-service grant was not found."));
    } catch (IOException _) {
      throw unavailable();
    }
  }

  private AppServiceGrant activeGrant(
      String consumerAppId,
      AppServiceDescriptor descriptor,
      String scope,
      String context,
      Map<String, List<String>> parameters) {
    try {
      Optional<AppServiceGrant> active =
          store.listGrants().stream()
              .filter(grant -> grant.consumerAppId().equals(consumerAppId))
              .filter(grant -> grant.providerAppId().equals(descriptor.providerAppId()))
              .filter(grant -> grant.serviceId().equals(descriptor.serviceId()))
              .filter(grant -> grant.status() == AppServiceGrantStatus.ACTIVE)
              .filter(grant -> effectiveStatus(grant) == AppServiceGrantStatus.ACTIVE)
              .filter(grant -> grantSupportedByDescriptor(grant, descriptor))
              .filter(grant -> grant.scopes().contains(scope))
              .filter(grant -> grantCoversContext(descriptor, grant, context))
              .findFirst();
      if (active.isPresent()) {
        return active.get();
      }
      AppServiceGrant auditGrant =
          new AppServiceGrant(
              "asg-" + "0".repeat(24),
              consumerAppId,
              descriptor.providerAppId(),
              descriptor.serviceId(),
              List.of(scope),
              context == null ? List.of() : List.of(context),
              "Invocation denied because no active grant matched.",
              AppServiceGrantStatus.PENDING,
              clock.instant(),
              clock.instant(),
              null,
              null,
              null,
              0,
              null);
      appendAudit(
          AUDIT_EVENT_SERVICE_INVOCATION_DENIED,
          auditGrant,
          scope,
          context,
          AUDIT_STATUS_DENIED,
          "active_grant_required",
          parameters);
      throw new PlatformApiException(
          403,
          "app_service_grant_required",
          "An active app-service grant is required for this invocation.");
    } catch (IOException _) {
      throw unavailable();
    }
  }

  private boolean grantCoversContext(
      AppServiceDescriptor descriptor, AppServiceGrant grant, String context) {
    if (descriptor.contexts().isEmpty()) {
      return grant.contexts().isEmpty() || (context != null && grant.contexts().contains(context));
    }
    return context != null && grant.contexts().contains(context);
  }

  private AppServiceGrantStatus effectiveStatus(AppServiceGrant grant) {
    if (grant.status() != AppServiceGrantStatus.ACTIVE) {
      return grant.status();
    }
    if (isExpired(grant.expiresAt())) {
      return AppServiceGrantStatus.EXPIRED;
    }
    if (cleanupFailedFor(grant)) {
      return AppServiceGrantStatus.INACTIVE;
    }
    if (!consumerCanCall(grant.consumerAppId())) {
      return AppServiceGrantStatus.INACTIVE;
    }
    boolean providerInstalled =
        installedApps().stream()
            .anyMatch(snapshot -> snapshot.appId().equals(grant.providerAppId()));
    if (!providerInstalled) {
      return AppServiceGrantStatus.INACTIVE;
    }
    Optional<AppServiceDescriptor> descriptor =
        installedServices().stream()
            .filter(service -> service.providerAppId().equals(grant.providerAppId()))
            .filter(service -> service.serviceId().equals(grant.serviceId()))
            .findFirst();
    if (descriptor.isEmpty()) {
      return AppServiceGrantStatus.INACTIVE;
    }
    if (!grantSupportedByDescriptor(grant, descriptor.get())
        || !approvalMetadataStillMatches(grant, descriptor.get())) {
      return AppServiceGrantStatus.REVALIDATION_REQUIRED;
    }
    return AppServiceGrantStatus.ACTIVE;
  }

  private Optional<AppServiceGrant> existingReusableGrant(
      String consumerAppId,
      String providerAppId,
      String serviceId,
      List<String> scopes,
      List<String> contexts)
      throws IOException {
    return store.listGrants().stream()
        .filter(grant -> grant.consumerAppId().equals(consumerAppId))
        .filter(grant -> grant.providerAppId().equals(providerAppId))
        .filter(grant -> grant.serviceId().equals(serviceId))
        .filter(grant -> sameTokens(grant.scopes(), scopes))
        .filter(grant -> sameTokens(grant.contexts(), contexts))
        .filter(this::grantCanBeReusedForRequest)
        .findFirst();
  }

  private boolean grantCanBeReusedForRequest(AppServiceGrant grant) {
    if (grant.status() == AppServiceGrantStatus.PENDING) {
      return true;
    }
    return grant.status() == AppServiceGrantStatus.ACTIVE
        && effectiveStatus(grant) == AppServiceGrantStatus.ACTIVE;
  }

  private boolean consumerCanCall(String consumerAppId) {
    return installedApps().stream()
        .filter(snapshot -> snapshot.appId().equals(consumerAppId))
        .findFirst()
        .map(snapshot -> snapshot.manifest().permissions().contains(CAPABILITY_APP_SERVICES_CALL))
        .orElse(false);
  }

  private void ensureNoFailedCleanup(String consumerAppId, String providerAppId) {
    if (cleanupFailedAppIds.contains(consumerAppId)
        || cleanupFailedAppIds.contains(providerAppId)) {
      throw unavailable();
    }
  }

  private boolean cleanupFailedFor(AppServiceGrant grant) {
    return cleanupFailedAppIds.contains(grant.consumerAppId())
        || cleanupFailedAppIds.contains(grant.providerAppId());
  }

  private void appendAudit(
      String eventType,
      AppServiceGrant grant,
      String scope,
      String context,
      String status,
      String reasonCode,
      Map<String, List<String>> parameters) {
    try {
      String subjectUri =
          parameters == null
              ? null
              : PlatformApiParameters.readOptionalString(parameters, PARAM_SUBJECT_URI);
      Instant now = clock.instant();
      store.appendAuditEvent(
          new AppServiceAuditEvent(
              newEventId(
                  eventType,
                  grant.grantId(),
                  now,
                  auditEventRunId,
                  auditEventSequence.incrementAndGet()),
              now,
              eventType,
              grant.consumerAppId(),
              grant.providerAppId(),
              grant.serviceId(),
              grant.grantId(),
              scope,
              context,
              status,
              reasonCode,
              subjectUri == null ? null : TrustGraphScoreAppServiceAdapter.sha256(subjectUri)));
    } catch (IOException | PlatformApiException exception) {
      LOG.log(System.Logger.Level.WARNING, "Failed to append app-service audit event", exception);
    }
  }

  private Map<String, Object> serviceCallEnvelope(
      AppServiceDescriptor descriptor,
      AppServiceGrant grant,
      Instant invokedAt,
      Map<String, Object> result) {
    LinkedHashMap<String, Object> serviceCall = LinkedHashMap.newLinkedHashMap(6);
    serviceCall.put(PARAM_PROVIDER_APP_ID, descriptor.providerAppId());
    serviceCall.put(PARAM_SERVICE_ID, descriptor.serviceId());
    serviceCall.put("grantId", grant.grantId());
    serviceCall.put(FIELD_STATUS, "ok");
    serviceCall.put("invokedAt", invokedAt.toString());
    serviceCall.put("result", result);
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put("serviceCall", serviceCall);
    return envelope;
  }

  private List<String> requestedContexts(Map<String, List<String>> parameters) {
    String raw = PlatformApiParameters.readOptionalString(parameters, PARAM_CONTEXTS);
    if (raw == null) {
      raw = PlatformApiParameters.readOptionalString(parameters, PARAM_CONTEXT);
    }
    return AppServiceManifestParser.commaList(raw, PARAM_CONTEXTS);
  }

  private String requestedContext(
      Map<String, List<String>> parameters, AppServiceDescriptor descriptor) {
    if (descriptor.contexts().isEmpty()) {
      return null;
    }
    return AppServiceManifestParser.normalizeToken(
        PARAM_CONTEXT, PlatformApiParameters.requireString(parameters, PARAM_CONTEXT));
  }

  private static Map<String, List<String>> withInvocationContext(
      Map<String, List<String>> parameters, String context) {
    if (context == null) {
      if (!parameters.containsKey(PARAM_CONTEXT)) {
        return parameters;
      }
      LinkedHashMap<String, List<String>> normalized = new LinkedHashMap<>(parameters);
      normalized.remove(PARAM_CONTEXT);
      return normalized;
    }
    LinkedHashMap<String, List<String>> normalized = new LinkedHashMap<>(parameters);
    normalized.put(PARAM_CONTEXT, List.of(context));
    return normalized;
  }

  private void ensureGrantSupportedByDescriptor(
      AppServiceGrant grant, AppServiceDescriptor descriptor) {
    if (!grantSupportedByDescriptor(grant, descriptor)) {
      throw new PlatformApiException(
          409,
          "app_service_grant_stale",
          "The app-service grant no longer matches the provider service descriptor.");
    }
  }

  private boolean grantSupportedByDescriptor(
      AppServiceGrant grant, AppServiceDescriptor descriptor) {
    if (descriptorUnsupported(descriptor)) {
      return false;
    }
    if (descriptor.hasUnsupportedScopes(grant.scopes())) {
      return false;
    }
    if (descriptor.contexts().isEmpty()) {
      return grant.contexts().isEmpty();
    }
    if (grant.contexts().isEmpty()) {
      return false;
    }
    return grant.contexts().stream().allMatch(descriptor::supportsContext);
  }

  private void ensureDescriptorSupported(AppServiceDescriptor descriptor) {
    if (!SUPPORTED_SERVICE_KIND.equals(descriptor.kind())) {
      throw new PlatformApiException(
          400,
          "app_service_kind_unsupported",
          "The service descriptor uses an unsupported adapter kind.");
    }
    if (!adapters.containsKey(descriptor.adapter())) {
      throw new PlatformApiException(
          404,
          "app_service_adapter_missing",
          "No platform adapter is registered for this service.");
    }
  }

  private boolean descriptorUnsupported(AppServiceDescriptor descriptor) {
    return !SUPPORTED_SERVICE_KIND.equals(descriptor.kind())
        || !adapters.containsKey(descriptor.adapter());
  }

  private boolean approvalMetadataStillMatches(
      AppServiceGrant grant, AppServiceDescriptor descriptor) {
    if (grant.providerServiceVersionAtApproval() != null
        && !grant.providerServiceVersionAtApproval().equals(descriptor.version())) {
      return false;
    }
    return grant.compatibilityFingerprint() == null
        || grant.compatibilityFingerprint().equals(descriptor.compatibilityFingerprint());
  }

  private boolean isExpired(Instant expiresAt) {
    return expiresAt != null && !expiresAt.isAfter(clock.instant());
  }

  private String requestedScope(
      Map<String, List<String>> parameters, AppServiceDescriptor descriptor) {
    String raw = PlatformApiParameters.readOptionalString(parameters, PARAM_SCOPE);
    if (raw == null || raw.isBlank()) {
      return descriptor.scopes().contains(REQUIRED_TRUST_SCORE_SCOPE)
          ? REQUIRED_TRUST_SCORE_SCOPE
          : descriptor.scopes().getFirst();
    }
    String scope = AppServiceManifestParser.normalizeToken(PARAM_SCOPE, raw);
    if (!descriptor.scopes().contains(scope)) {
      throw new PlatformApiException(
          400, "app_service_scope_unsupported", "The service does not support this scope.");
    }
    return scope;
  }

  private int readLimit(Map<String, List<String>> parameters) {
    String raw = PlatformApiParameters.readOptionalString(parameters, "limit");
    if (raw == null || raw.isBlank()) {
      return DEFAULT_AUDIT_LIMIT;
    }
    try {
      int parsed = Integer.parseInt(raw.trim());
      if (parsed <= 0) {
        throw new NumberFormatException("non-positive");
      }
      return Math.min(parsed, 200);
    } catch (NumberFormatException _) {
      throw new PlatformApiException(
          400, "invalid_query_parameter", "Query parameter 'limit' must be a positive integer.");
    }
  }

  private String requireAppPrincipal(PlatformApiPrincipal principal) {
    if (!principal.isApp()) {
      throw new PlatformApiException(
          403, "forbidden", "This Platform API route requires an app principal.");
    }
    return principal.appId();
  }

  private void requireHostOperator(PlatformApiPrincipal principal, String message) {
    if (principal.isApp()) {
      throw new PlatformApiException(403, "forbidden", message);
    }
  }

  private static PlatformApiException unavailable() {
    return new PlatformApiException(
        503, "app_services_unavailable", "App-service storage or discovery is unavailable.");
  }

  private static String newGrantId(
      String consumerAppId,
      String providerAppId,
      String serviceId,
      List<String> scopes,
      List<String> contexts,
      Instant now) {
    return "asg-"
        + hashHex(
                consumerAppId
                    + "|"
                    + providerAppId
                    + "|"
                    + serviceId
                    + "|"
                    + String.join(",", scopes)
                    + "|"
                    + String.join(",", contexts)
                    + "|"
                    + now)
            .substring(0, 24);
  }

  private static String newBundleId(
      String consumerAppId, String bundleAlias, List<String> aliases, Instant now) {
    return "asb-"
        + hashHex(
                consumerAppId
                    + "|"
                    + (bundleAlias == null ? "" : bundleAlias)
                    + "|"
                    + String.join(",", aliases)
                    + "|"
                    + now)
            .substring(0, 24);
  }

  private static String newEventId(
      String eventType, String grantId, Instant now, String runId, long sequence) {
    return "ase-"
        + hashHex(eventType + "|" + grantId + "|" + now + "|" + runId + "|" + sequence)
            .substring(0, 24);
  }

  private static boolean sameTokens(List<String> first, List<String> second) {
    return Set.copyOf(first).equals(Set.copyOf(second));
  }

  private static String optionalAlias(String value) {
    return value == null || value.isBlank() ? null : AppServiceManifestParser.normalizeAlias(value);
  }

  static String hashHex(String value) {
    try {
      java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
      return HEX.formatHex(digest.digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is required", exception);
    }
  }

  private record BundleApprovalPlan(AppServiceGrantBundle bundle, List<AppServiceGrant> grants) {}

  private record BundleGrantApprovalContext(
      AppServiceGrantBundle bundle,
      List<AppServiceGrant> currentGrants,
      Instant expiresAt,
      Instant now,
      boolean renewal,
      Set<String> plannedGrantIds) {}

  private record GrantMatch(AppServiceGrant grant, AppServiceGrantStatus status) {}

  private record DependencyEvaluation(
      AppServiceDependencyStatus status, AppServiceDescriptor descriptor, AppServiceGrant grant) {}
}
