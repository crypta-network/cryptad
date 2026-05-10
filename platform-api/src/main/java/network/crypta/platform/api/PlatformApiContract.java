package network.crypta.platform.api;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Deterministic compatibility contract for one Platform API surface.
 *
 * <p>The contract is the app-facing metadata artifact for Platform API v1. It names the current URL
 * API version, the integer compatibility contract version used by app manifests and catalogs, the
 * stable capability vocabulary, and the route/action descriptors used by app-principal
 * authorization. It intentionally contains no request bodies, query strings, local paths, command
 * lines, tokens, or private key material.
 *
 * <p>The current contract is process-local and immutable. Platform API authorization consults these
 * endpoint descriptors when app token or app browser-session principals make requests, while
 * developer tooling and release certification serialize the same model for offline compatibility
 * checks. That keeps the published contract and the authorization matrix tied to one descriptor
 * set.
 *
 * <p>All descriptor collections are copied during construction. Callers can safely retain a
 * contract instance, compare snapshots, or use it from multiple request threads without additional
 * synchronization.
 *
 * @param apiVersion URL API version such as {@code v1}
 * @param contractVersion integer app compatibility contract version
 * @param generatedBy stable producer label for snapshots
 * @param stabilityPolicy short human-readable stability policy
 * @param capabilities deterministic public capability descriptors
 * @param endpoints deterministic public endpoint descriptors
 */
public record PlatformApiContract(
    String apiVersion,
    int contractVersion,
    String generatedBy,
    String stabilityPolicy,
    List<PlatformApiCapabilityDescriptor> capabilities,
    List<PlatformApiEndpointDescriptor> endpoints) {
  /**
   * URL API version covered by the current app-facing contract.
   *
   * <p>This value describes the route prefix, for example {@code /api/v1}. It is intentionally
   * separate from {@link #CURRENT_CONTRACT_VERSION}, which is the compatibility version app
   * manifests and catalogs use for install and release-review decisions.
   */
  public static final String CURRENT_API_VERSION = "v1";

  /**
   * Integer compatibility contract version used by app manifests and catalogs.
   *
   * <p>The value increases only when the app-facing Platform API compatibility surface changes in a
   * way that tooling should be able to compare. It is not the Cryptad build number, and it is not
   * the URL API version.
   */
  public static final int CURRENT_CONTRACT_VERSION = 3;

  private static final int INITIAL_CONTRACT_VERSION = 1;
  private static final int APP_UPDATE_LIFECYCLE_CONTRACT_VERSION = 2;
  private static final int APP_VAULT_CONTRACT_VERSION = 3;

  /**
   * Stable producer label written into generated contract snapshots.
   *
   * <p>The label identifies the contract source without embedding host-specific details. Snapshot
   * consumers can use it for display and provenance, but it is not intended as an authentication
   * mechanism.
   */
  public static final String GENERATED_BY = "cryptad";

  private static final String STABILITY_POLICY =
      "Stable endpoints and capabilities remain available within Platform API v1 contract version "
          + CURRENT_CONTRACT_VERSION
          + ". Endpoint descriptors retain the contract version where each route first appeared. "
          + "Experimental, deprecated, scheduled-for-removal, and internal entries are flagged for "
          + "developer tooling and release review before behavior changes.";

  private static final String ROUTE_FAMILY_APPS = "apps";
  private static final String ROUTE_FAMILY_APP_CATALOGS = "app-catalogs";
  private static final String ROUTE_FAMILY_APP_VAULT = "app-vault";
  private static final String ROUTE_FAMILY_CONFIG = "config";
  private static final String ROUTE_FAMILY_IDENTITY_VAULT = "identity-vault";
  private static final String ROUTE_FAMILY_PEERS = "peers";
  private static final String ROUTE_FAMILY_QUEUE = "queue";
  private static final String ROUTE_FAMILY_SECURITY_LEVELS = "security-levels";
  private static final String ROUTE_APP_VAULT_SECRET = "/app-vault/secrets/{name}";
  private static final String ROUTE_IDENTITY_VAULT_GRANT = "/identity-vault/grants/{grantId}";
  private static final String METHOD_DELETE = "DELETE";
  private static final String METHOD_GET = "GET";
  private static final String METHOD_PATCH = "PATCH";
  private static final String METHOD_POST = "POST";
  private static final String METHOD_PUT = "PUT";
  private static final List<String> APP_CATALOG_UPDATE_MANAGE_CAPABILITIES =
      List.of(PlatformApiCapabilities.APPS_MANAGE, PlatformApiCapabilities.CATALOGS_MANAGE);

  private static final PlatformApiContract CURRENT =
      new PlatformApiContract(
          CURRENT_API_VERSION,
          CURRENT_CONTRACT_VERSION,
          GENERATED_BY,
          STABILITY_POLICY,
          capabilityDescriptors(),
          endpointDescriptors());

  /**
   * Creates a normalized immutable contract model.
   *
   * <p>The constructor validates only the structural rules that must hold for any contract
   * snapshot: text fields must be present, the contract version must be positive, descriptor
   * collections must be non-null, capability names must be unique, and every endpoint-required
   * capability must have a corresponding capability descriptor. It does not sort the supplied
   * descriptors; callers provide the intended deterministic order.
   */
  public PlatformApiContract {
    PlatformApiContractVersion version =
        new PlatformApiContractVersion(apiVersion, contractVersion);
    apiVersion = version.apiVersion();
    contractVersion = version.contractVersion();
    generatedBy = requireText(generatedBy, "generatedBy");
    stabilityPolicy = requireText(stabilityPolicy, "stabilityPolicy");
    capabilities = List.copyOf(Objects.requireNonNull(capabilities, "capabilities"));
    endpoints = List.copyOf(Objects.requireNonNull(endpoints, "endpoints"));
    requireEndpointCapabilitiesKnown(capabilities, endpoints);
  }

  /**
   * Returns the process-local Platform API v1 contract.
   *
   * <p>The returned instance is shared and immutable. It is safe for request routing,
   * app-management summaries, developer CLI snapshots, and release-certification checks to reuse
   * the same object without defensive copying.
   *
   * @return deterministic current Platform API compatibility contract for this build
   */
  public static PlatformApiContract current() {
    return CURRENT;
  }

  /**
   * Returns the typed API and compatibility contract version pair for this contract.
   *
   * <p>The record form is useful for callers that need to pass the URL API version and integer
   * compatibility version together without implying they advance in lockstep. JSON serialization
   * still emits the two fields separately to preserve the public snapshot shape.
   *
   * @return validated version pair for this contract instance
   */
  public PlatformApiContractVersion version() {
    return new PlatformApiContractVersion(apiVersion, contractVersion);
  }

  /**
   * Returns all capability names in deterministic lexicographic order.
   *
   * <p>This helper is intended for linting, manifest validation, and drift tests that only need the
   * public capability vocabulary. The returned set is immutable and detached from the descriptor
   * list stored in the contract.
   *
   * @return immutable sorted capability vocabulary exposed to app manifests
   */
  public Set<String> capabilityNames() {
    TreeSet<String> names = new TreeSet<>();
    for (PlatformApiCapabilityDescriptor descriptor : capabilities) {
      names.add(descriptor.name());
    }
    return java.util.Collections.unmodifiableSet(names);
  }

  /**
   * Finds the contract endpoint matching one normalized request.
   *
   * <p>Routing code calls this method after it has decoded the request path below {@code /api/v1}.
   * The lookup is deliberately descriptor-based rather than hard-coded in the authorization layer,
   * so an endpoint added to the public contract is also the endpoint the app-principal matrix uses.
   * Host/operator authorization bypasses this app-principal lookup through the existing local-admin
   * model.
   *
   * @param method HTTP-style method name; it is normalized to upper case before matching
   * @param pathSegments decoded Platform API path segments beneath {@code /api/v1}
   * @param principalType principal type being authorized for this request
   * @return matching descriptor, or {@code null} when no app-visible contract entry matches
   */
  PlatformApiEndpointDescriptor endpointFor(
      String method, List<String> pathSegments, PlatformApiPrincipalType principalType) {
    String normalizedMethod = Objects.requireNonNull(method, "method").toUpperCase(Locale.ROOT);
    List<String> segments = List.copyOf(Objects.requireNonNull(pathSegments, "pathSegments"));
    for (PlatformApiEndpointDescriptor endpoint : endpoints) {
      if (endpoint.matches(normalizedMethod, segments) && endpoint.allowsPrincipal(principalType)) {
        return endpoint;
      }
    }
    return null;
  }

  /**
   * Returns capability descriptors keyed by capability name.
   *
   * <p>The map preserves the descriptor order from the contract list. Callers use it when verifying
   * manifest permissions or optional capabilities and need stability metadata for a known
   * capability name.
   *
   * @return deterministic immutable capability descriptor lookup by manifest capability name
   */
  Map<String, PlatformApiCapabilityDescriptor> capabilitiesByName() {
    LinkedHashMap<String, PlatformApiCapabilityDescriptor> byName =
        LinkedHashMap.newLinkedHashMap(capabilities.size());
    for (PlatformApiCapabilityDescriptor descriptor : capabilities) {
      byName.put(descriptor.name(), descriptor);
    }
    return java.util.Collections.unmodifiableMap(byName);
  }

  private static void requireEndpointCapabilitiesKnown(
      List<PlatformApiCapabilityDescriptor> capabilities,
      List<PlatformApiEndpointDescriptor> endpoints) {
    Set<String> names = new TreeSet<>();
    for (PlatformApiCapabilityDescriptor descriptor : capabilities) {
      if (!names.add(descriptor.name())) {
        throw new IllegalArgumentException("duplicate capability descriptor: " + descriptor.name());
      }
    }
    for (PlatformApiEndpointDescriptor endpoint : endpoints) {
      for (String capability : endpoint.requiredCapabilities()) {
        if (!names.contains(capability)) {
          throw new IllegalArgumentException(
              "endpoint references unknown capability: " + capability);
        }
      }
    }
  }

  private static List<PlatformApiCapabilityDescriptor> capabilityDescriptors() {
    return List.of(
        capability(PlatformApiCapabilities.ALERTS_READ, "Read current runtime alerts."),
        capability(PlatformApiCapabilities.ALERTS_WRITE, "Dismiss operator-visible alerts."),
        capability(
            PlatformApiCapabilities.APPS_MANAGE, "Install, update, start, stop, or remove apps."),
        capability(
            PlatformApiCapabilities.APPS_READ, "Read installed app summaries and diagnostics."),
        capability(
            PlatformApiCapabilities.CATALOGS_MANAGE,
            "Add, refresh, remove, install from, or update from app catalogs."),
        capability(
            PlatformApiCapabilities.CATALOGS_READ, "Read signed app-catalog sources and entries."),
        capability(PlatformApiCapabilities.CONFIG_READ, "Read configuration projections."),
        capability(
            PlatformApiCapabilities.CONFIG_WRITE, "Apply and persist configuration changes."),
        capability(PlatformApiCapabilities.CONNECTIVITY_READ, "Read connectivity diagnostics."),
        capability(
            PlatformApiCapabilities.CONTENT_INSERT,
            "Create local file or directory insert requests."),
        capability(PlatformApiCapabilities.DIAGNOSTICS_READ, "Read runtime diagnostic reports."),
        capability(
            PlatformApiCapabilities.NODE_READ, "Read node identity, greeting, and reference data."),
        capability(PlatformApiCapabilities.PEERS_READ, "Read peer summaries and peer details."),
        capability(PlatformApiCapabilities.PEERS_WRITE, "Add, update, annotate, or remove peers."),
        capability(
            PlatformApiCapabilities.PLATFORM_CONTRACT_READ,
            "Read the public Platform API compatibility contract."),
        capability(
            PlatformApiCapabilities.QUEUE_READ,
            "Read queue pages, counts, keys, and completion state."),
        capability(
            PlatformApiCapabilities.QUEUE_WRITE,
            "Create downloads or mutate existing queue entries."),
        capability(
            PlatformApiCapabilities.SECURITY_READ, "Read security-level state and warnings."),
        capability(PlatformApiCapabilities.SECURITY_WRITE, "Change security-level settings."),
        capability(PlatformApiCapabilities.UPDATES_READ, "Read core update state."),
        capability(PlatformApiCapabilities.UPDATES_WRITE, "Trigger core update actions."),
        experimentalCapability(
            PlatformApiCapabilities.VAULT_IDENTITIES_CREATE,
            "Create app-owned vault identities without exposing private key material."),
        experimentalCapability(
            PlatformApiCapabilities.VAULT_IDENTITIES_MANAGE,
            "Manage vault identity grants through host/operator routes."),
        experimentalCapability(
            PlatformApiCapabilities.VAULT_IDENTITIES_READ,
            "Read vault identity metadata granted to the calling app."),
        experimentalCapability(
            PlatformApiCapabilities.VAULT_IDENTITIES_USE,
            "Use granted vault identities for approved bounded operations."),
        experimentalCapability(
            PlatformApiCapabilities.VAULT_SECRETS_READ,
            "Read app-owned secret values from the process-only vault API."),
        experimentalCapability(
            PlatformApiCapabilities.VAULT_SECRETS_WRITE,
            "Create, replace, or delete app-owned secret values through the process-only vault"
                + " API."),
        capability(PlatformApiCapabilities.WIZARD_READ, "Read first-time wizard state."),
        capability(PlatformApiCapabilities.WIZARD_WRITE, "Submit first-time wizard choices."));
  }

  private static List<PlatformApiEndpointDescriptor> endpointDescriptors() {
    EndpointBuilder builder = new EndpointBuilder();
    builder.get(
        "node",
        "/node/greeting",
        PlatformApiCapabilities.NODE_READ,
        PlatformApiCapabilities.NODE_READ,
        "Read the node greeting snapshot.");
    builder.get(
        "node",
        "/node/reference",
        PlatformApiCapabilities.NODE_READ,
        PlatformApiCapabilities.NODE_READ,
        "Read the node reference export.");
    builder.get(
        "connectivity",
        "/connectivity",
        PlatformApiCapabilities.CONNECTIVITY_READ,
        PlatformApiCapabilities.CONNECTIVITY_READ,
        "Read connectivity diagnostics.");
    builder.get(
        "diagnostics",
        "/diagnostics",
        PlatformApiCapabilities.DIAGNOSTICS_READ,
        PlatformApiCapabilities.DIAGNOSTICS_READ,
        "Read runtime diagnostic sections and plain-text export.");
    builder.get(
        "alerts",
        "/alerts",
        PlatformApiCapabilities.ALERTS_READ,
        PlatformApiCapabilities.ALERTS_READ,
        "Read current runtime alerts.");
    builder.post(
        "alerts",
        "/alerts/{alertId}/dismiss",
        "alerts.dismiss",
        List.of(PlatformApiCapabilities.ALERTS_WRITE),
        "Dismiss one operator-visible alert.");
    builder.get(
        ROUTE_FAMILY_CONFIG,
        "/config",
        PlatformApiCapabilities.CONFIG_READ,
        PlatformApiCapabilities.CONFIG_READ,
        "Read exported configuration projections.");
    builder.post(
        ROUTE_FAMILY_CONFIG,
        "/config/overrides",
        "config.overrides",
        List.of(PlatformApiCapabilities.CONFIG_WRITE),
        "Apply configuration overrides.");
    builder.post(
        ROUTE_FAMILY_CONFIG,
        "/config/persist",
        "config.persist",
        List.of(PlatformApiCapabilities.CONFIG_WRITE),
        "Persist current configuration values.");
    builder.get(
        ROUTE_FAMILY_SECURITY_LEVELS,
        "/security-levels",
        PlatformApiCapabilities.SECURITY_READ,
        PlatformApiCapabilities.SECURITY_READ,
        "Read security-level state.");
    builder.get(
        ROUTE_FAMILY_SECURITY_LEVELS,
        "/security-levels/network-warning",
        "security.network-warning",
        PlatformApiCapabilities.SECURITY_READ,
        "Read the network threat-level warning.");
    builder.post(
        ROUTE_FAMILY_SECURITY_LEVELS,
        "/security-levels/network",
        "security.network",
        List.of(PlatformApiCapabilities.SECURITY_WRITE),
        "Change the network threat level.");
    builder.post(
        ROUTE_FAMILY_SECURITY_LEVELS,
        "/security-levels/physical",
        "security.physical",
        List.of(PlatformApiCapabilities.SECURITY_WRITE),
        "Change the physical threat level.");
    builder.get(
        "updates",
        "/updates/core",
        PlatformApiCapabilities.UPDATES_READ,
        PlatformApiCapabilities.UPDATES_READ,
        "Read core update state.");
    builder.post(
        "updates",
        "/updates/core/download",
        "updates.core.download",
        List.of(PlatformApiCapabilities.UPDATES_WRITE),
        "Start a core package download.");
    builder.get(
        "wizard",
        "/wizard/first-time",
        PlatformApiCapabilities.WIZARD_READ,
        PlatformApiCapabilities.WIZARD_READ,
        "Read first-time wizard state.");
    builder.post(
        "wizard",
        "/wizard/first-time/apply",
        "wizard.first-time.apply",
        List.of(PlatformApiCapabilities.WIZARD_WRITE),
        "Apply first-time wizard choices.");
    builder.get(
        ROUTE_FAMILY_QUEUE,
        "/queue",
        PlatformApiCapabilities.QUEUE_READ,
        PlatformApiCapabilities.QUEUE_READ,
        "Read the queue snapshot.");
    builder.get(
        ROUTE_FAMILY_QUEUE,
        "/queue/count",
        PlatformApiCapabilities.QUEUE_READ,
        PlatformApiCapabilities.QUEUE_READ,
        "Read queue counts.");
    builder.get(
        ROUTE_FAMILY_QUEUE,
        "/queue/keys",
        PlatformApiCapabilities.QUEUE_READ,
        PlatformApiCapabilities.QUEUE_READ,
        "Read queue key exports.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/downloads",
        "queue.downloads.create",
        List.of(PlatformApiCapabilities.QUEUE_WRITE),
        "Create a direct download request.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/inserts/file",
        "queue.inserts.file",
        List.of(PlatformApiCapabilities.CONTENT_INSERT, PlatformApiCapabilities.QUEUE_WRITE),
        "Create a local file insert request.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/inserts/directory",
        "queue.inserts.directory",
        List.of(PlatformApiCapabilities.CONTENT_INSERT, PlatformApiCapabilities.QUEUE_WRITE),
        "Create a local directory insert request.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/requests/remove",
        "queue.requests.remove",
        List.of(PlatformApiCapabilities.QUEUE_WRITE),
        "Remove queue requests.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/requests/restart",
        "queue.requests.restart",
        List.of(PlatformApiCapabilities.QUEUE_WRITE),
        "Restart queue requests.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/requests/priority",
        "queue.requests.priority",
        List.of(PlatformApiCapabilities.QUEUE_WRITE),
        "Change queue request priority.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/cleanup/uploads",
        "queue.cleanup.uploads",
        List.of(PlatformApiCapabilities.QUEUE_WRITE),
        "Clean completed upload requests.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/cleanup/downloads",
        "queue.cleanup.downloads",
        List.of(PlatformApiCapabilities.QUEUE_WRITE),
        "Clean completed download requests.");
    builder.get(
        ROUTE_FAMILY_PEERS,
        "/peers",
        PlatformApiCapabilities.PEERS_READ,
        PlatformApiCapabilities.PEERS_READ,
        "Read peer summaries.");
    builder.get(
        ROUTE_FAMILY_PEERS,
        "/peers/{peerId}",
        PlatformApiCapabilities.PEERS_READ,
        PlatformApiCapabilities.PEERS_READ,
        "Read one peer detail.");
    builder.post(
        ROUTE_FAMILY_PEERS,
        "/peers/add",
        "peers.add",
        List.of(PlatformApiCapabilities.PEERS_WRITE),
        "Add a peer.");
    builder.post(
        ROUTE_FAMILY_PEERS,
        "/peers/{peerId}/settings",
        "peers.settings",
        List.of(PlatformApiCapabilities.PEERS_WRITE),
        "Update peer settings.");
    builder.post(
        ROUTE_FAMILY_PEERS,
        "/peers/{peerId}/note",
        "peers.note",
        List.of(PlatformApiCapabilities.PEERS_WRITE),
        "Update a peer note.");
    builder.post(
        ROUTE_FAMILY_PEERS,
        "/peers/{peerId}/remove",
        "peers.remove",
        List.of(PlatformApiCapabilities.PEERS_WRITE),
        "Remove a peer.");
    builder.get(
        ROUTE_FAMILY_APPS,
        "/apps",
        PlatformApiCapabilities.APPS_READ,
        PlatformApiCapabilities.APPS_READ,
        "List installed apps.");
    builder.get(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}",
        PlatformApiCapabilities.APPS_READ,
        PlatformApiCapabilities.APPS_READ,
        "Read one installed app summary.");
    builder.get(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/runtime",
        PlatformApiCapabilities.APPS_READ,
        PlatformApiCapabilities.APPS_READ,
        "Read token-free app runtime status.");
    builder.get(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/logs",
        PlatformApiCapabilities.APPS_READ,
        PlatformApiCapabilities.APPS_READ,
        "Read redacted app process logs.");
    builder.get(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/permissions",
        PlatformApiCapabilities.APPS_READ,
        PlatformApiCapabilities.APPS_READ,
        "Read app permissions and denied-count summary.");
    builder.get(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/audit",
        PlatformApiCapabilities.APPS_READ,
        PlatformApiCapabilities.APPS_READ,
        "Read bounded app audit entries.");
    builder.post(
        ROUTE_FAMILY_APPS,
        "/apps/install",
        "apps.install",
        List.of(PlatformApiCapabilities.APPS_MANAGE),
        "Install a staged app bundle.");
    builder.post(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/start",
        "apps.start",
        List.of(PlatformApiCapabilities.APPS_MANAGE),
        "Start an installed app.");
    builder.post(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/stop",
        "apps.stop",
        List.of(PlatformApiCapabilities.APPS_MANAGE),
        "Stop a running app.");
    builder.post(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/update",
        "apps.update",
        List.of(PlatformApiCapabilities.APPS_MANAGE),
        "Update an installed app from a staged bundle.");
    builder.appUpdateGet(
        "/apps/{appId}/updates",
        PlatformApiCapabilities.APPS_READ,
        "Read app update lifecycle status.");
    builder.appUpdatePost(
        "/apps/{appId}/updates/check",
        "apps.updates.check",
        APP_CATALOG_UPDATE_MANAGE_CAPABILITIES,
        "Check signed catalogs for an app update candidate.");
    builder.appUpdatePost(
        "/apps/{appId}/updates/stage",
        "apps.updates.stage",
        APP_CATALOG_UPDATE_MANAGE_CAPABILITIES,
        "Stage a verified app update candidate.");
    builder.appUpdatePost(
        "/apps/{appId}/updates/apply",
        "apps.updates.apply",
        APP_CATALOG_UPDATE_MANAGE_CAPABILITIES,
        "Apply a staged app update.");
    builder.appUpdatePost(
        "/apps/{appId}/updates/rollback",
        "apps.updates.rollback",
        List.of(PlatformApiCapabilities.APPS_MANAGE),
        "Restore the previous retained app bundle.");
    builder.appUpdateGet(
        "/apps/{appId}/updates/policy", "apps.updates.policy", "Read the app update policy.");
    builder.appUpdatePolicyPost();
    builder.delete(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}",
        "apps.uninstall",
        List.of(PlatformApiCapabilities.APPS_MANAGE),
        "Uninstall a stopped app.");
    builder.get(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs",
        PlatformApiCapabilities.CATALOGS_READ,
        PlatformApiCapabilities.CATALOGS_READ,
        "List configured app catalogs.");
    builder.get(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/{catalogId}/apps",
        PlatformApiCapabilities.CATALOGS_READ,
        PlatformApiCapabilities.CATALOGS_READ,
        "List apps in one catalog.");
    builder.get(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/{catalogId}/apps/{appId}",
        PlatformApiCapabilities.CATALOGS_READ,
        PlatformApiCapabilities.CATALOGS_READ,
        "Read one catalog app entry.");
    builder.post(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/add",
        "catalogs.add",
        List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
        "Add a signed catalog source.");
    builder.post(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/{catalogId}/refresh",
        "catalogs.refresh",
        List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
        "Refresh one signed catalog source.");
    builder.delete(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/{catalogId}",
        "catalogs.remove",
        List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
        "Remove one signed catalog source.");
    builder.post(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/{catalogId}/apps/{appId}/install",
        "catalogs.apps.install",
        List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
        "Install an app from a signed catalog.");
    builder.post(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/{catalogId}/apps/{appId}/update",
        "catalogs.apps.update",
        List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
        "Update an app from a signed catalog.");
    builder.appVaultGet(
        "/app-vault/secrets",
        "app-vault.secrets.list",
        List.of(PlatformApiCapabilities.VAULT_SECRETS_READ),
        false,
        "List redacted metadata for app-owned secrets.");
    builder.appVaultPutSecret();
    builder.appVaultGet(
        ROUTE_APP_VAULT_SECRET,
        "app-vault.secrets.read",
        List.of(PlatformApiCapabilities.VAULT_SECRETS_READ),
        false,
        "Read one app-owned secret value for an app process principal.");
    builder.appVaultDeleteSecret();
    builder.appVaultGet(
        "/app-vault/identities",
        "app-vault.identities.list",
        List.of(PlatformApiCapabilities.VAULT_IDENTITIES_READ),
        true,
        "List vault identity metadata visible to the calling app.");
    builder.appVaultPost(
        "/app-vault/identities",
        "app-vault.identities.create",
        List.of(PlatformApiCapabilities.VAULT_IDENTITIES_CREATE),
        false,
        "Create an app-owned vault identity.");
    builder.appVaultGet(
        "/app-vault/identities/{identityId}",
        "app-vault.identities.read",
        List.of(PlatformApiCapabilities.VAULT_IDENTITIES_READ),
        true,
        "Read one vault identity metadata record visible to the calling app.");
    builder.appVaultPost(
        "/app-vault/identities/{identityId}/use",
        "app-vault.identities.use",
        List.of(PlatformApiCapabilities.VAULT_IDENTITIES_USE),
        false,
        "Use one granted vault identity for a bounded operation.");
    builder.appVaultGet(
        "/app-vault/grants",
        "app-vault.grants.list",
        List.of(PlatformApiCapabilities.VAULT_IDENTITIES_READ),
        true,
        "List vault identity grants for the calling app.");
    builder.appVaultPost(
        "/app-vault/grants/request",
        "app-vault.grants.request",
        List.of(PlatformApiCapabilities.VAULT_IDENTITIES_READ),
        true,
        "Submit a token-free vault grant request for operator review.");
    builder.identityVaultGet(
        "/identity-vault/identities",
        "identity-vault.identities.list",
        "List vault identities for host/operator management.");
    builder.identityVaultPost(
        "/identity-vault/identities",
        "identity-vault.identities.create",
        "Create an operator-managed vault identity.");
    builder.identityVaultGet(
        "/identity-vault/identities/{identityId}",
        "identity-vault.identities.read",
        "Read one vault identity for host/operator management.");
    builder.identityVaultDelete(
        "/identity-vault/identities/{identityId}",
        "identity-vault.identities.delete",
        "Delete one vault identity and revoke its grants.");
    builder.identityVaultGet(
        "/identity-vault/grants",
        "identity-vault.grants.list",
        "List vault identity grants for host/operator management.");
    builder.identityVaultPost(
        "/identity-vault/grants",
        "identity-vault.grants.create",
        "Grant one vault identity to one app.");
    builder.identityVaultGrantStatusPatch();
    builder.identityVaultDelete(
        ROUTE_IDENTITY_VAULT_GRANT,
        "identity-vault.grants.revoke",
        "Revoke one vault identity grant.");
    builder.get(
        "platform",
        "/platform/contract",
        PlatformApiCapabilities.PLATFORM_CONTRACT_READ,
        PlatformApiCapabilities.PLATFORM_CONTRACT_READ,
        "Read the deterministic Platform API compatibility contract.");
    return builder.build();
  }

  private static PlatformApiCapabilityDescriptor capability(String name, String description) {
    return new PlatformApiCapabilityDescriptor(
        name, PlatformApiStabilityLevel.STABLE, INITIAL_CONTRACT_VERSION, null, description);
  }

  private static PlatformApiCapabilityDescriptor experimentalCapability(
      String name, String description) {
    return new PlatformApiCapabilityDescriptor(
        name,
        PlatformApiStabilityLevel.EXPERIMENTAL,
        APP_VAULT_CONTRACT_VERSION,
        null,
        description);
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }

  private static final class EndpointBuilder {
    private final List<PlatformApiEndpointDescriptor> endpoints = new java.util.ArrayList<>();

    private void get(
        String family,
        String routeTemplate,
        String actionLabel,
        String capability,
        String description) {
      endpoint(
          new EndpointSpec(
              family,
              METHOD_GET,
              routeTemplate,
              actionLabel,
              List.of(capability),
              INITIAL_CONTRACT_VERSION,
              true,
              true,
              description));
    }

    private void post(
        String family,
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        String description) {
      endpoint(
          new EndpointSpec(
              family,
              METHOD_POST,
              routeTemplate,
              actionLabel,
              capabilities,
              INITIAL_CONTRACT_VERSION,
              true,
              true,
              description));
    }

    private void delete(
        String family,
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        String description) {
      endpoint(
          new EndpointSpec(
              family,
              METHOD_DELETE,
              routeTemplate,
              actionLabel,
              capabilities,
              INITIAL_CONTRACT_VERSION,
              true,
              true,
              description));
    }

    private void appVaultGet(
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        boolean appBrowserAllowed,
        String description) {
      appVaultEndpoint(
          METHOD_GET, routeTemplate, actionLabel, capabilities, appBrowserAllowed, description);
    }

    private void appVaultPost(
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        boolean appBrowserAllowed,
        String description) {
      appVaultEndpoint(
          METHOD_POST, routeTemplate, actionLabel, capabilities, appBrowserAllowed, description);
    }

    private void appVaultPutSecret() {
      appVaultEndpoint(
          METHOD_PUT,
          ROUTE_APP_VAULT_SECRET,
          "app-vault.secrets.write",
          List.of(PlatformApiCapabilities.VAULT_SECRETS_WRITE),
          false,
          "Create or replace one app-owned secret value.");
    }

    private void appVaultDeleteSecret() {
      appVaultEndpoint(
          METHOD_DELETE,
          ROUTE_APP_VAULT_SECRET,
          "app-vault.secrets.delete",
          List.of(PlatformApiCapabilities.VAULT_SECRETS_WRITE),
          false,
          "Delete one app-owned secret without exposing the old value.");
    }

    private void identityVaultGet(String routeTemplate, String actionLabel, String description) {
      identityVaultEndpoint(METHOD_GET, routeTemplate, actionLabel, description);
    }

    private void identityVaultPost(String routeTemplate, String actionLabel, String description) {
      identityVaultEndpoint(METHOD_POST, routeTemplate, actionLabel, description);
    }

    private void identityVaultGrantStatusPatch() {
      identityVaultEndpoint(
          METHOD_PATCH,
          ROUTE_IDENTITY_VAULT_GRANT,
          "identity-vault.grants.status",
          "Change one vault grant status.");
    }

    private void identityVaultDelete(String routeTemplate, String actionLabel, String description) {
      identityVaultEndpoint(METHOD_DELETE, routeTemplate, actionLabel, description);
    }

    private void appUpdateGet(String routeTemplate, String actionLabel, String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APPS,
              METHOD_GET,
              routeTemplate,
              actionLabel,
              List.of(PlatformApiCapabilities.APPS_READ),
              APP_UPDATE_LIFECYCLE_CONTRACT_VERSION,
              true,
              true,
              description));
    }

    private void appUpdatePost(
        String routeTemplate, String actionLabel, List<String> capabilities, String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APPS,
              METHOD_POST,
              routeTemplate,
              actionLabel,
              capabilities,
              APP_UPDATE_LIFECYCLE_CONTRACT_VERSION,
              true,
              true,
              description));
    }

    private void appUpdatePolicyPost() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APPS,
              METHOD_POST,
              "/apps/{appId}/updates/policy",
              "apps.updates.policy",
              List.of(PlatformApiCapabilities.APPS_MANAGE),
              APP_UPDATE_LIFECYCLE_CONTRACT_VERSION,
              false,
              false,
              "Update the local app update policy."));
    }

    private void endpoint(EndpointSpec spec) {
      endpoints.add(
          new PlatformApiEndpointDescriptor(
              spec.family(),
              spec.method(),
              spec.routeTemplate(),
              spec.actionLabel(),
              spec.capabilities(),
              spec.hostOperatorBypassAllowed(),
              spec.appProcessAllowed(),
              spec.appBrowserAllowed(),
              spec.stability(),
              spec.sinceContractVersion(),
              null,
              spec.description()));
    }

    private void appVaultEndpoint(
        String method,
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        boolean appBrowserAllowed,
        String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APP_VAULT,
              method,
              routeTemplate,
              actionLabel,
              capabilities,
              APP_VAULT_CONTRACT_VERSION,
              false,
              true,
              appBrowserAllowed,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              description));
    }

    private void identityVaultEndpoint(
        String method, String routeTemplate, String actionLabel, String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_IDENTITY_VAULT,
              method,
              routeTemplate,
              actionLabel,
              List.of(PlatformApiCapabilities.VAULT_IDENTITIES_MANAGE),
              APP_VAULT_CONTRACT_VERSION,
              true,
              false,
              false,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              description));
    }

    private List<PlatformApiEndpointDescriptor> build() {
      return List.copyOf(endpoints);
    }
  }

  private record EndpointSpec(
      String family,
      String method,
      String routeTemplate,
      String actionLabel,
      List<String> capabilities,
      int sinceContractVersion,
      boolean hostOperatorBypassAllowed,
      boolean appProcessAllowed,
      boolean appBrowserAllowed,
      PlatformApiStabilityLevel stability,
      String description) {
    private EndpointSpec(
        String family,
        String method,
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        int sinceContractVersion,
        boolean appProcessAllowed,
        boolean appBrowserAllowed,
        String description) {
      this(
          family,
          method,
          routeTemplate,
          actionLabel,
          capabilities,
          sinceContractVersion,
          true,
          appProcessAllowed,
          appBrowserAllowed,
          PlatformApiStabilityLevel.STABLE,
          description);
    }

    private EndpointSpec {
      capabilities = List.copyOf(capabilities);
      Objects.requireNonNull(stability, "stability");
    }
  }
}
