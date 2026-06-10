package network.crypta.platform.api.appservices;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;

/**
 * Public descriptor for one local service advertised by an installed app.
 *
 * <p>The descriptor is intentionally metadata-only. It names the provider app, service id, adapter
 * id, supported scopes, supported contexts, and availability. It never includes installed paths,
 * process tokens, private state roots, or raw app data.
 *
 * <p>Descriptors are parsed from signed installed manifests, not from running app processes. The
 * Platform API uses them for discovery, operator review, grant validation, and adapter dispatch. A
 * descriptor does not authorize anything by itself; invocation still requires an authenticated app
 * principal, a matching active grant, a current provider advertisement, and a registered adapter.
 *
 * <p>An empty context list means the service is not context-scoped. When contexts are present,
 * grant requests and invocations must name one of them explicitly. The empty list is therefore not
 * an authorization wildcard for contextual services; it is a descriptor-level statement that the
 * service has no context dimension at all.
 *
 * @param providerAppId stable provider app id from the installed manifest
 * @param providerName provider display name safe for operator views
 * @param providerVersion provider display version safe for operator views
 * @param serviceId public service id used by grants and invocation routes
 * @param name service display name shown during discovery and approval
 * @param version service version token declared by the provider
 * @param kind implementation kind, currently {@code platform-adapter}
 * @param adapter platform adapter id, currently {@code trust-graph.score}
 * @param scopes supported action/scope names for grant and invocation checks
 * @param contexts supported invocation contexts, or empty for unscoped services
 * @param description operator-facing summary of the service behavior
 * @param stability stability label such as {@code preview}
 * @param available whether the service is currently advertised by an installed provider
 */
public record AppServiceDescriptor(
    String providerAppId,
    String providerName,
    String providerVersion,
    String serviceId,
    String name,
    String version,
    String kind,
    String adapter,
    List<String> scopes,
    List<String> contexts,
    String description,
    String stability,
    boolean available) {
  /**
   * Creates a validated descriptor.
   *
   * <p>The constructor normalizes ids, tokens, scopes, and contexts so parsed manifest data and
   * test fixtures behave the same as route inputs. Display fields are bounded but otherwise kept as
   * human-readable text because they are rendered in operator-facing JSON.
   */
  public AppServiceDescriptor {
    providerAppId = AppServiceManifestParser.normalizeAppId(providerAppId);
    providerName = AppServiceManifestParser.requiredText("providerName", providerName, 80);
    providerVersion = AppServiceManifestParser.requiredText("providerVersion", providerVersion, 40);
    serviceId = AppServiceManifestParser.normalizeServiceId(serviceId);
    name = AppServiceManifestParser.requiredText("name", name, 80);
    version = AppServiceManifestParser.requiredText("version", version, 40);
    kind = AppServiceManifestParser.requiredToken("kind", kind, 40);
    adapter = AppServiceManifestParser.normalizeServiceId(adapter);
    scopes = AppServiceManifestParser.normalizeTokens("scopes", scopes, 16);
    contexts = AppServiceManifestParser.normalizeTokens("contexts", contexts, 16);
    description = AppServiceManifestParser.optionalText(description, 512);
    stability = AppServiceManifestParser.requiredToken("stability", stability, 32);
  }

  /**
   * Returns a copy with adjusted availability.
   *
   * <p>Availability is a runtime view over the same public descriptor metadata. It allows discovery
   * surfaces to preserve a descriptor shape while reporting that the provider is not currently
   * usable.
   *
   * @param newAvailable public availability value to expose
   * @return descriptor with the same metadata and the new availability flag
   */
  @SuppressWarnings("unused")
  public AppServiceDescriptor withAvailability(boolean newAvailable) {
    return new AppServiceDescriptor(
        providerAppId,
        providerName,
        providerVersion,
        serviceId,
        name,
        version,
        kind,
        adapter,
        scopes,
        contexts,
        description,
        stability,
        newAvailable);
  }

  /**
   * Returns a deterministic JSON-compatible representation.
   *
   * <p>The map order is stable for contract tests, SDK fixtures, Web Shell rendering, and release
   * evidence. Only public discovery metadata is included; callers do not need an additional
   * redaction pass before serializing this value.
   *
   * @return public descriptor map with stable key order
   */
  public java.util.Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(13);
    json.put("providerAppId", providerAppId);
    json.put("providerName", providerName);
    json.put("providerVersion", providerVersion);
    json.put("serviceId", serviceId);
    json.put("name", name);
    json.put("version", version);
    json.put("kind", kind);
    json.put("adapter", adapter);
    json.put("scopes", scopes);
    json.put("contexts", contexts);
    json.put("description", description);
    json.put("stability", stability);
    json.put("available", available);
    return json;
  }

  /**
   * Returns whether any requested scope is absent from this service descriptor.
   *
   * <p>The method performs descriptor containment only. It does not decide whether the caller is
   * allowed to use a supported scope; the coordinator still needs an active grant carrying the same
   * value. The explicit loop keeps the check bounded by the small requested-scope list and avoids
   * relying on collection-wide containment behavior.
   *
   * @param requestedScopes normalized requested scope tokens
   * @return {@code true} when at least one requested scope is not advertised by this service
   */
  boolean hasUnsupportedScopes(List<String> requestedScopes) {
    Objects.requireNonNull(requestedScopes, "requestedScopes");
    for (String requestedScope : requestedScopes) {
      if (!scopes.contains(requestedScope)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Returns whether this descriptor advertises the supplied context token.
   *
   * <p>For unscoped services, represented by an empty descriptor context list, this method returns
   * {@code true} so adapters can accept a descriptor-level context check without special casing.
   * Grant creation and invocation still reject or strip context parameters for unscoped services in
   * the coordinator.
   *
   * @param context context token supplied by a grant request or invocation
   * @return {@code true} when the descriptor allows the context at descriptor level
   */
  boolean supportsContext(String context) {
    return contexts.isEmpty()
        || contexts.contains(AppServiceManifestParser.normalizeToken("context", context));
  }

  boolean satisfiesVersionRange(AppServiceVersionRange range) {
    return range == null || range.contains(version);
  }

  String compatibilityFingerprint() {
    return "sha256:"
        + AppServiceCoordinator.hashHex(
            providerAppId
                + "|"
                + serviceId
                + "|"
                + version
                + "|"
                + kind
                + "|"
                + adapter
                + "|"
                + String.join(",", scopes.stream().sorted().toList())
                + "|"
                + String.join(",", contexts.stream().sorted().toList())
                + "|"
                + stability);
  }
}
