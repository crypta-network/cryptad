package network.crypta.platform.api.appservices;

import java.util.LinkedHashMap;
import java.util.List;

/**
 * Manifest-declared request for a service provided by another installed app.
 *
 * <p>Request descriptors are transparency metadata only. They help the operator understand what an
 * app is expected to ask for, but they do not approve a grant and do not authorize invocation.
 *
 * <p>The descriptor is parsed from the consumer app's signed installed manifest. It is shown in
 * discovery and Web Shell review surfaces so an operator can compare expected service use with
 * actual pending grants. A consumer app must still call the grant request route, declare {@code
 * app.services.call}, and wait for host/operator approval before invocation can succeed.
 *
 * <p>Contexts in this record are review hints copied from the consumer manifest. They do not
 * broaden a future grant. The coordinator validates the submitted grant request against the
 * provider's current descriptor when the app requests access and again when the operator approves
 * it.
 *
 * @param consumerAppId stable consumer app id that declares the request
 * @param consumerName consumer display name safe for operator views
 * @param consumerVersion consumer display version safe for operator views
 * @param providerAppId requested provider app id from manifest metadata
 * @param serviceId requested public service id from manifest metadata
 * @param scopes requested scopes/actions for operator review
 * @param contexts requested contexts for operator review, or empty for unscoped services
 * @param purpose operator-facing purpose explaining why the app requests the service
 */
public record AppServiceRequestDescriptor(
    String consumerAppId,
    String consumerName,
    String consumerVersion,
    String providerAppId,
    String serviceId,
    List<String> scopes,
    List<String> contexts,
    String purpose) {
  /**
   * Creates a validated request descriptor.
   *
   * <p>Identifier, scope, and context fields are normalized to match provider descriptors and
   * grant-request route inputs. Display and purpose fields are bounded so they can be serialized in
   * public Platform API responses without exposing unbounded manifest text.
   */
  public AppServiceRequestDescriptor {
    consumerAppId = AppServiceManifestParser.normalizeAppId(consumerAppId);
    consumerName = AppServiceManifestParser.requiredText("consumerName", consumerName, 80);
    consumerVersion = AppServiceManifestParser.requiredText("consumerVersion", consumerVersion, 40);
    providerAppId = AppServiceManifestParser.normalizeAppId(providerAppId);
    serviceId = AppServiceManifestParser.normalizeServiceId(serviceId);
    scopes = AppServiceManifestParser.normalizeTokens("scopes", scopes, 16);
    contexts = AppServiceManifestParser.normalizeTokens("contexts", contexts, 16);
    purpose = AppServiceManifestParser.requiredText("purpose", purpose, 512);
  }

  /**
   * Returns a deterministic JSON-compatible representation.
   *
   * <p>The map preserves the manifest review order used by SDK tests, Web Shell rendering, and
   * release evidence. It includes no installed manifest path or other local filesystem detail.
   *
   * @return public request descriptor map with stable key order
   */
  public java.util.Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put("consumerAppId", consumerAppId);
    json.put("consumerName", consumerName);
    json.put("consumerVersion", consumerVersion);
    json.put("providerAppId", providerAppId);
    json.put("serviceId", serviceId);
    json.put("scopes", scopes);
    json.put("contexts", contexts);
    json.put("purpose", purpose);
    return json;
  }
}
