package network.crypta.platform.api.appservices;

import java.util.List;
import java.util.Map;

/**
 * Built-in executor for one platform-mediated app-service invocation.
 *
 * <p>Adapters are the only code allowed to cross from the generic app-service grant layer into a
 * concrete local capability. The coordinator authenticates the app principal, finds an active
 * grant, checks provider and consumer manifests, and then calls an adapter whose id was advertised
 * by the provider manifest. Implementations must validate their own parameter schema and return
 * only redacted, JSON-compatible data.
 *
 * <p>This interface is intentionally not an HTTP proxy contract. An adapter should call an
 * in-process platform service or a narrow, explicitly registered local implementation. It must not
 * forward arbitrary URLs, expose provider app storage, or accept raw bearer tokens from a consumer
 * app.
 *
 * <p>The coordinator supplies a grant that already matches the requested provider, service, scope,
 * and context. Adapter implementations should only narrow authorization further based on their own
 * bounded schema. They must not expand the grant, infer additional contexts, or treat missing
 * parameters as permission to use a broader provider capability.
 */
public interface AppServiceAdapter {
  /**
   * Returns the adapter id declared in provider manifests.
   *
   * <p>The id is stable manifest metadata, for example {@code trust-graph.score}. The coordinator
   * uses it to select an adapter after the provider service descriptor has been discovered from the
   * installed app manifest.
   *
   * @return public adapter id used in signed service descriptors
   */
  String adapterId();

  /**
   * Invokes the adapter after the coordinator has authenticated the app principal and found an
   * active grant.
   *
   * <p>Implementations should treat every field in {@code queryParameters} as untrusted app input.
   * They are responsible for service-specific bounds, enum validation, and redaction. Throw {@link
   * network.crypta.platform.api.PlatformApiException} with a stable error code when the request is
   * invalid or unauthorized for the active grant.
   *
   * @param descriptor advertised service descriptor that selected this adapter
   * @param grant active grant authorizing this call for one consumer app
   * @param queryParameters decoded invocation parameters from the Platform API request
   * @return JSON-compatible redacted result for the service-call envelope
   */
  Map<String, Object> invoke(
      AppServiceDescriptor descriptor,
      AppServiceGrant grant,
      Map<String, List<String>> queryParameters);
}
