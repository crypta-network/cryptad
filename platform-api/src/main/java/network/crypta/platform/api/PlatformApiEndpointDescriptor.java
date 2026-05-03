package network.crypta.platform.api;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Public descriptor for one Platform API route/action contract entry.
 *
 * <p>Endpoint descriptors are the shared representation used for the published compatibility
 * contract and for app-principal authorization. Each descriptor names the route family, HTTP-style
 * method, route template, audit/action label, required app manifest capabilities, principal
 * classes, and stability metadata. The descriptor is intentionally about the route contract only;
 * it does not describe request bodies, query strings, response payload schemas, local filesystem
 * inputs, tokens, or process launch details.
 *
 * <p>Route templates are relative to {@code /api/v1} and use single-segment placeholders such as
 * {@code {appId}}. Placeholders match any non-empty decoded path segment. Required capabilities are
 * normalized into lexicographic order during construction so authorization checks, contract
 * snapshots, and drift tests remain deterministic.
 *
 * @param routeFamily top-level route family such as {@code queue}
 * @param method HTTP-style method name, normalized to upper case during construction
 * @param routeTemplate deterministic route template relative to {@code /api/v1}
 * @param actionLabel action label used by authorization and app audit entries
 * @param requiredCapabilities sorted manifest capabilities required from app principals
 * @param hostOperatorBypassAllowed whether host/operator requests may use the existing local-admin
 *     model for this route
 * @param appProcessAllowed whether AppHost process-token principals may use this route
 * @param appBrowserAllowed whether app browser-session principals may use this route
 * @param stability stability classification for the endpoint
 * @param sinceContractVersion first positive Platform API contract version containing the endpoint
 * @param deprecation optional deprecation/removal metadata, or {@code null}
 * @param description short human-readable description suitable for contract snapshots
 */
public record PlatformApiEndpointDescriptor(
    String routeFamily,
    String method,
    String routeTemplate,
    String actionLabel,
    List<String> requiredCapabilities,
    boolean hostOperatorBypassAllowed,
    boolean appProcessAllowed,
    boolean appBrowserAllowed,
    PlatformApiStabilityLevel stability,
    int sinceContractVersion,
    PlatformApiDeprecation deprecation,
    String description) {
  /**
   * Creates a validated endpoint descriptor.
   *
   * <p>The constructor enforces the structural invariants needed before a descriptor can be used by
   * authorization or serialized as public contract metadata. App-visible endpoints must require at
   * least one capability, route templates must be absolute API-relative paths, text fields must not
   * be blank, and the contract version must be positive.
   */
  public PlatformApiEndpointDescriptor {
    routeFamily = requireText(routeFamily, "routeFamily");
    method = requireText(method, "method").toUpperCase(java.util.Locale.ROOT);
    routeTemplate = normalizeRouteTemplate(routeTemplate);
    actionLabel = requireText(actionLabel, "actionLabel");
    requiredCapabilities = sortedCapabilities(requiredCapabilities);
    if ((appProcessAllowed || appBrowserAllowed) && requiredCapabilities.isEmpty()) {
      throw new IllegalArgumentException("app-visible endpoints must require a capability");
    }
    Objects.requireNonNull(stability, "stability");
    if (sinceContractVersion <= 0) {
      throw new IllegalArgumentException("sinceContractVersion must be a positive integer");
    }
    description = requireText(description, "description");
  }

  /**
   * Returns whether this descriptor matches a normalized request method and path segment list.
   *
   * <p>The matcher is deliberately conservative. It requires the same segment count, treats
   * placeholders as one decoded non-empty segment, and does not interpret query strings or request
   * bodies. Callers normalize the method before invoking this helper.
   *
   * @param requestMethod normalized HTTP-style method name, usually already upper case
   * @param pathSegments decoded Platform API path segments beneath {@code /api/v1}
   * @return {@code true} when the request maps to this contract endpoint
   */
  boolean matches(String requestMethod, List<String> pathSegments) {
    if (!method.equals(requestMethod)) {
      return false;
    }
    List<String> templateSegments = templateSegments();
    if (templateSegments.size() != pathSegments.size()) {
      return false;
    }
    for (int index = 0; index < templateSegments.size(); index++) {
      String templateSegment = templateSegments.get(index);
      String pathSegment = pathSegments.get(index);
      if (templateSegment.startsWith("{") && templateSegment.endsWith("}")) {
        if (pathSegment.isEmpty()) {
          return false;
        }
      } else if (!templateSegment.equals(pathSegment)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Returns whether the supplied principal type may use this endpoint family.
   *
   * <p>This checks only the endpoint's principal-class flags. Capability checks still use {@link
   * #requiredCapabilities()} through {@link #toAction()} before an app request is allowed.
   *
   * @param principalType principal type being considered for the current request
   * @return {@code true} when the endpoint is visible to that principal class
   */
  boolean allowsPrincipal(PlatformApiPrincipalType principalType) {
    return switch (Objects.requireNonNull(principalType, "principalType")) {
      case APP -> appProcessAllowed;
      case APP_BROWSER -> appBrowserAllowed;
      case HOST_OPERATOR -> hostOperatorBypassAllowed;
    };
  }

  /**
   * Converts this descriptor into the authorization action object.
   *
   * <p>The action preserves the route family, audit/action label, and sorted capability list used
   * by the descriptor. This is the bridge that keeps the published contract and app-principal
   * authorization matrix aligned.
   *
   * @return authorization action derived from this endpoint descriptor
   */
  PlatformApiAction toAction() {
    return PlatformApiAction.of(routeFamily, actionLabel, requiredCapabilities);
  }

  private List<String> templateSegments() {
    String relative = routeTemplate.substring(1);
    if (relative.isEmpty()) {
      return List.of();
    }
    return List.of(relative.split("/", -1));
  }

  private static String normalizeRouteTemplate(String value) {
    String text = requireText(value, "routeTemplate");
    if (!text.startsWith("/") || text.contains("//")) {
      throw new IllegalArgumentException("routeTemplate must be an absolute API-relative path");
    }
    return text;
  }

  private static List<String> sortedCapabilities(List<String> source) {
    Objects.requireNonNull(source, "requiredCapabilities");
    Set<String> sorted = new TreeSet<>();
    for (String capability : source) {
      sorted.add(requireText(capability, "requiredCapabilities value"));
    }
    return List.copyOf(sorted);
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }
}
