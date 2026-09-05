package network.crypta.platform.api;

import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

/**
 * Captures immutable authorization semantics for one endpoint inherited by a stable baseline.
 *
 * <p>The identity alone is not enough to protect a compatibility promise. This value also binds the
 * route family, audit/action label, required capabilities, host-operator bypass behavior, and the
 * allowed app principal kinds. A later {@code 1.x} baseline must carry an equal value for every
 * endpoint inherited from a still-supported predecessor; changing any field therefore fails the
 * monotonic extension check.
 *
 * <p>Construction sorts capability names and rejects non-app-facing descriptors. The record is
 * immutable and contains no runtime authorization state; admission still relies on the app's actual
 * permissions and principal.
 *
 * @param identity the exact stable endpoint identity, normally {@code METHOD /path}
 * @param routeFamily the established route-family identity
 * @param actionLabel the established authorization and audit action
 * @param requiredCapabilities the complete sorted capability requirement
 * @param hostOperatorBypassAllowed whether the established host-operator bypass is part of
 *     semantics
 * @param appProcessAllowed whether an app process principal may use the endpoint
 * @param appBrowserAllowed whether an app browser principal may use the endpoint
 */
public record PlatformApiBaselineEndpoint(
    String identity,
    String routeFamily,
    String actionLabel,
    List<String> requiredCapabilities,
    boolean hostOperatorBypassAllowed,
    boolean appProcessAllowed,
    boolean appBrowserAllowed) {

  /**
   * Creates an exact, deterministic endpoint-semantics value.
   *
   * <p>Capability names are normalized into deterministic order and duplicates are rejected. At
   * least one app principal must remain allowed, keeping operator-only descriptors outside the
   * stable app baseline model. Text fields are trimmed before storage, so equality and digest
   * comparisons operate on one canonical representation rather than caller formatting.
   *
   * @throws NullPointerException if a required text or capability collection is {@code null}
   * @throws IllegalArgumentException if text is blank, capabilities repeat, or no app principal is
   *     allowed
   */
  public PlatformApiBaselineEndpoint {
    identity = requireText(identity, "identity");
    routeFamily = requireText(routeFamily, "routeFamily");
    actionLabel = requireText(actionLabel, "actionLabel");
    TreeSet<String> capabilities = new TreeSet<>();
    for (String capability : Objects.requireNonNull(requiredCapabilities, "requiredCapabilities")) {
      if (!capabilities.add(requireText(capability, "requiredCapabilities value"))) {
        throw new IllegalArgumentException("duplicate required capability: " + capability);
      }
    }
    requiredCapabilities = List.copyOf(capabilities);
    if (!appProcessAllowed && !appBrowserAllowed) {
      throw new IllegalArgumentException("stable baseline endpoint must be app-facing");
    }
  }

  /**
   * Projects compatibility and authorization semantics from an existing endpoint descriptor.
   *
   * <p>Restricted-audience, internal, and operator-only descriptors are rejected before projection.
   * The returned value does not promote or change the source descriptor's stability. It copies only
   * the fields that define the stable authorization promise and contains no handler, runtime
   * principal, or permission-grant state.
   *
   * @param descriptor the existing app-facing descriptor whose semantics are frozen
   * @return an immutable baseline endpoint carrying the descriptor's exact stable semantics
   * @throws IllegalArgumentException if the descriptor is restricted or not app-facing
   */
  public static PlatformApiBaselineEndpoint fromDescriptor(
      PlatformApiEndpointDescriptor descriptor) {
    PlatformApiEndpointDescriptor checked = Objects.requireNonNull(descriptor, "descriptor");
    if (checked.stability().isRestrictedAudience()
        || (!checked.appProcessAllowed() && !checked.appBrowserAllowed())) {
      throw new IllegalArgumentException(
          "operator-only or internal endpoints cannot enter a stable app baseline");
    }
    return new PlatformApiBaselineEndpoint(
        PlatformApiContract.endpointIdentity(checked),
        checked.routeFamily(),
        checked.actionLabel(),
        checked.requiredCapabilities(),
        checked.hostOperatorBypassAllowed(),
        checked.appProcessAllowed(),
        checked.appBrowserAllowed());
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }
}
