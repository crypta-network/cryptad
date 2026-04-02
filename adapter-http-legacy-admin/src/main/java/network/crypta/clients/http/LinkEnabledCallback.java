package network.crypta.clients.http;

/**
 * Callback consulted to decide whether an HTTP link should be shown to a client.
 *
 * <p>This interface is invoked by UI or routing components before rendering or advertising a link
 * to the outside world. Implementations can examine the {@link ToadletContext}, current
 * configuration, or internal state to decide if a link should be visible. Typical uses include
 * hiding links while a service is disabled, requiring authentication before exposing controls, or
 * gating experimental endpoints during gradual rollout. The callback is expected to be cheap to
 * execute and free of side effects so it can be invoked repeatedly during page generation or
 * capability discovery. Unless stated otherwise by the implementation, callers should treat it as
 * thread-safe and idempotent so the same decision can be reused across request handling code paths.
 *
 * <ul>
 *   <li><strong>Visibility guard:</strong> Centralizes link availability decisions in one place.
 *   <li><strong>Policy enforcement:</strong> Allows integration of authentication or feature flags
 *       without scattering conditional logic.
 *   <li><strong>Context-aware:</strong> May leverage request metadata from {@link ToadletContext}
 *       when available; callers should tolerate {@code null} contexts.
 * </ul>
 *
 * @see #isEnabled(ToadletContext)
 */
public interface LinkEnabledCallback {
  /**
   * Determines whether a specific link should be rendered or advertised for the provided request
   * context.
   *
   * <p>Callers invoke this method before surfacing navigation elements, action buttons, or embedded
   * links. The implementation may inspect authentication state, feature flags, or request metadata
   * exposed by {@link ToadletContext} to decide if the link remains visible. Because the method can
   * be called multiple times during a single page render or capability probe, it should avoid
   * observable side effects and run quickly. When the supplied context is {@code null},
   * implementations should apply a conservative default, such as disabling the link unless a safe
   * fallback is appropriate.
   *
   * <pre>{@code
   * if (callback.isEnabled(ctx)) {
   *   renderLink();
   * }
   * }</pre>
   *
   * @param ctx request context supplying user and connection details; may be {@code null} for
   *     background checks or non-request invocations where no context is available.
   * @return {@code true} when the link may be displayed to the requesting client; {@code false}
   *     when it should remain hidden, disabled, or otherwise withheld.
   */
  boolean isEnabled(ToadletContext ctx);
}
