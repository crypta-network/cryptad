package network.crypta.runtime.http;

import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.http.HttpShellRuntimeSupport;
import network.crypta.clients.http.ToadletContainer;
import network.crypta.support.io.TempBucketFactory;

/**
 * Runtime-owned seam for the HTTP shell host used during bootstrap and endpoint wiring.
 *
 * <p>This interface isolates runtime code from the concrete legacy HTTP shell implementation while
 * still exposing the small set of operations that bootstrap and endpoint wiring need. Callers keep
 * using the shared {@link ToadletContainer} and {@link LinkFilterExceptionProvider} contracts for
 * normal toadlet registration and filtering behavior, and they use this seam only for the remaining
 * shell lifecycle hooks that are still runtime-owned.
 *
 * <p>The intent is structural rather than behavioral. Implementations preserve the existing shell
 * startup order, FProxy creation flow, and startup-page behavior, but runtime packages no longer
 * need to depend directly on {@code network.crypta.clients.http.SimpleToadletServer}. That keeps
 * ownership boundaries narrower while allowing future HTTP-shell changes to stay behind a
 * runtime-local abstraction.
 */
public interface HttpShellContainer extends ToadletContainer, LinkFilterExceptionProvider {

  /**
   * Starts the underlying HTTP shell listener when the shell is configured to run.
   *
   * <p>Callers typically invoke this after configuration registration is complete and before the
   * node begins exposing client-facing HTTP endpoints. Implementations should preserve the existing
   * shell startup semantics, including any internal no-op behavior when the shell is disabled. This
   * method does not imply that runtime support or FProxy wiring has already been installed.
   */
  void start();

  /**
   * Publishes runtime-backed HTTP shell support once the client core is ready.
   *
   * <p>This hook connects the shell to the daemon-backed services that require a live {@code
   * NodeClientCore}. Callers usually provide this after the core exists but before the shell
   * finishes its final startup sequence. Implementations are expected to retain the supplied
   * adapter for later callbacks rather than copying or translating it.
   *
   * @param runtimeSupport daemon-backed adapter that serves later HTTP shell callbacks and runtime
   *     lookups
   */
  void setRuntimeSupport(HttpShellRuntimeSupport runtimeSupport);

  /**
   * Replaces the temporary bucket factory used for HTTP requests.
   *
   * <p>This affects later request handling only. Existing in-flight requests may continue to use
   * the previously installed factory, depending on the concrete shell implementation. Runtime code
   * uses this hook when the node finishes creating the final temporary-storage infrastructure and
   * wants the HTTP shell to stop relying on its initial bootstrap bucket handling.
   *
   * @param tempBucketFactory bucket factory that should back subsequent HTTP request buffering and
   *     temporary storage work
   */
  void setBucketFactory(TempBucketFactory tempBucketFactory);

  /**
   * Indicates whether the HTTP shell is configured to run.
   *
   * <p>This is a configuration and lifecycle gate rather than a liveness probe. Runtime code uses
   * it to decide whether to run the later shell-only startup steps such as finishing startup,
   * creating FProxy, and removing the temporary startup toadlet. A {@code true} result means the
   * shell should participate in startup; it does not guarantee that the listener is already bound.
   *
   * @return {@code true} when the shell should take part in the node startup sequence
   */
  boolean isEnabled();

  /**
   * Completes the post-start startup wiring for the HTTP shell.
   *
   * <p>Runtime code calls this during the final node startup sequence, after the shell has its core
   * runtime support and after the basic listener startup path has run. Implementations may use this
   * hook to finalize internal state, register late shell components, or otherwise transition from
   * bootstrap mode to normal operation without changing the externally visible startup order.
   */
  void finishStart();

  /**
   * Creates the root FProxy wiring after runtime support is available.
   *
   * <p>This hook exists because FProxy creation remains part of the legacy shell container rather
   * than a standalone runtime service. Callers invoke it only in the established startup position
   * after the shell has the runtime-backed support it needs. Implementations should preserve the
   * current FProxy behavior and should not use this seam to reorder or broaden endpoint startup.
   */
  void createFproxy();

  /**
   * Removes the temporary startup toadlet once shell startup is complete.
   *
   * <p>The startup toadlet exists only to present bootstrap status while the node is still coming
   * up. Runtime code calls this after the normal HTTP shell and FProxy wiring are ready so the
   * transitional page can disappear. Implementations should treat the removal as an idempotent
   * cleanup step within the existing startup sequence.
   */
  void removeStartupToadlet();

  /**
   * Marks the startup toadlet PRNG warning as resolved.
   *
   * <p>This method deliberately hides the concrete startup-toadlet details from runtime code.
   * Bootstrap uses it once the strong random source is ready, so the startup UI can stop warning
   * about entropy readiness. Implementations should update only the startup-page readiness state
   * needed for that user-visible transition and should not treat this call as a broader startup
   * completion signal.
   */
  void markStartupPrngReady();
}
