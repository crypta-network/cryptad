package network.crypta.runtime.endpoints.http;

import network.crypta.clients.http.bridge.CoreHttpShellRuntimeSupport;
import network.crypta.clients.http.bridge.HttpShellContainers;
import network.crypta.runtime.http.HttpShellContainerFactory;
import network.crypta.runtime.http.HttpShellRuntimeSupportFactory;

/**
 * Endpoint-owned default production bindings for the runtime HTTP shell seams.
 *
 * <p>This helper keeps the default production binding choice inside the runtime endpoint package
 * while letting higher-level runtime/bootstrap code depend only on the neutral seam types from
 * {@code network.crypta.runtime.http}. Bootstrap code calls these accessors when it wants the
 * historical daemon wiring, but the neutral seam package stays free of references back to the
 * adapter-owned bridge classes. That separation keeps ownership boundaries clear without changing
 * startup order, shell lifecycle sequencing, or the current bridge implementations used in
 * production.
 *
 * <p>The returned factories are pure binding choices. They do not cache container instances,
 * initialize the shell eagerly, or apply any policy beyond selecting the legacy endpoint-backed
 * implementations that the current node bootstrap path already relies on.
 */
public final class HttpShellBridgeFactories {
  private HttpShellBridgeFactories() {}

  /**
   * Returns the default production HTTP shell container factory.
   *
   * <p>The returned factory preserves the existing container creation path by delegating to {@link
   * HttpShellContainers#create(network.crypta.config.SubConfig,
   * network.crypta.support.PriorityAwareExecutor)}. Callers usually thread this binding through
   * bootstrap records such as {@code NodeRuntimeBridgeFactories}, then invoke the factory later
   * when the node services subsystem is ready to construct the HTTP shell for a specific
   * configuration and executor.
   *
   * @return factory that creates the current adapter-backed HTTP shell container bridge without
   *     eagerly constructing the shell
   */
  public static HttpShellContainerFactory defaultContainerFactory() {
    return HttpShellContainers::create;
  }

  /**
   * Returns the default production HTTP shell runtime-support factory.
   *
   * <p>The returned factory preserves the legacy runtime-support binding by creating {@link
   * CoreHttpShellRuntimeSupport} instances for the supplied client core. Bootstrap code typically
   * chooses this binding once, stores it alongside the other runtime seams, and invokes it later
   * after the node has created a live {@code NodeClientCore}. The method itself does not retain the
   * core or initialize any shell state. The created support objects are intentionally compatible
   * with both the runtime-owned seam and the legacy HTTP shell adapter, so they match the default
   * container factory returned by {@link #defaultContainerFactory()}.
   *
   * @return factory that creates the current adapter-backed HTTP shell runtime support bridge for a
   *     supplied daemon core
   */
  public static HttpShellRuntimeSupportFactory coreBackedRuntimeSupportFactory() {
    return CoreHttpShellRuntimeSupport::new;
  }
}
