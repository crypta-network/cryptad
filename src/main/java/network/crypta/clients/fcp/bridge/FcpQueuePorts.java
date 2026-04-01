package network.crypta.clients.fcp.bridge;

import network.crypta.node.NodeClientCore;
import network.crypta.runtime.admin.queue.QueueAdminBackend;
import network.crypta.runtime.admin.queue.page.QueuePageBackend;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueInsertPort;

/**
 * Bridge-owned factory entrypoints for the FCP queue adapters.
 *
 * <p>This class keeps the constructor knowledge for the queue bridge local to the {@code
 * network.crypta.clients.fcp.bridge} package while exposing only the narrow runtime seams upstream.
 * Runtime-owned wiring code can call the bundle factory without naming the concrete bridge
 * implementations that still belong to the FCP adapter package. That keeps the ownership split
 * explicit while leaving queue behavior, lazy endpoint resolution, and exception mapping in the
 * existing adapter classes.
 *
 * <p>The bundle returned by {@link #create(NodeClientCore)} is intentionally mechanical. It
 * allocates the same bridge implementations that the runtime admin factory previously constructed
 * directly, passes through the same {@link NodeClientCore} instance, and adds no caching or policy
 * of its own. Callers therefore get the same queue semantics and lifecycle expectations as before
 * this refactor.
 */
public final class FcpQueuePorts {
  private FcpQueuePorts() {}

  /**
   * Bundle of queue-related runtime-owned ports backed by the FCP bridge implementations.
   *
   * <p>The bundle is a pure value object. It carries the existing queue bridge instances behind the
   * runtime-owned interfaces so the caller can wire them without depending on the concrete FCP
   * adapter classes.
   */
  public record Bundle(
      QueueAdminBackend adminBackend,
      QueuePageBackend pageBackend,
      QueueCompletionPort completionPort,
      QueueDownloadPort downloadPort,
      QueueInsertPort insertPort) {}

  /**
   * Creates the FCP-backed queue bridge bundle used by runtime-admin wiring.
   *
   * <p>The returned bundle contains the exact bridge implementations previously created directly by
   * the admin runtime factory. Each member preserves the historical constructor wiring and behavior
   * for queue inspection, rendering, completion tracking, download handling, and insert handling.
   *
   * @param core live daemon client core used by all queue bridge adapters in the bundle
   * @return immutable bundle containing the runtime-owned queue bridge interfaces for {@code core}
   */
  public static Bundle create(NodeClientCore core) {
    QueueAdminBackend adminBackend = new FcpQueueAdminBackend(core);
    QueuePageBackend pageBackend = new FcpQueuePageBackend(core);
    QueueCompletionPort completionPort = new LegacyQueueCompletionPort(core);
    QueueDownloadPort downloadPort = new LegacyQueueDownloadPort(core);
    QueueInsertPort insertPort = new LegacyQueueInsertPort(core);
    return new Bundle(adminBackend, pageBackend, completionPort, downloadPort, insertPort);
  }
}
