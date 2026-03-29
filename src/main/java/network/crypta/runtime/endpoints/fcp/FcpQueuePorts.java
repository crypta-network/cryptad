package network.crypta.runtime.endpoints.fcp;

import network.crypta.node.NodeClientCore;
import network.crypta.runtime.admin.queue.QueueAdminBackend;
import network.crypta.runtime.admin.queue.page.QueuePageBackend;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueInsertPort;

/**
 * Bridge-owned factory methods for the FCP queue adapters.
 *
 * <p>This class keeps the constructor knowledge for the queue bridge local to the {@code
 * network.crypta.runtime.endpoints.fcp} package while exposing only the narrow runtime seams
 * upstream. Runtime-owned wiring code can call these methods without naming the concrete bridge
 * implementations that still belong to the FCP endpoint package. That keeps the ownership split
 * explicit while leaving queue behavior, lazy endpoint resolution, and exception mapping in the
 * existing adapter classes.
 *
 * <p>Each method is intentionally mechanical. It allocates the same bridge implementation that the
 * runtime admin factory previously constructed directly, passes through the same {@link
 * NodeClientCore} instance, and adds no caching or policy of its own. Callers therefore get the
 * same queue semantics and lifecycle expectations as before this refactor.
 */
public final class FcpQueuePorts {
  private FcpQueuePorts() {}

  /**
   * Creates the FCP-backed queue-admin bridge used by runtime-admin diagnostics and mutations.
   *
   * <p>The returned backend delegates queue inspection and mutation calls to the existing FCP
   * bridge layer. This method performs no validation, caching, or eager endpoint initialization. It
   * simply preserves the historical constructor wiring while exposing only the runtime-owned {@link
   * QueueAdminBackend} seam to callers outside the package.
   *
   * @param core live daemon client core that the bridge uses to resolve current FCP endpoints
   * @return queue-admin backend backed by the existing FCP bridge implementation for {@code core}
   */
  public static QueueAdminBackend adminBackend(NodeClientCore core) {
    return new FcpQueueAdminBackend(core);
  }

  /**
   * Creates the FCP-backed queue-page bridge used to read queue state for HTML rendering.
   *
   * <p>The returned backend is the same page-oriented adapter that the runtime-admin wiring used
   * previously. It remains responsible for translating live FCP queue state into runtime-owned page
   * views, while this factory method keeps only the constructor knowledge inside the bridge-owned
   * package.
   *
   * @param core live daemon client core that provides access to the current FCP endpoint bundle
   * @return queue-page backend backed by the existing FCP bridge implementation for {@code core}
   */
  public static QueuePageBackend pageBackend(NodeClientCore core) {
    return new FcpQueuePageBackend(core);
  }

  /**
   * Creates the bridge that enqueues persistent downloads through the legacy FCP path.
   *
   * <p>This method preserves the existing download-port construction exactly. The returned adapter
   * still owns request translation, policy rejection mapping, and lazy FCP server lookup. The
   * factory itself remains a thin package-owned entry point, so runtime-admin code does not import
   * the concrete bridge class directly.
   *
   * @param core live daemon client core used by the download bridge for queue access and policy
   *     checks
   * @return queue-download port backed by the existing FCP bridge implementation for {@code core}
   */
  public static QueueDownloadPort downloadPort(NodeClientCore core) {
    return new LegacyQueueDownloadPort(core);
  }

  /**
   * Creates the bridge that enqueues persistent inserts through the legacy FCP path.
   *
   * <p>The returned adapter is unchanged from the previous wiring. It still translates detached
   * insert requests into the legacy FCP insert flow and defers all queue semantics to the existing
   * implementation. This method exists only to keep the constructor dependency local to the bridge
   * package.
   *
   * @param core live daemon client core used by the insert bridge to reach the current FCP server
   * @return queue-insert port backed by the existing FCP bridge implementation for {@code core}
   */
  public static QueueInsertPort insertPort(NodeClientCore core) {
    return new LegacyQueueInsertPort(core);
  }

  /**
   * Creates the bridge that exposes completed-request queue operations through the runtime SPI.
   *
   * <p>The returned adapter continues to use the existing legacy completion-port implementation,
   * including its current persistence access and identifier loading behavior. This method adds no
   * new policy. It only narrows the dependency that external wiring code takes on the bridge
   * package.
   *
   * @param core live daemon client core that supplies the completion bridge with endpoint access
   * @return queue-completion port backed by the existing FCP bridge implementation for {@code core}
   */
  public static QueueCompletionPort completionPort(NodeClientCore core) {
    return new LegacyQueueCompletionPort(core);
  }
}
