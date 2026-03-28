package network.crypta.runtime.admin;

import java.io.IOException;
import java.util.Objects;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.admin.queue.QueueAdminBackend;
import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;

/**
 * Bridges the remaining legacy queue support helpers onto the runtime SPI.
 *
 * <p>This adapter is intentionally small. It keeps the persistence support-state inspection and the
 * panic start / finish sequence in the daemon root module while presenting the HTTP layer with the
 * detached contract defined by {@link QueueSupportPort}. Queue availability itself is read through
 * the runtime-owned queue backend seam.
 *
 * <p>The adapter does not attempt to normalize or reinterpret the daemon state. It forwards the
 * live checks in the same order the legacy queue code previously used, including the short-circuit
 * that avoids resolving persistence-broken path details while the node is still awaiting a password
 * or already stopping.
 */
final class LegacyQueueSupportPort implements QueueSupportPort {
  /** Shared daemon client core used to reach the live queue support state. */
  private final NodeClientCore core;

  /** Runtime-owned queue backend seam used for queue availability checks. */
  private final QueueAdminBackend queueBackend;

  /**
   * Creates a queue support adapter backed by the current daemon runtime.
   *
   * <p>The adapter keeps a direct reference to {@code core} because the remaining queue support
   * helpers still span node persistence state and the panic lifecycle. Queue availability is
   * supplied separately through the runtime-owned backend seam.
   *
   * @param core daemon client core that owns the live persistence and panic collaborators
   * @param queueBackend queue backend seam that exposes the live queue availability state
   */
  LegacyQueueSupportPort(NodeClientCore core, QueueAdminBackend queueBackend) {
    this.core = Objects.requireNonNull(core, "core");
    this.queueBackend = Objects.requireNonNull(queueBackend, "queueBackend");
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation delegates to the runtime-owned queue backend seam.
   */
  @Override
  public boolean isQueueBackendEnabled() {
    return queueBackend.isEnabled();
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation preserves the legacy branch order. It reads the password and shutdown
   * flags first, returns a short-circuit snapshot for those states, and only resolves the
   * persistence-broken path details when the queue page should actually render them.
   */
  @Override
  public QueuePersistenceStatusSnapshot persistenceStatus() {
    Node node = core.getNode();
    boolean awaitingPassword = node.awaitingPassword();
    boolean stopping = node.isStopping();

    if (awaitingPassword || stopping) {
      return new QueuePersistenceStatusSnapshot(awaitingPassword, stopping, null, null);
    }

    return new QueuePersistenceStatusSnapshot(
        false, false, core.getPersistentTempDir(), node.getDatabasePath());
  }

  /**
   * {@inheritDoc}
   *
   * <p>The adapter preserves the existing daemon-side ordering by deleting the master keys file
   * before triggering the live node panic sequence.
   */
  @Override
  public void beginPanic() throws IOException {
    Node node = core.getNode();
    node.storage().killMasterKeysFile();
    node.panic();
  }

  /**
   * {@inheritDoc}
   *
   * <p>This delegates to the node's final panic completion step after the HTTP layer has already
   * rendered the panicking page.
   */
  @Override
  public void finishPanic() {
    core.getNode().finishPanic();
  }
}
