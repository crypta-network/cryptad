package network.crypta.clients.fcp;

/**
 * Groups the transient helper collaborators owned by {@link ClientGet}.
 *
 * <p>The request still delegates lifecycle, replay, restart, and status duties to specialized
 * helper classes, but it depends on a single bundle instead of storing each helper directly. This
 * keeps the outer request class below the coupling threshold enforced in this repository while
 * preserving the existing runtime behavior and ownership model.
 *
 * <p>Instances are short-lived companions to one {@link ClientGet}. They are created during request
 * assembly, retained only in-memory, and reused for the lifetime of that request. The bundle does
 * not add synchronization of its own; thread-safety remains the same as the underlying helpers and
 * the owning request.
 */
final class ClientGetHelpers {
  /** Helper that rebuilds replayable FCP messages from the request state. */
  private final ClientGetMessageReplay messageReplay;

  /** Helper that applies success, failure, and cleanup transitions to the request. */
  private final ClientGetLifecycle lifecycle;

  /** Helper that exposes payload-oriented accessors without bloating the request class. */
  private final ClientGetPayloadAccess payloadAccess;

  /** Helper that captures the request state used to build status snapshots. */
  private final ClientGetStatusSnapshotBuilder statusSnapshotBuilder;

  /** Helper that recreates or restarts the underlying getter when needed. */
  private final ClientGetRestartCoordinator restartCoordinator;

  /** Helper that sends or derives status-oriented protocol messages for the request. */
  private final ClientGetStatusReporter statusReporter;

  /**
   * Creates the full helper bundle for one request.
   *
   * <p>Each specialized helper receives the same owning request instance, so they can coordinate on
   * a shared state without the outer request exposing extra fields. The constructor performs only
   * deterministic object creation and does not trigger network or persistence work.
   *
   * @param request owning request whose lifecycle and status state the helpers operate on
   */
  ClientGetHelpers(ClientGet request) {
    messageReplay = new ClientGetMessageReplay(request);
    lifecycle = new ClientGetLifecycle(request);
    payloadAccess = new ClientGetPayloadAccess(request);
    statusSnapshotBuilder = new ClientGetStatusSnapshotBuilder(request);
    restartCoordinator = new ClientGetRestartCoordinator(request);
    statusReporter = new ClientGetStatusReporter(request);
  }

  /**
   * Returns the helper responsible for rebuilding replayable FCP messages.
   *
   * @return replay helper shared by the owning request for repeated message emission
   */
  ClientGetMessageReplay messageReplay() {
    return messageReplay;
  }

  /**
   * Returns the helper that applies request lifecycle transitions.
   *
   * @return lifecycle helper used for success, failure, and cleanup handling
   */
  ClientGetLifecycle lifecycle() {
    return lifecycle;
  }

  /**
   * Returns the helper that exposes payload data and delivery-mode views.
   *
   * @return payload helper used for bucket, size, MIME, and return-type access
   */
  ClientGetPayloadAccess payloadAccess() {
    return payloadAccess;
  }

  /**
   * Returns the helper that captures status snapshot input data.
   *
   * @return snapshot builder used when the request exposes status to clients
   */
  ClientGetStatusSnapshotBuilder statusSnapshotBuilder() {
    return statusSnapshotBuilder;
  }

  /**
   * Returns the helper that coordinates getter restart behavior.
   *
   * @return restart helper responsible for recreating or resuming fetch execution
   */
  ClientGetRestartCoordinator restartCoordinator() {
    return restartCoordinator;
  }

  /**
   * Returns the helper that reports request status through FCP messages.
   *
   * @return status reporter used for synchronous and asynchronous request status output
   */
  ClientGetStatusReporter statusReporter() {
    return statusReporter;
  }
}
