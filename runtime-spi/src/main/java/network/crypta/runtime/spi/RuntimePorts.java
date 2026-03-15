package network.crypta.runtime.spi;

/**
 * Aggregate entry point for runtime-facing SPI adapters used by higher layers.
 *
 * <p>This interface groups the small set of runtime capabilities currently exposed outside the
 * daemon root module. Instead of injecting several unrelated services into infrastructure code, the
 * runtime exposes one stable handle that can be threaded through legacy code paths with minimal
 * disruption. Each sub-port narrows access to a specific concern such as execution, randomness,
 * file-transfer policy, lifecycle observation, or configuration management.
 *
 * <p>The aggregate is intentionally small and JDK-only. It is not a general domain API for the
 * node, and it does not attempt to model every daemon subsystem. Future adapters can depend on this
 * interface as a conservative platform boundary while legacy code continues to use richer internal
 * types until later migrations happen.
 *
 * @see ExecutionPort
 * @see RandomnessPort
 * @see TransferAccessPort
 * @see LifecyclePort
 * @see ConfigPort
 * @see ConnectivityPort
 * @see NodeInfoPort
 * @see PeerPort
 * @see RequestQueuePort
 */
public interface RuntimePorts {
  /**
   * Returns the execution capability exposed to infrastructure code.
   *
   * <p>Use this port when a caller needs to enqueue background work without depending on the
   * daemon's executor classes. The returned object should be treated as a long-lived runtime view
   * rather than as a disposable handle, and callers should keep their own task semantics outside
   * the SPI.
   *
   * @return execution-facing runtime port for submitting named asynchronous work
   */
  ExecutionPort execution();

  /**
   * Returns the randomness capability exposed to infrastructure code.
   *
   * <p>This groups both secure byte generation and the existing weak random generator behind one
   * JDK-level abstraction. Callers should choose the secure or weak path based on the sensitivity
   * of the values they need, not on convenience.
   *
   * @return randomness-facing runtime port for secure and weak random operations
   */
  RandomnessPort randomness();

  /**
   * Returns the file-transfer policy capability exposed to infrastructure code.
   *
   * <p>This port lets adapters ask whether uploads or downloads are permitted for a path and get
   * the currently configured transfer directories. The returned object intentionally uses only
   * {@link java.io.File} values so it remains independent of daemon-only policy types.
   *
   * @return transfer-policy runtime port for directory metadata and allow/deny checks
   */
  @SuppressWarnings("unused")
  TransferAccessPort transferAccess();

  /**
   * Returns the lifecycle capability exposed to infrastructure code.
   *
   * <p>Use this port when code needs to observe a startup or shutdown state without gaining control
   * over lifecycle transitions. It is read-only by design and should be treated as a lightweight
   * view of the live daemon state.
   *
   * @return lifecycle runtime port for observing startup time and state flags
   */
  LifecyclePort lifecycle();

  /**
   * Returns the configuration capability exposed to infrastructure code.
   *
   * <p>This port lets higher layers export selected configuration sections, apply dotted-name
   * overrides, and request persistence without depending on daemon configuration classes. The
   * returned object should be treated as a live runtime view backed by the node's existing config
   * subsystem.
   *
   * @return configuration runtime port for export, update, and persistence operations
   */
  ConfigPort config();

  /**
   * Returns the connectivity capability exposed to admin-facing HTTP code.
   *
   * <p>This port lets higher layers request one detached snapshot containing the current listener
   * port configuration, UDP socket status summary, optional connection-type notice, and, when
   * requested, advanced tracker tables. It intentionally exposes only JDK-only DTOs, so callers can
   * render the connectivity page without depending on daemon-only trackers, socket handlers, or
   * alert classes.
   *
   * @return connectivity runtime port for read-only connectivity snapshots
   */
  ConnectivityPort connectivity();

  /**
   * Returns the persistent-request queue-control capability exposed to infrastructure code.
   *
   * <p>This port lets callers submit persistent-request jobs, observe whether the persistence
   * database has already been killed, and schedule lightweight delayed retries without depending on
   * daemon-only persistence runners, client contexts, or ticker implementations.
   *
   * @return queue-control runtime port for persistent-request work and delayed retries
   */
  RequestQueuePort requestQueue();

  /**
   * Returns the node-info capability exposed to management-facing infrastructure code.
   *
   * <p>This port lets higher layers request node greeting metadata and node-reference exports
   * without depending on daemon-only node, version, localization, compressor, or field-set types.
   * The returned object should be treated as a live runtime view whose methods produce detached
   * immutable snapshots.
   *
   * @return node-info runtime port for greeting metadata and node-reference exports
   */
  NodeInfoPort nodeInfo();

  /**
   * Returns the peer-management capability exposed to management-facing infrastructure code.
   *
   * <p>This port lets higher layers list peers, resolve one peer, add or remove peers, adjust
   * darknet-only peer flags, and read or write the existing private darknet comment note without
   * depending on daemon-only peer, network, or field-set types. The returned object should be
   * treated as a live runtime view whose methods produce detached immutable snapshots.
   *
   * @return peer-management runtime port for peer inventory and peer mutation
   */
  PeerPort peer();
}
