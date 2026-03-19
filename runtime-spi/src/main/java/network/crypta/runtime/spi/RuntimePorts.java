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
 * @see ConnectionsPagePort
 * @see ConnectionsSupportPort
 * @see DarknetConnectionsPort
 * @see DarknetMessagingPort
 * @see DiagnosticPort
 * @see QueueCompletionPort
 * @see QueuePagePort
 * @see QueueDownloadPort
 * @see QueueMutationPort
 * @see QueueSupportPort
 * @see StatisticsPort
 * @see PageChromePort
 * @see NodeInfoPort
 * @see PeerPort
 * @see RequestQueuePort
 * @see SecurityLevelsPort
 * @see FirstTimeWizardPort
 * @see WelcomePagePort
 * @see WelcomeActionPort
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
   * Returns the legacy connections-page capability exposed to admin-facing HTTP code.
   *
   * <p>This port lets higher layers request one detached page snapshot for either the darknet
   * friends page or the opennet strangers page without depending on daemon-only node, peer, stats,
   * or HTML builder types. Request-context-only concerns such as alert summaries and form-password
   * protected peer-action wrappers remain in the HTTP layer, but the returned object keeps the
   * large legacy peer traversal, sorting, and HTML fragment rendering inside the daemon root
   * module.
   *
   * @return connections-page runtime port for detached legacy friends and strangers snapshots
   */
  ConnectionsPagePort connectionsPage();

  /**
   * Returns the legacy connections-page support capability exposed to admin-facing HTTP code.
   *
   * <p>This port keeps a small set of remaining live-runtime helpers behind the runtime boundary:
   * the opennet-enabled flag used to gate the strangers page and the peer-offer reference import
   * text used by the legacy add-peer flow. It is intentionally page-support-oriented rather than a
   * general node API.
   *
   * @return connections-page support port for opennet enablement and peer-offer reference text
   */
  ConnectionsSupportPort connectionsSupport();

  /**
   * Returns the legacy darknet friends-page companion capability exposed to admin-facing HTTP code.
   *
   * <p>This port lets higher layers resolve the current hash-based friends-page selection tokens to
   * detached peer identity, display-name, and private-note data, and export one peer-specific full
   * noderef without traversing live daemon peers directly. It exists only for the remaining legacy
   * friends-page POST and download paths that have not yet moved to a more general detached model.
   *
   * @return darknet friends-page companion port for detached peer selection and noderef export
   */
  DarknetConnectionsPort darknetConnections();

  /**
   * Returns the legacy darknet message-compose capability exposed to admin-facing HTTP code.
   *
   * <p>This port lets higher layers send node-to-node text messages and file offers to detached
   * peer identities without depending on daemon-only peer classes, upload wrappers, or peer-status
   * constants. The returned object should be treated as a live runtime view that resolves detached
   * peer identifiers on demand and preserves the current UI-level delivery categorization.
   *
   * @return darknet messaging runtime port for detached compose/send actions
   */
  DarknetMessagingPort darknetMessaging();

  /**
   * Returns the diagnostic-report capability exposed to admin-facing HTTP code.
   *
   * <p>This port lets higher layers request one detached plain-text report snapshot containing the
   * current diagnostic section ordering and body lines. It intentionally exposes only JDK-only
   * section DTOs, so callers can render the legacy diagnostic page without depending on daemon-only
   * node, FCP, statistics, or thread-diagnostics types.
   *
   * @return diagnostic-report runtime port for read-only report snapshots
   */
  DiagnosticPort diagnostic();

  /**
   * Returns the shared admin page-chrome capability exposed to HTTP shell rendering code.
   *
   * <p>This port lets higher layers request one detached status-bar snapshot containing the current
   * detached security levels plus peer-progress counts without depending on daemon-only node, peer,
   * opennet, or security-level classes. The HTTP layer still owns alerts, language selection, mode
   * switching, menu rendering, and all HTML structures.
   *
   * @return page-chrome runtime port for detached shared shell state
   */
  PageChromePort pageChrome();

  /**
   * Returns the legacy queue support capability exposed to admin-facing HTTP code.
   *
   * <p>This port keeps the remaining queue-oriented live-runtime helpers behind the runtime
   * boundary: the backend-enabled gate, the persistence-disabled support snapshot, and the panic
   * start / finish actions. It is intentionally page-support-oriented rather than a general queue
   * API.
   *
   * @return queue support port for backend enablement, persistence state, and panic actions
   */
  QueueSupportPort queueSupport();

  /**
   * Returns the legacy queue-completion tracking capability exposed to admin-facing HTTP code.
   *
   * <p>This port keeps the remaining completion callback registration, persisted completed-request
   * recovery, and completion alert registration inside the daemon root module while exposing only a
   * minimal idempotent startup hook upstream.
   *
   * @return queue-completion runtime port for per-side completion-tracker startup
   */
  QueueCompletionPort queueCompletion();

  /**
   * Returns the legacy queue-page read capability exposed to admin-facing HTTP code.
   *
   * <p>This port lets higher layers request one detached HTML-template snapshot for either the
   * downloads or uploads queue, together with the count subpage and key-list export, without
   * depending on daemon-only queue, requester, or HTML builder types. Request-context-only controls
   * such as alert summaries and form-password injection remain in the HTTP layer.
   *
   * @return queue-page runtime port for detached legacy queue snapshots and text exports
   */
  QueuePagePort queuePage();

  /**
   * Returns the legacy queue-download capability exposed to admin-facing HTTP code.
   *
   * <p>This port keeps the remaining live creation of new persistent downloads inside the daemon
   * root module while exposing only a narrow JDK-only request shape upstream. Callers retain HTTP
   * request parsing, per-key bulk aggregation, redirects, and user-facing error mapping.
   *
   * @return queue-download runtime port for creating new persistent downloads
   */
  QueueDownloadPort queueDownload();

  /**
   * Returns the legacy queue-insert capability exposed to admin-facing HTTP code.
   *
   * <p>This port keeps the remaining new-upload and local-insert queue registration inside the
   * daemon root module while exposing only narrow JDK-only request shapes upstream. Callers retain
   * HTTP request parsing, URI validation, redirects, and user-facing error mapping.
   *
   * @return queue-insert runtime port for creating new persistent uploads and local inserts
   */
  QueueInsertPort queueInsert();

  /**
   * Returns the legacy queue-mutation capability exposed to admin-facing HTTP code.
   *
   * <p>This port keeps the remaining existing-request queue mutations inside the daemon root module
   * while exposing only a narrow JDK-only mutation surface upstream. Callers keep request parsing,
   * confirmation pages, redirects, and HTTP-specific error mapping in their own layer.
   *
   * @return queue-mutation runtime port for existing persistent-request mutations
   */
  QueueMutationPort queueMutation();

  /**
   * Returns the legacy statistics-page capability exposed to admin-facing HTTP code.
   *
   * <p>This port lets higher layers request one detached HTML-template snapshot for either the main
   * statistics overview or the requester subpage without depending on daemon-only node, peer,
   * requester, or HTML builder types. Request-context-only controls remain in the HTTP layer, but
   * the returned object keeps the large legacy page traversal and formatting inside the daemon root
   * module.
   *
   * @return statistics-page runtime port for detached overview and requester snapshots
   */
  StatisticsPort statistics();

  /**
   * Returns the legacy security-levels-page capability exposed to admin-facing HTTP code.
   *
   * <p>This port keeps the remaining live security-level reads, confirmation-warning generation,
   * and master-password-file mutations behind the runtime boundary while exposing only SPI-local
   * enums, snapshots, status values, and plain rendered HTML fragments upstream.
   *
   * @return security-levels runtime port for detached page state and mutations
   */
  SecurityLevelsPort securityLevels();

  /**
   * Returns the legacy JavaScript first-time-wizard capability exposed to admin-facing HTTP code.
   *
   * <p>This port keeps the remaining live wizard reads, validation bounds, bandwidth suggestions,
   * security-level changes, master-password mutations, and config writes inside the daemon root
   * module while exposing only detached SPI-local snapshot and submission values upstream.
   *
   * @return first-time-wizard runtime port for detached page state and submission application
   */
  FirstTimeWizardPort firstTimeWizard();

  /**
   * Returns the legacy welcome-page read capability exposed to admin-facing HTTP code.
   *
   * <p>This port keeps the remaining welcome-page config reads and latest-log tail file selection
   * inside the daemon root module while exposing only a tiny detached snapshot and one text export
   * upstream. It is intentionally read-only and should not grow to cover the welcome page's POST
   * actions.
   *
   * @return welcome-page runtime port for detached read-only page state and latest-log export
   */
  WelcomePagePort welcomePage();

  /**
   * Returns the legacy welcome-page action capability exposed to admin-facing HTTP code.
   *
   * <p>This port keeps the remaining welcome-page POST actions inside the daemon root module while
   * exposing only a very small page-specific mutation surface upstream. It is intentionally
   * transitional and should not expand into a general maintenance API.
   *
   * @return welcome-page action runtime port for update, restart, shutdown, and bandwidth upgrade
   */
  WelcomeActionPort welcomeAction();

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
