package network.crypta.clients.fcp;

import static network.crypta.clients.fcp.RequestIdentifier.RequestType.GET;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.keys.FreenetURI;
import network.crypta.node.PrioRunnable;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.node.RequestStarter;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a single high-level request that the node carries out on behalf of an FCP client.
 *
 * <p>Instances of this class encapsulate the lifecycle, persistence configuration and bookkeeping
 * for operations such as {@code ClientGet}, {@code ClientPut} and multi-key fetches. A {@code
 * ClientRequest} is created by the FCP layer when a client issues a request, then scheduled and
 * tracked by the node until it completes, fails or is explicitly cancelled. Subclasses implement
 * the protocol-specific behavior while this base class coordinates common state and interaction
 * with the core node.
 *
 * <p>Requests may be connection-bound, reboot-persistent or fully persistent on disk. Each instance
 * keeps a stable identifier, priority class, client token and statistics that are used for progress
 * reporting and scheduling. Implementations are typically confined to the owning {@link
 * ClientContext} and must be safe to invoke from the node's worker threads.
 *
 * <ul>
 *   <li>Tracks client-visible metadata such as identifiers, tokens and verbosity.
 *   <li>Coordinates persistence, resumption and cancellation across reconnects and restarts.
 *   <li>Provides hooks for status reporting, restart and orderly shutdown.
 * </ul>
 *
 * @see RequestIdentifier
 * @see PersistentRequestClient
 * @see ClientRequester
 */
public abstract class ClientRequest implements Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(ClientRequest.class);

  /**
   * ATTENTION: When incrementing this, please skip version 2. Version 2 had already temporarily
   * been used by a development branch.
   */
  @Serial private static final long serialVersionUID = 1L;

  /** URI to fetch, or target URI to insert to */
  protected FreenetURI uri;

  /** Unique request identifier */
  protected final String identifier;

  /** Verbosity level. Relevant to all ClientRequests, although they interpret it differently. */
  protected final int verbosity;

  /** Original FCPConnectionHandler. Null if persistence != connection */
  protected final transient FCPConnectionHandler origHandler;

  /** Is the request on the global queue? */
  protected final boolean global;

  /** If the request isn't on the global queue, what is the client's name? */
  protected final String clientName;

  /** Client */
  protected transient PersistentRequestClient client;

  /** Priority class */
  protected short priorityClass;

  /** Is the request scheduled as "real-time" (as opposed to bulk)? */
  protected final boolean realTime;

  /** Persistence type */
  protected final Persistence persistence;

  /** Has the request finished? */
  protected boolean finished;

  /**
   * Client token (string to feed back to the client on a Persistent* when he does a
   * ListPersistentRequests).
   */
  protected String clientToken;

  /** Timestamp : startup time */
  protected final long startupTime;

  /** Timestamp : completion time */
  protected long completionTime;

  /**
   * Low-level node-side request handle used to communicate with the core routing and scheduling
   * engine.
   *
   * <p>This reference is transient and is recreated when a persistent request is resumed from disk,
   * ensuring that the request always uses a live core-side representation.
   */
  protected transient RequestClient lowLevelClient;

  /**
   * Cached hash code derived from {@link Object#hashCode()} to provide a stable identifier even
   * after the request has been serialized and deserialized.
   */
  private final int hashCode;

  @Override
  public int hashCode() {
    return hashCode;
  }

  @Override
  @SuppressWarnings("RedundantMethodOverride")
  public boolean equals(Object obj) {
    return this == obj;
  }

  // Legacy threshold callback removed.

  /**
   * Creates a {@code ClientRequest} associated with an existing persistent client.
   *
   * <p>This constructor is used when a {@link PersistentRequestClient} has already been resolved,
   * typically while resuming a request. It configures core metadata such as the requested {@link
   * FreenetURI}, client-visible identifier, verbosity, priority class and persistence mode, and
   * wires the request to the appropriate global or per-client queue.
   *
   * @param uri2 target URI being fetched or inserted on behalf of the client
   * @param identifier2 unique identifier string supplied by the FCP client for correlation
   * @param verbosity2 requested verbosity level for progress and status messages
   * @param handler connection handler owning the request while persistence is {@code CONNECTION}
   * @param client persistent request client instance that represents the owning FCP client
   * @param priorityClass2 initial priority class used by the scheduler to order work
   * @param persistenceType2 persistence mode controlling lifetime across disconnects and restarts
   * @param realTime whether the request is scheduled as real-time instead of background bulk
   * @param clientToken2 optional opaque token echoed back to the client in notifications
   * @param global whether the request belongs to the shared global queue rather than a client
   */
  protected ClientRequest(
      FreenetURI uri2,
      String identifier2,
      int verbosity2,
      FCPConnectionHandler handler,
      PersistentRequestClient client,
      short priorityClass2,
      Persistence persistenceType2,
      boolean realTime,
      String clientToken2,
      boolean global) {
    int hash = super.hashCode();
    if (hash == 0) hash = 1;
    hashCode = hash;
    this.uri = uri2;
    this.identifier = identifier2;
    if (global) {
      this.verbosity = Integer.MAX_VALUE;
      this.clientName = null;
    } else {
      this.verbosity = verbosity2;
      this.clientName = client.name;
    }
    this.finished = false;
    this.priorityClass = priorityClass2;
    this.persistence = persistenceType2;
    this.clientToken = clientToken2;
    this.global = global;
    if (persistence == Persistence.CONNECTION) {
      this.origHandler = handler;
      lowLevelClient = origHandler.connectionRequestClient(realTime);
      this.client = null;
    } else {
      origHandler = null;
      this.client = client;
      if (client == null) {
        throw new IllegalStateException("Persistent client must not be null");
      }
      if (client.persistence != persistence) {
        throw new IllegalStateException("Persistent client has mismatched persistence");
      }
      lowLevelClient = client.lowLevelClient(realTime);
    }
    assert lowLevelClient != null;
    this.startupTime = System.currentTimeMillis();
    this.realTime = realTime;
  }

  /**
   * Creates a {@code ClientRequest} and resolves the persistent client from the connection.
   *
   * <p>This constructor is typically used when a request is first created from an FCP command. It
   * determines the appropriate persistent client (global or per-connection), configures the
   * request's persistence mode, priority and verbosity and allocates a low-level {@link
   * RequestClient} suitable for either real-time or bulk scheduling.
   *
   * @param uri2 target URI being fetched or inserted on behalf of the client
   * @param identifier2 unique identifier string supplied by the FCP client for correlation
   * @param verbosity2 requested verbosity level for progress and status messages
   * @param handler connection handler from which persistent client information is derived
   * @param priorityClass2 initial priority class used by the scheduler to order work
   * @param persistenceType2 persistence mode controlling lifetime across disconnects and restarts
   * @param realTime whether the request is scheduled as real-time instead of background bulk
   * @param clientToken2 optional opaque token echoed back to the client in notifications
   * @param global whether the request belongs to the shared global queue rather than a client
   */
  protected ClientRequest(
      FreenetURI uri2,
      String identifier2,
      int verbosity2,
      FCPConnectionHandler handler,
      short priorityClass2,
      Persistence persistenceType2,
      final boolean realTime,
      String clientToken2,
      boolean global) {
    int hash = super.hashCode();
    if (hash == 0) hash = 1;
    hashCode = hash;
    this.uri = uri2;
    this.identifier = identifier2;
    this.finished = false;
    this.priorityClass = priorityClass2;
    this.persistence = persistenceType2;
    this.clientToken = clientToken2;
    this.global = global;
    if (persistence == Persistence.CONNECTION) {
      this.origHandler = handler;
      client = null;
      lowLevelClient = new RequestClientBuilder().realTime(realTime).build();
      this.clientName = null;
      this.verbosity = verbosity2;
    } else {
      origHandler = null;
      client = resolvePersistentClient(handler, persistenceType2, global);
      if (global) {
        this.verbosity = Integer.MAX_VALUE;
        clientName = null;
      } else {
        this.verbosity = verbosity2;
        this.clientName = client.name;
      }
      lowLevelClient = client.lowLevelClient(realTime);
      if (lowLevelClient == null)
        throw new NullPointerException(
            "No lowLevelClient from client: "
                + client
                + " global = "
                + global
                + " persistence = "
                + persistence);
    }
    if (lowLevelClient.persistent() != (persistence == Persistence.FOREVER))
      throw new IllegalStateException(
          "Low level client.persistent="
              + lowLevelClient.persistent()
              + " but persistence type = "
              + persistence);
    assert client == null || (client.persistence == persistence);
    this.startupTime = System.currentTimeMillis();
    this.realTime = realTime;
  }

  private PersistentRequestClient resolvePersistentClient(
      FCPConnectionHandler handler, Persistence persistenceType2, boolean global) {
    if (global) {
      return persistenceType2 == Persistence.FOREVER
          ? handler.getServer().getGlobalForeverClient()
          : handler.getServer().getGlobalRebootClient();
    }
    return persistenceType2 == Persistence.FOREVER
        ? handler.getForeverClient()
        : handler.getRebootClient();
  }

  /**
   * No-argument constructor used only by the serialization framework.
   *
   * <p>Fields are initialized to neutral defaults and populated later during deserialization and
   * {@link #onResume(ClientContext)}. Application code should not call this constructor directly.
   */
  protected ClientRequest() {
    // For serialization.
    identifier = null;
    verbosity = 0;
    origHandler = null;
    global = false;
    clientName = null;
    realTime = false;
    persistence = null;
    startupTime = 0;
    hashCode = 0;
  }

  /**
   * Handles loss of the associated FCP connection while the request is active.
   *
   * <p>The node calls this method when the underlying FCP connection terminates unexpectedly or is
   * closed by the client. Implementations typically record the condition, adjust any queued
   * responses and decide whether the request should continue running as a persistent background job
   * or be cancelled outright. This callback is invoked on a node worker thread and should return
   * quickly.
   *
   * @param context client context providing access to schedulers, queues and persistent roots
   */
  public abstract void onLostConnection(ClientContext context);

  /**
   * Sends any queued protocol messages for this request to a reconnecting client.
   *
   * <p>This is used when the client lists persistent requests or re-establishes an FCP session and
   * wants to receive outstanding messages such as progress updates, completion notifications or
   * failure details. Implementations should respect {@code includeData} to avoid resending large
   * payloads unnecessarily and may honor {@code onlyData} when a client is interested only in bulk
   * data transfers.
   *
   * @param handler output handler responsible for writing messages to the current connection
   * @param listRequestIdentifier identifier of the listing command that triggered this replay
   * @param includeData whether message bodies and bulk data blocks are included in the replay
   * @param onlyData whether to send only data-bearing messages and suppress pure metadata updates
   */
  public abstract void sendPendingMessages(
      FCPConnectionOutputHandler handler,
      String listRequestIdentifier,
      boolean includeData,
      boolean onlyData);

  // Persistence

  /**
   * Describes how long a client request remains associated with the node.
   *
   * <p>The persistence mode determines whether a request is tied to the lifetime of a single FCP
   * connection, survives reconnects within the same node process or is durably stored on disk
   * across restarts. The chosen value influences queue selection, resumption behavior and whether
   * {@link PersistentRequestClient} instances are created.
   */
  public enum Persistence {
    /** Default: persists until connection loss. */
    CONNECTION,
    /**
     * Reports to client by name; persists over connection loss. Not saved to disk, so dies on
     * reboot.
     */
    REBOOT,
    /** Same as reboot but saved to disk, persists forever. */
    FOREVER;

    /**
     * Parses a persistence mode string from an FCP message and validates it.
     *
     * <p>The method accepts the textual representation used in the FCP protocol, for example {@code
     * "connection"}, {@code "reboot"} or {@code "forever"}, falling back to {@link #CONNECTION}
     * when {@code persistenceString} is {@code null}. Invalid values produce a {@link
     * MessageInvalidException} with a protocol error suitable for returning to the client.
     *
     * @param persistenceString textual persistence mode supplied by the client, case-insensitive
     * @param identifier request identifier used to decorate any resulting error message
     * @param global whether the request is being created on the global or per-client queue
     * @return parsed persistence value describing the desired lifetime for the new request
     * @throws MessageInvalidException if {@code persistenceString} is not a known persistence name
     */
    public static Persistence parseOrThrow(
        String persistenceString, String identifier, boolean global)
        throws MessageInvalidException {
      try {
        if (persistenceString == null) return Persistence.CONNECTION;
        else return Persistence.valueOf(persistenceString.toUpperCase());
      } catch (IllegalArgumentException _) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.ERROR_PARSING_NUMBER,
            "Error parsing Persistence field: " + persistenceString,
            identifier,
            global);
      }
    }
  }

  @SuppressWarnings("SameParameterValue")
  abstract void register(boolean noTags) throws IdentifierCollisionException;

  /**
   * Cancels this request and releases any associated resources.
   *
   * <p>If the underlying {@link ClientRequester} is still active it is asked to cancel itself via
   * the supplied {@link ClientContext}. Persistent state and any cached buckets are then freed by
   * calling {@link #freeData()}. This method is idempotent and may be invoked after completion when
   * the caller no longer cares about remaining notifications.
   *
   * @param context client context used when propagating the cancellation into the core node
   */
  public void cancel(ClientContext context) {
    ClientRequester cr = getClientRequest();
    // It might have been finished on startup.
    if (LOG.isDebugEnabled())
      LOG.debug("Cancelling {} for {} persistence = {}", cr, this, persistence);
    if (cr != null) cr.cancel(context);
    freeData();
  }

  /**
   * Returns whether this request is configured to persist indefinitely.
   *
   * <p>A request is considered "forever persistent" when its {@link #persistence} mode is {@link
   * Persistence#FOREVER}, meaning it survives connection loss and node restarts until explicitly
   * removed by the client.
   *
   * @return {@code true} when the request is stored on disk and survives node restarts
   */
  public boolean isPersistentForever() {
    return persistence == Persistence.FOREVER;
  }

  /**
   * Returns whether this request is persistent beyond the creating FCP connection.
   *
   * <p>Connection-persistent requests are discarded automatically when their connection closes,
   * while reboot and forever persistent requests continue running under a {@link
   * PersistentRequestClient}. This helper hides the underlying {@link #persistence} enum.
   *
   * @return {@code true} if the request is not {@link Persistence#CONNECTION} and can outlive
   *     connection loss
   */
  public boolean isPersistent() {
    return persistence != Persistence.CONNECTION;
  }

  /**
   * Reports whether the request has reached a terminal state.
   *
   * <p>This flag is set once the core node has either successfully completed the operation or
   * determined that it has irrecoverably failed. The request object may still remain registered,
   * for example until the client acknowledges the completion message.
   *
   * @return {@code true} once the request has finished and will not perform further work
   */
  public boolean hasFinished() {
    return finished;
  }

  /**
   * Returns the client-supplied identifier for this request.
   *
   * <p>The identifier is opaque to the node and is echoed back in all FCP messages related to this
   * request so that clients can correlate responses with their original commands.
   *
   * @return identifier string that uniquely identifies this request for the owning client
   */
  public String getIdentifier() {
    return identifier;
  }

  /**
   * Returns the underlying {@link ClientRequester} that performs the actual network work.
   *
   * <p>Subclasses typically create a concrete requester in {@link #start(ClientContext)} and return
   * it here so that lifecycle callbacks such as {@link #cancel(ClientContext)} and {@link
   * #onShutdown(ClientContext)} can delegate to it.
   *
   * @return currently associated requester instance, or {@code null} when no requester is active
   */
  protected abstract ClientRequester getClientRequest();

  /**
   * Invoked when a completed request is dropped without explicit client acknowledgement.
   *
   * <p>The default implementation cancels the internal requester again and frees cached data.
   * Subclasses may override this to perform additional accounting or logging as required.
   *
   * @param context client context used when propagating the drop semantics into the core
   */
  public void dropped(ClientContext context) {
    cancel(context);
    freeData();
  }

  /**
   * Returns the current priority class used for scheduling this request.
   *
   * <p>Priority classes are defined by {@link RequestStarter} and influence how quickly the node
   * allocates bandwidth and other resources compared to other queued requests.
   *
   * @return priority class value in the range defined by {@link RequestStarter}
   */
  public short getPriority() {
    return priorityClass;
  }

  /** Free cached data bucket(s) */
  protected abstract void freeData();

  /** Request completed. But we may have to stick around until we are acked. */
  protected void finish() {
    if (persistence == Persistence.CONNECTION) origHandler.finishedClientRequest(this);
    else client.finishedClientRequest(this);
  }

  /**
   * Returns the fraction of blocks that have been successfully processed so far.
   *
   * <p>The meaning of a “block” depends on the concrete request type but is typically an individual
   * segment of a split file or key-based chunk. Implementations should return a value between
   * {@code 0.0} and {@code 1.0} when the total block count is known.
   *
   * @return completion fraction in the range {@code 0.0} to {@code 1.0}, or an implementation
   *     specific sentinel
   */
  @SuppressWarnings("unused")
  public abstract double getSuccessFraction();

  /**
   * Returns the total number of blocks that make up this request.
   *
   * <p>This is primarily used for progress reporting and may be approximate while the request is
   * still being analyzed. Implementations may return {@code 0.0} when the total is not yet known.
   *
   * @return total number of blocks expected for this request, or zero when unknown
   */
  public abstract double getTotalBlocks();

  /**
   * Returns the minimum number of blocks that must succeed for the request to complete.
   *
   * <p>For many content types this corresponds to the redundancy threshold in splitfile encoding.
   * Callers typically combine this value with {@link #getFetchedBlocks()} to estimate whether the
   * request is likely to finish successfully.
   *
   * @return minimum number of successful blocks required for a successful request outcome
   */
  @SuppressWarnings("unused")
  public abstract double getMinBlocks();

  /**
   * Returns how many blocks have been fetched or inserted successfully.
   *
   * <p>This count increases monotonically as work progresses. Combined with {@link
   * #getTotalBlocks()} it provides a coarse-grained progress indicator usable by clients and
   * monitoring tools.
   *
   * @return number of blocks that completed successfully so far for this request
   */
  public abstract double getFetchedBlocks();

  /**
   * Returns how many blocks have permanently failed during the current run.
   *
   * <p>Blocks counted here are not expected to succeed on their own without a restart.
   * Implementations decide when to classify a failure as permanent, for example after exhausting
   * retry attempts.
   *
   * @return number of blocks that failed irrecoverably under the current request run
   */
  public abstract double getFailedBlocks();

  /**
   * Returns how many blocks have failed fatally and cannot be retried.
   *
   * <p>This is a stronger notion than {@link #getFailedBlocks()} and usually corresponds to hard
   * validation errors or other unrecoverable conditions observed by the node.
   *
   * @return number of blocks that encountered fatal errors preventing any further processing
   */
  @SuppressWarnings("unused")
  public abstract double getFatalyFailedBlocks();

  /**
   * Returns a human-readable description of the most recent failure, if any.
   *
   * <p>The returned string is intended for diagnostic purposes and may be presented directly to
   * users or logged. Implementations should consider {@code longDescription} when choosing between
   * a brief summary and a more detailed explanation.
   *
   * @param longDescription whether a verbose explanation is preferred over a short summary
   * @return textual description of the failure, or {@code null} if no failure is recorded
   */
  @SuppressWarnings("unused")
  public abstract String getFailureReason(boolean longDescription);

  /**
   * Indicates whether the total block count reported by {@link #getTotalBlocks()} is final.
   *
   * <p>Some request types discover additional blocks over time. Once this method returns {@code
   * true}, callers may treat the total as stable for reporting purposes.
   *
   * @return {@code true} if the total block count is known and will not change further
   */
  @SuppressWarnings("unused")
  public abstract boolean isTotalFinalized();

  /**
   * Starts the request if it has not already been started.
   *
   * <p>Implementations are responsible for creating the underlying {@link ClientRequester},
   * scheduling it on the appropriate queues and updating any status caches. This method may be
   * called again after a restart request but should avoid duplicating work when already running.
   *
   * @param context client context providing access to schedulers, factories and persistent roots
   */
  public abstract void start(ClientContext context);

  /** Indicates whether {@link #start(ClientContext)} has been invoked for this request. */
  protected boolean started;

  /**
   * Returns whether this request has been started at least once.
   *
   * <p>This flag is cleared when {@link #restartAsync(FCPServer, boolean)} schedules a restart so
   * that status caches can distinguish between running and pending requests.
   *
   * @return {@code true} when the request has been started and not yet reset for restart
   */
  public boolean isStarted() {
    return started;
  }

  /**
   * Returns whether this request has completed successfully according to the subclass semantics.
   *
   * <p>Implementations typically base this on internal counters or status codes reported by the
   * {@link ClientRequester}. It must return {@code false} while the request is still running.
   *
   * @return {@code true} when the request has finished and was considered successful
   */
  public abstract boolean hasSucceeded();

  /**
   * Indicates whether this request can currently be restarted.
   *
   * <p>Subclasses may disallow restarts after certain fatal errors or once resources have been
   * discarded. Callers usually check this before invoking {@link #restart(ClientContext, boolean)}
   * or {@link #restartAsync(FCPServer, boolean)}.
   *
   * @return {@code true} if restarting is supported in the current state
   */
  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  public abstract boolean canRestart();

  /**
   * Restarts the request synchronously using the supplied client context.
   *
   * <p>The implementation may reuse persistent on-disk state where available or start from scratch
   * otherwise. Callers are responsible for checking {@link #canRestart()} beforehand. Depending on
   * the request type this operation can be expensive and may block briefly while scheduling work.
   *
   * @param context client context used to create new requesters and schedule work
   * @param disableFilterData whether associated filter data should be disabled for the restart
   * @return {@code true} if the restart was submitted successfully and should be visible to clients
   * @throws PersistenceDisabledException if persistent storage required for restart is not enabled
   */
  public abstract boolean restart(ClientContext context, boolean disableFilterData)
      throws PersistenceDisabledException;

  /**
   * Called after a ModifyPersistentRequest. Sends a PersistentRequestModified message to clients if
   * any value changed.
   *
   * @param newClientToken optional new client token to associate with this request
   * @param newPriorityClass new priority class value requested by the client
   * @param server server instance used to propagate priority changes into the core context
   */
  public void modifyRequest(String newClientToken, short newPriorityClass, FCPServer server) {
    boolean clientTokenChanged = updateClientToken(newClientToken);
    boolean priorityClassChanged = updatePriorityClass(newPriorityClass, server);

    if (!clientTokenChanged && !priorityClassChanged) {
      return;
    }

    server.getCore().getClientContext().jobRunner.setCheckpointASAP();

    PersistentRequestModifiedMessage modifiedMsg =
        buildPersistentRequestModifiedMessage(clientTokenChanged, priorityClassChanged);
    client.queueClientRequestMessage(modifiedMsg, 0);
  }

  private boolean updateClientToken(String newClientToken) {
    if (newClientToken == null) {
      return false;
    }
    if (!newClientToken.equals(clientToken)) {
      clientToken = newClientToken;
      return true;
    }
    return false;
  }

  private boolean updatePriorityClass(short newPriorityClass, FCPServer server) {
    if (newPriorityClass < 0 || newPriorityClass == priorityClass) {
      return false;
    }
    priorityClass = newPriorityClass;
    ClientRequester requester = getClientRequest();
    requester.setPriorityClass(priorityClass, server.getCore().getClientContext());
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.setPriority(identifier, newPriorityClass);
      }
    }
    return true;
  }

  private PersistentRequestModifiedMessage buildPersistentRequestModifiedMessage(
      boolean clientTokenChanged, boolean priorityClassChanged) {
    if (clientTokenChanged && priorityClassChanged) {
      return new PersistentRequestModifiedMessage(identifier, global, priorityClass, clientToken);
    }
    if (priorityClassChanged) {
      return new PersistentRequestModifiedMessage(identifier, global, priorityClass);
    }
    if (clientTokenChanged) {
      return new PersistentRequestModifiedMessage(identifier, global, clientToken);
    }
    return null;
  }

  /**
   * Schedules an asynchronous restart of this request on the appropriate executor.
   *
   * <p>For forever-persistent requests the restart is queued on the persistent job runner so that
   * it can survive node restarts; for other requests it is dispatched to the core executor as a
   * {@link PrioRunnable}. Status caches are updated before the restart is enqueued, and the {@link
   * #started} flag is cleared so that callers can observe the pending restart.
   *
   * @param server server instance used to access the core execution and persistence infrastructure
   * @param disableFilterData whether associated filter data should be disabled for the restart
   * @throws PersistenceDisabledException if the underlying persistence layer cannot support restart
   */
  @SuppressWarnings("unused")
  public void restartAsync(final FCPServer server, final boolean disableFilterData)
      throws PersistenceDisabledException {
    synchronized (this) {
      this.started = false;
    }
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.updateStarted(identifier, false);
      }
    }
    if (persistence == Persistence.FOREVER) {
      server
          .getCore()
          .getClientContext()
          .jobRunner
          .queue(
              (PersistentJob)
                  context -> {
                    try {
                      restart(context, disableFilterData);
                    } catch (PersistenceDisabledException _) {
                      // Impossible
                    }
                    return true;
                  },
              NativeThread.PriorityLevel.HIGH_PRIORITY.value);
    } else {
      server
          .getCore()
          .getNode()
          .getExecutor()
          .execute(
              new PrioRunnable() {

                @Override
                public int getPriority() {
                  return NativeThread.PriorityLevel.NORM_PRIORITY.value;
                }

                @Override
                public void run() {
                  try {
                    restart(server.getCore().getClientContext(), disableFilterData);
                  } catch (PersistenceDisabledException _) {
                    // Impossible
                  }
                }
              },
              "Restart request");
    }
  }

  /**
   * Called after a {@code RemovePersistentRequest} operation has removed this request.
   *
   * <p>The default implementation does nothing; subclasses that maintain additional state may
   * override to send {@code PersistentRequestRemoved} notifications or clean up any on-disk
   * artifacts. The request will no longer be visible in persistent listings after this point.
   *
   * @param context client context that can be used to access persistence services if necessary
   */
  public void requestWasRemoved(ClientContext context) {}

  /**
   * Returns whether this request belongs to one of the global queues.
   *
   * <p>The result is derived from the owning {@link PersistentRequestClient} rather than directly
   * from {@link #global} to ensure consistency after resumption.
   *
   * @return {@code true} if the request is managed by a global queue client
   */
  protected boolean isGlobalQueue() {
    if (client == null) return false;
    return client.isGlobalQueue;
  }

  /**
   * Returns the {@link PersistentRequestClient} that owns this request, if any.
   *
   * <p>This may be {@code null} for connection-persistent requests that are not attached to a named
   * persistent client.
   *
   * @return owning persistent client, or {@code null} for connection-bound requests
   */
  public PersistentRequestClient getClient() {
    return client;
  }

  /**
   * Returns a snapshot of the current status for UI and protocol reporting.
   *
   * <p>Implementations should construct a lightweight {@link RequestStatus} instance reflecting the
   * latest counters and flags for this request.
   *
   * @return current request status object describing progress and outcome
   */
  abstract RequestStatus getStatus();

  private static final long CLIENT_DETAIL_MAGIC = 0xebf0b4f4fa9f6721L;
  private static final int CLIENT_DETAIL_VERSION = 1;

  /**
   * Writes a compact, checksummed representation of this request’s client-visible state.
   *
   * @param dos destination stream used to serialize the client detail
   * @param checker checksum helper that callers can use to wrap or verify the serialized data
   * @throws IOException if writing to {@code dos} fails
   */
  public void getClientDetail(DataOutputStream dos, ChecksumChecker checker) throws IOException {
    if (persistence != Persistence.FOREVER) return;
    dos.writeLong(CLIENT_DETAIL_MAGIC);
    dos.writeInt(CLIENT_DETAIL_VERSION);
    // Identify the request first.
    RequestIdentifier req = getRequestIdentifier();
    req.writeTo(dos);
    // Basic details needed for scheduling, reporting and completion.
    dos.writeBoolean(realTime);
    dos.writeInt(verbosity);
    dos.writeLong(startupTime);
    // persistence is assumed to be PERSIST_FOREVER.
    // uri will be handled by subclasses.
    // This can change.
    dos.writeShort(priorityClass);
    // This can change and is variable size.
    if (clientToken == null) dos.writeBoolean(false);
    else {
      dos.writeBoolean(true);
      dos.writeUTF(clientToken);
    }
    // Stuff that changes on completion
    dos.writeBoolean(finished);
  }

  /**
   * Reconstructs a persistent {@code ClientRequest} instance from the compact client-detail
   * encoding written by {@link #getClientDetail(DataOutputStream, ChecksumChecker)}.
   *
   * <p>This constructor is used when resuming requests from disk. It validates the magic number,
   * version and {@link RequestIdentifier}, then restores scheduling parameters and recreates the
   * {@link PersistentRequestClient} and {@link RequestClient} references needed for further
   * processing.
   *
   * @param dis input stream positioned at the beginning of a client-detail record
   * @param reqID identifier that the caller expects, used to guard against mismatches
   * @param context client execution context used to rebuild persistent client structures
   * @throws IOException if reading from {@code dis} fails or is prematurely truncated
   * @throws StorageFormatException if the stored structure is incompatible or has invalid values
   */
  protected ClientRequest(DataInputStream dis, RequestIdentifier reqID, ClientContext context)
      throws IOException, StorageFormatException {
    long magic = dis.readLong();
    if (magic != CLIENT_DETAIL_MAGIC) throw new StorageFormatException("Bad magic");
    int version = dis.readInt();
    if (version != CLIENT_DETAIL_VERSION) throw new StorageFormatException("Bad version");
    RequestIdentifier copyReq = new RequestIdentifier(dis);
    if (!copyReq.equals(reqID)) throw new StorageFormatException("Request identifier has changed");
    realTime = dis.readBoolean();
    verbosity = dis.readInt();
    startupTime = dis.readLong();
    priorityClass = dis.readShort();
    if (priorityClass < RequestStarter.MAXIMUM_PRIORITY_CLASS
        || priorityClass > RequestStarter.PAUSED_PRIORITY_CLASS)
      throw new StorageFormatException("Bogus priority");
    if (dis.readBoolean()) clientToken = dis.readUTF();
    else clientToken = null;
    finished = dis.readBoolean();
    persistence = Persistence.FOREVER;
    origHandler = null;
    identifier = reqID.identifier;
    global = reqID.globalQueue;
    clientName = reqID.clientName;
    hashCode = super.hashCode();
    // We can't wait until onResume() to get the client, because it may be used in the
    // constructors.
    this.client = context.persistentRoot.makeClient(global, clientName);
    this.lowLevelClient = client.lowLevelClient(realTime);
  }

  /**
   * Reconnects this request to runtime services after it has been deserialized.
   *
   * <p>This method is invoked by the owning {@link ClientRequester} immediately after the request
   * has been read from persistent storage. It recreates transient collaborators such as the {@link
   * PersistentRequestClient}, low-level {@link RequestClient} and any subclass state via {@link
   * #innerResume(ClientContext)} before registering the request with the persistent root again.
   *
   * @param context client context that provides access to persistent roots and utility factories
   * @throws ResumeFailedException if the request cannot be reattached to the runtime environment
   */
  public final void onResume(ClientContext context) throws ResumeFailedException {
    client = context.persistentRoot.makeClient(global, clientName);
    lowLevelClient = client.lowLevelClient(realTime);
    innerResume(context);
    ClientRequester req = getClientRequest();
    if (req != null) req.onResume(context); // Can legally be null.
    context.persistentRoot.resume(this, global, clientName);
  }

  /**
   * Performs subclass-specific reattachment work during {@link #onResume(ClientContext)}.
   *
   * <p>Implementations should recreate transient structures that cannot be serialized directly,
   * such as bucket references or auxiliary state, but must not call back into the {@link
   * ClientRequester} tree to avoid recursion.
   *
   * @param context client context providing access to node-wide services required to resume
   * @throws ResumeFailedException if required resources cannot be reacquired during resumption
   */
  protected abstract void innerResume(ClientContext context) throws ResumeFailedException;

  /**
   * Returns the low-level {@link RequestClient} used to interact with the core node.
   *
   * <p>The returned instance may be {@code null} temporarily during construction or resumption but
   * is normally non-null while the request is active.
   *
   * @return low-level client representing this request within the node's scheduler
   */
  public RequestClient getRequestClient() {
    return lowLevelClient;
  }

  /**
   * Builds a {@link RequestIdentifier} for this request that captures queue and name information.
   *
   * <p>The identifier includes whether the request is global, the client name (if any) and the
   * client-supplied {@link #identifier} string, along with the request type.
   *
   * @return new identifier describing how this request is addressed from the FCP side
   * @throws IllegalStateException if the request uses {@link Persistence#CONNECTION} persistence
   *     and therefore is not associated with a persistent client
   */
  public RequestIdentifier getRequestIdentifier() {
    if (persistence == Persistence.CONNECTION)
      throw new IllegalStateException(); // Not associated with any client.
    return new RequestIdentifier(global, clientName, identifier, getType());
  }

  abstract RequestIdentifier.RequestType getType();

  /**
   * Reconstructs a {@code ClientRequest} from a serialized client-detail stream.
   *
   * <p>Currently only {@link RequestIdentifier.RequestType#GET} is supported and results in a
   * {@link ClientGet} instance. Other types return {@code null}, allowing callers to decide how to
   * treat unknown or legacy request encodings.
   *
   * @param dis input stream positioned at the start of a client-detail record
   * @param reqID identifier describing the request type and queue used during serialization
   * @param context client context used to create any dependent objects during restart
   * @param checker checksum helper responsible for validating the integrity of the serialized data
   * @return reconstructed request instance, or {@code null} when the type is not supported here
   * @throws StorageFormatException if the stored data is malformed or inconsistent with {@code
   *     reqID}
   * @throws IOException if reading from the stream fails while restarting
   * @throws ResumeFailedException if the request cannot be reattached to the runtime environment
   */
  public static ClientRequest restartFrom(
      DataInputStream dis, RequestIdentifier reqID, ClientContext context, ChecksumChecker checker)
      throws StorageFormatException, IOException, ResumeFailedException {
    return reqID.type == GET ? ClientGet.restartFrom(dis, reqID, context, checker) : null;
  }

  /**
   * Returns whether the original fetch was resumed entirely from stored data.
   *
   * <p>Subclasses use this to differentiate between fast restarts that reuse an existing splitfile
   * layout and slower paths that have to reconstruct state from scratch. The value may be used for
   * diagnostics or user-facing status messages.
   *
   * @return {@code true} when the request resumed from existing data without restarting work
   */
  public abstract boolean fullyResumed();

  /**
   * Called just before the node performs its final write during shutdown.
   *
   * <p>Subclasses can override this hook to flush any outstanding state to disk or perform
   * bookkeeping that cannot be recovered automatically after restart. The default implementation
   * forwards the call to the underlying {@link ClientRequester}, if present.
   *
   * @param context client context giving access to persistence mechanisms used during shutdown
   */
  public void onShutdown(ClientContext context) {
    ClientRequester request = getClientRequest();
    if (request != null) request.onShutdown(context);
  }
}
