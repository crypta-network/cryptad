package network.crypta.clients.fcp;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.NativeThread;

/**
 * Handles the <code>ListPersistentRequests</code> FCP message by streaming identifiers of
 * persistent client requests back to the connected peer. The message traverses the reboot
 * (short-lived) and forever (long-lived) request stores, optionally including global watchers, and
 * signals completion once all restartable and still-running requests have been enumerated.
 *
 * <p>This implementation separates listing work into lightweight jobs that respect output queue
 * backpressure and reuse the existing client {@link ClientContext} scheduling primitives. Each
 * phase schedules itself for later execution when the outbound handler is half full, ensuring that
 * message bursts do not overwhelm the connection. Completion is acknowledged with {@link
 * EndListPersistentRequestsMessage} to keep the client-side protocol in sync.
 *
 * <ul>
 *   <li>Responsibility: enumerate pending restartable requests then running requests.
 *   <li>Backpressure: pauses when {@link FCPConnectionOutputHandler#isQueueHalfFull()} reports a
 *       busy link and reschedules via the context ticker.
 *   <li>Scope: operates per incoming message instance and is not intended to be reused across
 *       connections.
 * </ul>
 *
 * <p>This class is not thread-safe; each instance is expected to run within the handling thread or
 * the associated scheduler of a single connection. The nested job types provide the concrete
 * execution strategy for transient (in-memory) and persistent thread-based listing flows.
 */
public class ListPersistentRequestsMessage extends FCPMessage {

  static final String NAME = "ListPersistentRequests";

  /**
   * Optional identifier supplied by the requester and echoed in every generated listing message.
   * Acts as a correlation token so clients can multiplex multiple listing operations across the
   * same connection without ambiguity; may be {@code null} when the peer omits the field.
   */
  private final String requestIdentifier;

  /**
   * Creates a new message instance based on the incoming field set received from the remote peer.
   * The optional <code>Identifier</code> value is preserved and echoed in subsequent response
   * messages so clients can correlate list replies to the originating request.
   *
   * <p>Construction does not perform validation beyond storing the identifier. Any structural or
   * semantic validation is deferred to {@link #run(FCPConnectionHandler, Node)}, allowing the
   * constructor to remain cheap for early parsing stages.
   *
   * @param fs parsed fields from the inbound FCP message; expected to include <code>Identifier
   *     </code> but tolerated when absent. Must not be {@code null}.
   */
  public ListPersistentRequestsMessage(SimpleFieldSet fs) {
    requestIdentifier = fs.get("Identifier");
  }

  /**
   * Returns an empty field set because the outgoing list initiation message does not carry
   * additional fields beyond the request name. Listing responses are emitted separately via queued
   * messages that reuse the identifier supplied at construction time. The returned instance is
   * fresh for each call, allowing callers to add transient keys if protocol extensions ever require
   * them.
   *
   * @return a new, mutable {@link SimpleFieldSet} with no predefined keys, ready for serialization.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Provides the protocol-visible name used when serializing this message onto the FCP connection.
   * The constant is shared across all instances and forms the dispatch key clients use to trigger
   * the listing flow on the remote node. Keeping this name stable is essential for interoperability
   * with existing FCP clients.
   *
   * @return literal string {@value #NAME} that the protocol recognizes.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Base job for enumerating restartable and running persistent requests. The job cooperates with
   * the {@link FCPConnectionOutputHandler} to avoid overfilling the outbound queue and uses
   * abstract hooks for rescheduling and completion so concrete subclasses can provide the desired
   * threading model. Instances track incremental progress counters so repeated invocations continue
   * where the previous cycle stopped.
   *
   * <p>The job processes restartable items first, then emits running requests; both phases advance
   * using incremental progress offsets to avoid re-sending previously delivered entries. When the
   * queue is congested, the job delegates to {@link #reschedule(ClientContext)} rather than busy
   * waiting.
   */
  public abstract static class ListJob implements PersistentJob {

    final PersistentRequestClient client;
    final FCPConnectionOutputHandler outputHandler;

    /**
     * Identifier echoed on every queued listing message so the remote peer can match results to the
     * original request; inherited from the parent message and never mutated.
     */
    protected final String listRequestIdentifier;

    boolean sentRestartJobs;

    /**
     * Constructs a listing job for a specific client namespace and output handler.
     *
     * @param client source of persistent requests to enumerate; must remain valid for the job
     *     lifetime.
     * @param outputHandler connection-scoped handler used to enqueue listing responses while
     *     respecting output backpressure.
     * @param listRequestIdentifier identifier echoed in replies so the client can match correlated
     *     list streams; may be {@code null}.
     */
    ListJob(
        PersistentRequestClient client,
        FCPConnectionOutputHandler outputHandler,
        String listRequestIdentifier) {
      this.client = client;
      this.outputHandler = outputHandler;
      this.listRequestIdentifier = listRequestIdentifier;
    }

    int progressCompleted = 0;
    int progressRunning = 0;

    /**
     * Executes one step of the listing workflow. The job first queues restartable items and then
     * any currently running requests, rescheduling itself when the outbound queue is congested.
     * Completion is delegated to subclasses so they can decide what to do when no running jobs
     * remain. The method is intentionally idempotent with respect to progress counters so repeated
     * invocations continue from the last delivered offset.
     *
     * @param context client execution context that provides scheduling and job-runner utilities.
     * @return always {@code false}; the surrounding scheduler is expected to requeue the task when
     *     needed.
     */
    @Override
    public boolean run(ClientContext context) {
      boolean continueProcessing = queueRestartJobs(context);
      if (continueProcessing) {
        if (noRunning()) {
          complete(context);
        } else {
          queueRunningJobs(context);
        }
      }
      return false;
    }

    private boolean queueRestartJobs(ClientContext context) {
      while (!sentRestartJobs) {
        if (outputHandler.isQueueHalfFull()) {
          reschedule(context);
          return false;
        }
        int progress =
            client.queuePendingMessagesOnConnectionRestart(
                outputHandler, listRequestIdentifier, progressCompleted, 30);
        if (progress <= progressCompleted) {
          sentRestartJobs = true;
        } else {
          progressCompleted = progress;
        }
      }
      return true;
    }

    private void queueRunningJobs(ClientContext context) {
      while (true) {
        if (outputHandler.isQueueHalfFull()) {
          reschedule(context);
          return;
        }
        int progress =
            client.queuePendingMessagesFromRunningRequests(
                outputHandler, listRequestIdentifier, progressRunning, 30);
        if (progress <= progressRunning) {
          complete(context);
          return;
        }
        progressRunning = progress;
      }
    }

    /**
     * Requests that the job be scheduled again at a later time, typically because the connection
     * output queue is congested. Implementations choose the scheduling mechanism appropriate for
     * their threading model.
     *
     * @param context client context that owns the relevant scheduler and timing facilities.
     */
    abstract void reschedule(ClientContext context);

    /**
     * Invoked once all restartable and running requests have been delivered for the associated
     * client scope. Implementations typically use this to chain into the next client namespace or
     * to signal completion to the remote peer. The hook runs synchronously with the final listing
     * step and should therefore complete quickly to avoid stalling the scheduler.
     *
     * @param context client context used to queue any follow-up work.
     */
    abstract void complete(ClientContext context);

    /**
     * Indicates whether the caller should skip enumerating currently running requests. Subclasses
     * override this to short-circuit the second phase when they have already produced the needed
     * output or when running requests are intentionally ignored. The default implementation returns
     * {@code false}, ensuring both phases run for typical list operations.
     *
     * @return {@code true} to bypass running-request enumeration; {@code false} to proceed.
     */
    protected boolean noRunning() {
      return false;
    }
  }

  /**
   * Listing job that runs on the caller thread and uses the ticker for deferred rescheduling. This
   * variant is appropriate for transient reboot clients that do not require persistence across JVM
   * restarts. It favors low overhead and immediate execution, while still honoring output
   * backpressure by deferring work via the ticker when necessary.
   *
   * <p>Consumers typically instantiate this class to enumerate requests that are expected to be
   * dropped on node shutdown, such as reboot-scope downloads. Because it executes synchronously, it
   * should perform minimal work per invocation to avoid blocking the connection handler thread.
   */
  public abstract static class TransientListJob extends ListJob implements Runnable {

    final ClientContext context;

    /**
     * Creates a transient listing job bound to a specific client context. The constructor does not
     * initiate work; callers should invoke {@link #run()} after instantiation to start enumeration.
     *
     * @param client source of requests to enumerate; typically the reboot-scoped client.
     * @param handler output handler used to enqueue messages while avoiding queue overflows.
     * @param context runtime context that supplies the ticker for delayed rescheduling.
     * @param listRequestIdentifier identifier propagated to emitted messages so the requester can
     *     correlate responses across phases.
     */
    TransientListJob(
        PersistentRequestClient client,
        FCPConnectionOutputHandler handler,
        ClientContext context,
        String listRequestIdentifier) {
      super(client, handler, listRequestIdentifier);
      this.context = context;
    }

    @Override
    public void run() {
      super.run(context);
    }

    /**
     * Resubmits the job to the ticker with a short delay when the outbound queue is congested.
     *
     * @param context client context providing the ticker scheduler.
     */
    @Override
    void reschedule(ClientContext context) {
      context.ticker.queueTimedJob(this, 100);
    }
  }

  /**
   * Listing job that persists by enqueueing itself into the {@link ClientContext#jobRunner} with a
   * high scheduling priority. Suitable for forever requests that must survive across process
   * lifetimes and share the persistent job infrastructure. The job honors backpressure via ticker
   * rescheduling but otherwise runs on worker threads managed by the persistent job runner.
   *
   * <p>This variant integrates with the persistence layer; if persistence is disabled, it falls
   * back to immediately signaling completion to keep the protocol consistent even when local
   * storage is unavailable.
   */
  public abstract static class PersistentListJob extends ListJob
      implements PersistentJob, Runnable {

    final ClientContext context;

    /**
     * Creates a persistent listing job wired to the job runner. Invocation does not submit the job;
     * call {@link #run()} to enqueue it. Because the job may outlive the caller thread, callers
     * should ensure the supplied {@link ClientContext} remains valid for the duration of the list
     * operation.
     *
     * @param client persistent client whose queued and running requests will be listed.
     * @param handler output handler used to send listing responses while monitoring queue capacity.
     * @param context client context that owns the persistent job runner and ticker.
     * @param listRequestIdentifier identifier echoed back to the requester for correlation; may be
     *     {@code null}.
     */
    PersistentListJob(
        PersistentRequestClient client,
        FCPConnectionOutputHandler handler,
        ClientContext context,
        String listRequestIdentifier) {
      super(client, handler, listRequestIdentifier);
      this.context = context;
    }

    /**
     * Reschedules the job using the ticker when queue pressure requires deferring additional
     * output.
     *
     * @param context client context that provides the ticker.
     */
    @Override
    void reschedule(ClientContext context) {
      context.ticker.queueTimedJob(this, 100);
    }

    /**
     * Queues the job into the persistent job runner at a high priority. When persistence is
     * disabled, the method falls back to signaling completion immediately so the protocol remains
     * consistent. The caller retains no ownership of the task after submission; all progress is
     * tracked internally via {@link ListJob#progressCompleted} and {@link ListJob#progressRunning}.
     */
    @Override
    public void run() {
      try {
        context.jobRunner.queue(this, NativeThread.PriorityLevel.HIGH_PRIORITY.value - 1);
      } catch (PersistenceDisabledException _) {
        outputHandler.handler.send(new EndListPersistentRequestsMessage(listRequestIdentifier));
      }
    }
  }

  /**
   * Executes the message by spawning listing jobs for reboot, optional global, and forever
   * persistent request clients. Each phase chains into the next, and the final stage sends {@link
   * EndListPersistentRequestsMessage} to mark completion. Backpressure is honored via the job
   * rescheduling logic inside the nested job types.
   *
   * @param handler connection handler that supplies client scopes and output routing.
   * @param node owning node used to access the {@link ClientContext}.
   * @throws MessageInvalidException if the message cannot be processed for this connection.
   */
  @Override
  public void run(final FCPConnectionHandler handler, Node node) throws MessageInvalidException {

    PersistentRequestClient rebootClient = handler.getRebootClient();

    TransientListJob job =
        new TransientListJob(
            rebootClient,
            handler.getOutputHandler(),
            node.services().clientCore().getClientContext(),
            requestIdentifier) {

          @Override
          void complete(ClientContext context) {

            if (handler.getRebootClient().watchGlobal) {
              PersistentRequestClient globalRebootClient =
                  handler.getServer().getGlobalRebootClient();

              TransientListJob job =
                  new TransientListJob(
                      globalRebootClient, outputHandler, context, listRequestIdentifier) {

                    @Override
                    void complete(ClientContext context) {
                      finishComplete(context);
                    }
                  };
              job.run();
            } else {
              finishComplete(context);
            }
          }

          private void finishComplete(ClientContext context) {
            try {
              context.jobRunner.queue(
                  (PersistentJob)
                      context1 -> {
                        PersistentRequestClient foreverClient = handler.getForeverClient();
                        PersistentListJob job1 =
                            new PersistentListJob(
                                foreverClient, outputHandler, context1, listRequestIdentifier) {

                              @Override
                              void complete(ClientContext context1) {
                                if (handler.getRebootClient().watchGlobal) {
                                  PersistentRequestClient globalForeverClient =
                                      handler.getServer().getGlobalForeverClient();
                                  PersistentListJob job1 =
                                      new PersistentListJob(
                                          globalForeverClient,
                                          outputHandler,
                                          context1,
                                          listRequestIdentifier) {

                                        @Override
                                        void complete(ClientContext context1) {
                                          finishFinal();
                                        }
                                      };
                                  job1.run(context1);
                                } else {
                                  finishFinal();
                                }
                              }

                              private void finishFinal() {
                                outputHandler.handler.send(
                                    new EndListPersistentRequestsMessage(listRequestIdentifier));
                              }
                            };
                        job1.run(context1);
                        return false;
                      },
                  NativeThread.PriorityLevel.HIGH_PRIORITY.value - 1);
            } catch (PersistenceDisabledException _) {
              handler.send(new EndListPersistentRequestsMessage(listRequestIdentifier));
            }
          }
        };
    job.run();
  }
}
