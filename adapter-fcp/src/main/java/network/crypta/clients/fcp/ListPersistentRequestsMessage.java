package network.crypta.clients.fcp;

import network.crypta.runtime.spi.RequestQueuePort;
import network.crypta.runtime.spi.RequestQueuePriority;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.support.SimpleFieldSet;

/**
 * Handles the <code>ListPersistentRequests</code> FCP message by streaming identifiers of
 * persistent client requests back to the connected peer.
 *
 * <p>The message traverses the reboot (short-lived) and forever (long-lived) request stores,
 * optionally including global watchers, and signals completion once all restartable and
 * still-running requests have been enumerated. Backpressure is honored by rescheduling work through
 * the runtime request-queue SPI when the connection output queue is half full.
 */
public class ListPersistentRequestsMessage extends FCPMessage {

  static final String NAME = "ListPersistentRequests";

  /**
   * Optional identifier supplied by the requester and echoed in every generated listing message.
   * Acts as a correlation token, so clients can multiplex multiple listing operations across the
   * same connection without ambiguity; may be {@code null} when the peer omits the field.
   */
  private final String requestIdentifier;

  /**
   * Creates a new message instance based on the incoming field set received from the remote peer.
   *
   * @param fs parsed fields from the inbound FCP message; the {@code Identifier} field is optional
   */
  public ListPersistentRequestsMessage(SimpleFieldSet fs) {
    requestIdentifier = fs.get("Identifier");
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Base job for listing restartable and running persistent requests.
   *
   * <p>The job cooperates with the {@link FCPConnectionOutputHandler} to avoid overfilling the
   * outbound queue and uses abstract hooks for rescheduling and completion so concrete subclasses
   * can provide the desired threading model. Instances track incremental progress counters so
   * repeated invocations continue where the previous cycle stopped.
   */
  public abstract static class ListJob {

    final PersistentRequestClient client;
    final FCPConnectionOutputHandler outputHandler;

    /**
     * Identifier echoed on every queued listing message so the remote peer can match results to the
     * original request; inherited from the parent message and never mutated.
     */
    protected final String listRequestIdentifier;

    boolean sentRestartJobs;
    int progressCompleted;
    int progressRunning;

    /**
     * Constructs a listing job for a specific client namespace and output handler.
     *
     * @param client source of persistent requests to enumerate; must remain valid for the job
     *     lifetime
     * @param outputHandler connection-scoped handler used to enqueue listing responses while
     *     respecting output backpressure
     * @param listRequestIdentifier identifier echoed in replies so the client can match correlated
     *     list streams; may be {@code null}
     */
    ListJob(
        PersistentRequestClient client,
        FCPConnectionOutputHandler outputHandler,
        String listRequestIdentifier) {
      this.client = client;
      this.outputHandler = outputHandler;
      this.listRequestIdentifier = listRequestIdentifier;
    }

    /**
     * Executes one step of the listing workflow. The job first queues restartable items and then
     * any currently running requests, rescheduling itself when the outbound queue is congested.
     * Completion is delegated to subclasses so they can decide what to do when no running jobs
     * remain.
     *
     * @return always {@code false}; callers requeue explicitly through {@link #reschedule()}
     */
    final boolean execute() {
      boolean continueProcessing = queueRestartJobs();
      if (continueProcessing) {
        if (noRunning()) {
          complete();
        } else {
          queueRunningJobs();
        }
      }
      return false;
    }

    private boolean queueRestartJobs() {
      while (!sentRestartJobs) {
        if (outputHandler.isQueueHalfFull()) {
          reschedule();
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

    private void queueRunningJobs() {
      while (true) {
        if (outputHandler.isQueueHalfFull()) {
          reschedule();
          return;
        }
        int progress =
            client.queuePendingMessagesFromRunningRequests(
                outputHandler, listRequestIdentifier, progressRunning, 30);
        if (progress <= progressRunning) {
          complete();
          return;
        }
        progressRunning = progress;
      }
    }

    /**
     * Requests that the job be scheduled again at a later time, typically because the connection
     * output queue is congested.
     */
    abstract void reschedule();

    /**
     * Invoked once all restartable and running requests have been delivered for the associated
     * client scope.
     */
    abstract void complete();

    /**
     * Indicates whether the caller should skip listing currently running requests.
     *
     * @return {@code true} to bypass running-request enumeration; {@code false} to proceed
     */
    protected boolean noRunning() {
      return false;
    }
  }

  /**
   * The listing job that runs on the caller thread and uses the runtime queue port for deferred
   * rescheduling.
   */
  public abstract static class TransientListJob extends ListJob implements Runnable {
    private static final long RESCHEDULE_DELAY_MILLIS = 100L;

    final RequestQueuePort requestQueuePort;

    /**
     * Creates a transient listing job.
     *
     * @param client source of requests to enumerate; typically the reboot-scoped client
     * @param handler output handler used to enqueue messages while avoiding queue overflows
     * @param requestQueuePort runtime queue port that supplies delayed rescheduling
     * @param listRequestIdentifier identifier propagated to emitted messages so the requester can
     *     correlate responses across phases
     */
    TransientListJob(
        PersistentRequestClient client,
        FCPConnectionOutputHandler handler,
        RequestQueuePort requestQueuePort,
        String listRequestIdentifier) {
      super(client, handler, listRequestIdentifier);
      this.requestQueuePort = requestQueuePort;
    }

    @Override
    public void run() {
      execute();
    }

    @Override
    void reschedule() {
      requestQueuePort.scheduleLater(this, RESCHEDULE_DELAY_MILLIS);
    }
  }

  /**
   * The listing job that persists by enqueueing itself through the runtime request-queue SPI with
   * the legacy listing priority.
   */
  public abstract static class PersistentListJob extends ListJob implements Runnable {
    private static final long RESCHEDULE_DELAY_MILLIS = 100L;

    final RequestQueuePort requestQueuePort;
    final Runnable queueUnavailableAction;

    /**
     * Creates a persistent listing job.
     *
     * @param client persistent client whose queued and running requests will be listed
     * @param handler output handler used to send listing responses while monitoring queue capacity
     * @param requestQueuePort runtime queue port that owns persistent job submission and delayed
     *     rescheduling
     * @param listRequestIdentifier identifier echoed back to the requester for correlation; may be
     *     {@code null}
     * @param queueUnavailableAction fallback invoked when persistent submission becomes unavailable
     */
    PersistentListJob(
        PersistentRequestClient client,
        FCPConnectionOutputHandler handler,
        RequestQueuePort requestQueuePort,
        String listRequestIdentifier,
        Runnable queueUnavailableAction) {
      super(client, handler, listRequestIdentifier);
      this.requestQueuePort = requestQueuePort;
      this.queueUnavailableAction = queueUnavailableAction;
    }

    @Override
    void reschedule() {
      requestQueuePort.scheduleLater(this, RESCHEDULE_DELAY_MILLIS);
    }

    @Override
    public void run() {
      try {
        requestQueuePort.submitPersistentJob(this::execute, RequestQueuePriority.LISTING);
      } catch (RequestQueueUnavailableException _) {
        queueUnavailableAction.run();
      }
    }
  }

  @Override
  public void run(final FCPConnectionHandler handler) throws MessageInvalidException {
    RequestQueuePort requestQueuePort = handler.getServer().runtime().requestQueue();
    FCPConnectionOutputHandler outputHandler = handler.getOutputHandler();
    Runnable endListing =
        () -> handler.send(new EndListPersistentRequestsMessage(requestIdentifier));

    PersistentRequestClient rebootClient = handler.getRebootClient();

    TransientListJob job =
        new TransientListJob(rebootClient, outputHandler, requestQueuePort, requestIdentifier) {

          @Override
          void complete() {
            if (handler.getRebootClient().watchGlobal) {
              PersistentRequestClient globalRebootClient =
                  handler.getServer().getGlobalRebootClient();
              TransientListJob job =
                  new TransientListJob(
                      globalRebootClient, outputHandler, requestQueuePort, listRequestIdentifier) {

                    @Override
                    void complete() {
                      finishPersistentPhase();
                    }
                  };
              job.run();
            } else {
              finishPersistentPhase();
            }
          }

          private void finishPersistentPhase() {
            PersistentRequestClient foreverClient = handler.getForeverClient();
            PersistentListJob job1 =
                new PersistentListJob(
                    foreverClient,
                    outputHandler,
                    requestQueuePort,
                    listRequestIdentifier,
                    endListing) {

                  @Override
                  void complete() {
                    if (handler.getRebootClient().watchGlobal) {
                      PersistentRequestClient globalForeverClient =
                          handler.getServer().getGlobalForeverClient();
                      PersistentListJob job1 =
                          new PersistentListJob(
                              globalForeverClient,
                              outputHandler,
                              requestQueuePort,
                              listRequestIdentifier,
                              endListing) {

                            @Override
                            void complete() {
                              endListing.run();
                            }
                          };
                      job1.execute();
                    } else {
                      endListing.run();
                    }
                  }
                };
            job1.run();
          }
        };
    job.run();
  }
}
