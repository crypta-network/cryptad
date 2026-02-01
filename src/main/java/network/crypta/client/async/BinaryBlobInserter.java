package network.crypta.client.async;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.Serial;
import java.util.ArrayList;
import network.crypta.client.FailureCodeTracker;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.SSKBlock;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.RequestClient;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SimpleSendableInsert;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates the insertion of a binary blob that has been pre-encoded as a set of independently
 * insertable blocks. Each block is scheduled using the appropriate {@link ClientRequestScheduler}
 * based on its key type (CHK or SSK). The inserter tracks completion, retries, and error codes
 * across all blocks and reports a single success or failure result to the owning {@link
 * ClientPutter} when all blocks have finished.
 *
 * <p>This class is suited for workloads where the caller already possesses a self-contained,
 * immutable blob in the project-specific binary format (see {@code BinaryBlob}). Typical usage is
 * to construct an instance for a given {@link Bucket} and then call {@link
 * #schedule(ClientContext)} once to queue all block-level inserts. Progress and results are
 * reported back to the parent via callbacks; the parent remains responsible for high-level
 * orchestration and for notifying external clients.
 *
 * <p>Concurrency: block-level inserts run concurrently via their schedulers; this class maintains
 * thread-safe counters and uses synchronization only for small critical sections (e.g., updating
 * counters and completion state). Instances are single-use: once all blocks complete and a final
 * outcome is delivered, the object should not be reused. The class is not intended to be shared
 * across multiple parents.
 *
 * <ul>
 *   <li>Counts consecutive {@code ROUTE_NOT_FOUND} outcomes as success after a configured
 *       threshold.
 *   <li>Enforces a maximum retry limit per block; a fatal error short-circuits the aggregate
 *       result.
 *   <li>Does not support persistence/resume; see {@link #onResume(ClientContext)} for details.
 * </ul>
 *
 * @see ClientPutter
 * @see SimpleSendableInsert
 * @see LowLevelPutException
 */
public class BinaryBlobInserter implements ClientPutState {
  private static final Logger LOG = LoggerFactory.getLogger(BinaryBlobInserter.class);

  final ClientPutter parent;
  final RequestClient clientContext;
  final MySendableInsert[] inserters;
  final FailureCodeTracker errors;
  final int maxRetries;
  final int consecutiveRNFsCountAsSuccess;
  private int completedBlocks;
  private int succeededBlocks;
  private boolean fatal;
  final InsertContext ctx;
  final boolean realTimeFlag;

  BinaryBlobInserter(
      Bucket blob,
      ClientPutter parent,
      RequestClient clientContext,
      boolean tolerant,
      short prioClass,
      InsertContext ctx,
      ClientContext context)
      throws IOException, BinaryBlobFormatException {
    this.ctx = ctx;
    this.maxRetries = ctx.getMaxInsertRetries();
    this.consecutiveRNFsCountAsSuccess = ctx.getConsecutiveRNFsCountAsSuccess();
    this.parent = parent;
    this.clientContext = clientContext;
    this.errors = new FailureCodeTracker(true);
    this.realTimeFlag = clientContext.realTimeFlag();
    DataInputStream dis = new DataInputStream(blob.getInputStream());

    BlockSet blocks = new SimpleBlockSet();

    try {
      BinaryBlob.readBinaryBlob(dis, blocks, tolerant);
    } finally {
      dis.close();
    }

    ArrayList<MySendableInsert> myInserters = new ArrayList<>();
    int x = 0;
    for (Key key : blocks.keys()) {
      KeyBlock block = blocks.get(key);
      MySendableInsert inserter =
          new MySendableInsert(x++, block, prioClass, getScheduler(block, context), clientContext);
      myInserters.add(inserter);
    }

    inserters = myInserters.toArray(new MySendableInsert[0]);
    parent.addMustSucceedBlocks(inserters.length);
    parent.notifyClients(context);
  }

  private ClientRequestScheduler getScheduler(KeyBlock block, ClientContext context) {
    if (block instanceof CHKBlock) return context.getChkInsertScheduler(realTimeFlag);
    else if (block instanceof SSKBlock) return context.getSskInsertScheduler(realTimeFlag);
    else
      throw new IllegalArgumentException("Unknown block type " + block.getClass() + " : " + block);
  }

  /**
   * Cancels all outstanding block inserts and reports a cancelled outcome to the parent.
   *
   * <p>Any block that has already finished will be ignored. In-flight blocks are asked to cancel,
   * and the parent is notified with an {@link InsertException} of mode {@link
   * InsertExceptionMode#CANCELLED}. Cancellation is best-effort; blocks may still surface callbacks
   * during shutdown, but those will be ignored by this inserter once it has cleared the local state
   * for the corresponding block number.
   *
   * @param context execution context carrying schedulers and runtime configuration. Must not be
   *     {@code null}; no state is retained.
   */
  @Override
  public void cancel(ClientContext context) {
    for (MySendableInsert inserter : inserters) {
      if (inserter != null) inserter.cancel(context);
    }
    parent.onFailure(new InsertException(InsertExceptionMode.CANCELLED), this, context);
  }

  /**
   * Returns the owning parent that receives progress and final outcome notifications.
   *
   * @return the non-null parent instance; the caller does not gain ownership and must not mutate
   *     its internal state.
   */
  @Override
  public BaseClientPutter getParent() {
    return parent;
  }

  /**
   * Returns the token used to associate this put operation with the request client.
   *
   * <p>The token is the {@link RequestClient} passed to the constructor and is used by the
   * scheduling layer for resource attribution and request grouping. The value is stable for the
   * lifetime of this inserter.
   *
   * @return an opaque, non-null token representing the request client; callers must treat it as a
   *     read-only association reference.
   */
  @Override
  public Object getToken() {
    return clientContext;
  }

  /**
   * Schedules all block-level inserts created from the source blob.
   *
   * <p>This method enqueues each block on its matching {@link ClientRequestScheduler}. It is safe
   * to call exactly once per instance; repeated invocations are not supported and will at best
   * re-schedule already queued work. Blocks run concurrently subject to the scheduler’s policy.
   * Completion and failure are reported asynchronously via callbacks to the parent.
   *
   * @param context execution context providing schedulers and runtime policy. Must not be {@code
   *     null}. The method does not capture or store the reference beyond scheduling.
   * @throws InsertException if scheduling cannot proceed due to a higher-level insert error or
   *     precondition violation detected by the parent or framework.
   */
  @Override
  public void schedule(ClientContext context) throws InsertException {
    for (MySendableInsert inserter : inserters) {
      inserter.schedule();
    }
  }

  class MySendableInsert extends SimpleSendableInsert {

    @Serial private static final long serialVersionUID = 1L;
    final int blockNum;
    private int consecutiveRNFs;
    private int retries;

    public MySendableInsert(
        int i,
        KeyBlock block,
        short prioClass,
        ClientRequestScheduler scheduler,
        RequestClient client) {
      super(block, prioClass, client, scheduler);
      this.blockNum = i;
    }

    @Override
    public void onSuccess(SendableRequestItem keyNum, ClientKey key, ClientContext context) {
      synchronized (this) {
        if (inserters[blockNum] == null) return;
        inserters[blockNum] = null;
        completedBlocks++;
        succeededBlocks++;
      }
      parent.completedBlock(false, context);
      maybeFinish(context);
    }

    // Note: logic mirrors SingleBlockInserter; consider future refactor.
    @Override
    public void onFailure(
        LowLevelPutException e, SendableRequestItem keyNum, ClientContext context) {
      synchronized (BinaryBlobInserter.this) {
        if (inserters[blockNum] == null) return;
      }
      if (parent.isCancelled()) {
        fail(true, context);
        return;
      }
      switch (e.code) {
        case LowLevelPutException.COLLISION -> fail(false, context);
        case LowLevelPutException.INTERNAL_ERROR -> errors.inc(InsertExceptionMode.INTERNAL_ERROR);
        case LowLevelPutException.REJECTED_OVERLOAD ->
            errors.inc(InsertExceptionMode.REJECTED_OVERLOAD);
        case LowLevelPutException.ROUTE_NOT_FOUND ->
            errors.inc(InsertExceptionMode.ROUTE_NOT_FOUND);
        case LowLevelPutException.ROUTE_REALLY_NOT_FOUND ->
            errors.inc(InsertExceptionMode.ROUTE_REALLY_NOT_FOUND);
        default -> {
          LOG.error("Unknown LowLevelPutException code: {}", e.code);
          errors.inc(InsertExceptionMode.INTERNAL_ERROR);
        }
      }
      if (e.code == LowLevelPutException.ROUTE_NOT_FOUND) {
        consecutiveRNFs++;
        if (LOG.isDebugEnabled())
          LOG.debug("Consecutive RNFs: {} / {}", consecutiveRNFs, consecutiveRNFsCountAsSuccess);
        if (consecutiveRNFs == consecutiveRNFsCountAsSuccess) {
          if (LOG.isDebugEnabled())
            LOG.debug("Consecutive RNFs: {} - counting as success", consecutiveRNFs);
          onSuccess(keyNum, null, context);
          return;
        }
      } else consecutiveRNFs = 0;
      if (LOG.isDebugEnabled()) LOG.debug("Failed: {}", e.toString());
      retries++;
      if ((retries > maxRetries) && (maxRetries != -1)) {
        fail(false, context);
        return;
      }
      this.clearWakeupTime(context);
      // Retry *this block*
      this.schedule();
    }

    private void fail(boolean fatal, ClientContext context) {
      synchronized (BinaryBlobInserter.this) {
        if (inserters[blockNum] == null) return;
        inserters[blockNum] = null;
        completedBlocks++;
        if (fatal) BinaryBlobInserter.this.fatal = true;
      }
      if (fatal) parent.fatallyFailedBlock(context);
      else parent.failedBlock(context);
      maybeFinish(context);
    }
  }

  /**
   * Checks whether all blocks have completed and, if so, delivers the aggregate result.
   *
   * <p>When the final block finishes, the method decides between overall success, fatal failure, or
   * too many retries based on internal counters. Success requires that every block succeed, or that
   * the configured consecutive route-not-found threshold be met where applicable. The method is
   * idempotent within the completion window and ignores subsequent calls once an outcome has been
   * reported.
   *
   * @param context execution context forwarded to the parent callback. The reference is not
   *     retained after the call returns.
   */
  public void maybeFinish(ClientContext context) {
    boolean success;
    boolean wasFatal;
    synchronized (this) {
      if (completedBlocks != inserters.length) return;
      success = completedBlocks == succeededBlocks;
      wasFatal = fatal;
    }
    if (success) {
      parent.onSuccess(this, context);
    } else if (wasFatal)
      parent.onFailure(
          new InsertException(InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS, errors, null),
          this,
          context);
    else
      parent.onFailure(
          new InsertException(InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS, errors, null),
          this,
          context);
  }

  /**
   * Resume is unsupported for this inserter.
   *
   * <p>Binary blob insertion is designed as an in-memory, single-lifecycle operation. The class
   * does not persist intermediate state for resumption across process restarts or serializer
   * boundaries. Callers should restart the insertion from the beginning by creating a new instance
   * if a pause/resume cycle is desired.
   *
   * @param context execution context required by the interface; ignored by this implementation.
   * @throws InsertException always thrown to signal that resume is not supported by this type.
   */
  @Override
  public void onResume(ClientContext context) throws InsertException {
    // Persistence is not supported for BinaryBlobInserter.
    throw new InsertException(
        InsertExceptionMode.INTERNAL_ERROR, "Persistence not supported yet", null);
  }

  /**
   * Notifies the inserter of a system shutdown. This implementation performs no action.
   *
   * <p>Callers may use this hook to align with framework lifecycles. Any in-flight work is managed
   * by the schedulers; blocks that complete after shutdown will be ignored once the parent has
   * transitioned out of the active state.
   *
   * @param context execution context supplied by the framework; not used.
   */
  @Override
  public void onShutdown(ClientContext context) {
    // Ignore.
  }
}
