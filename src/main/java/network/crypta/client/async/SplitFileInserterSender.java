package network.crypta.client.async;

import java.io.IOException;
import java.io.Serial;
import network.crypta.client.InsertException;
import network.crypta.client.async.SplitFileInserterSegmentStorage.BlockInsert;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientKey;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestScheduler;
import network.crypta.node.SendableInsert;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestSender;
import network.crypta.store.KeyCollisionException;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Drives low‑level CHK block inserts for a split‑file upload.
 *
 * <p>This request adapter bridges the high‑level {@link SplitFileInserter} orchestration with the
 * low‑level put path executed by the node. It selects the next block to insert from {@link
 * SplitFileInserterStorage}, encodes the block to obtain a {@code ClientCHK}/{@code CHKBlock}, and
 * then submits the put to the appropriate scheduler via {@link #getSender(ClientContext)}.
 *
 * <p>Persistence model: instances of this class are <strong>not</strong> serialized. For persistent
 * inserts the parent {@link SplitFileInserter} reconstructs both its {@link
 * SplitFileInserterStorage} and a fresh {@code SplitFileInserterSender} during {@link
 * SplitFileInserter#onResume(ClientContext)}. Any transient collaborators (for example, the
 * internal sender object) are therefore safe to keep non‑serializable.
 *
 * <p>Concurrency: selection and callbacks are invoked by the client request schedulers. The sender
 * treats disk failures and unexpected throwables as terminal for the affected block: errors are
 * converted to an {@link network.crypta.client.InsertException} and reported back to storage so the
 * insert can either retry or fail cleanly. Calls that modify on‑disk state are queued on the
 * correct {@link ClientContext#getJobRunner(boolean) persistence‑aware job runner}.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> choose a block, encode it, submit a put (local or
 *       remote), and translate success/failure into storage updates and client callbacks.
 *   <li><strong>Notable behaviors:</strong> local‑only mode stores to the node’s store directly;
 *       remote mode uses {@code realPut}. All unexpected throwables during sending are caught and
 *       mapped to an internal‑error failure so the scheduler state remains consistent.
 * </ul>
 *
 * @see SplitFileInserter
 * @see SplitFileInserterStorage
 */
public class SplitFileInserterSender extends SendableInsert {
  private static final Logger LOG = LoggerFactory.getLogger(SplitFileInserterSender.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * The owning high‑level inserter that coordinates metadata, progress, and completion reporting.
   * The reference is stable for the lifetime of the sender and is never {@code null}.
   */
  final SplitFileInserter parent;

  /**
   * Storage and per‑segment state for the split‑file insert. This collaborator persists its state
   * to a random‑access file; the field itself is transient because the sender is reconstructed on
   * resume.
   */
  final transient SplitFileInserterStorage storage;

  /**
   * Creates a sender bound to an existing split‑file inserter and its storage.
   *
   * <p>The persistence and real‑time flags are inherited from the parent, so this sender integrates
   * with the appropriate schedulers and job runners.
   *
   * @param parent owning inserter that provides context, priority, and client identity; must not be
   *     {@code null}
   * @param storage storage helper that selects/encodes blocks and persists progress; must not be
   *     {@code null}
   */
  public SplitFileInserterSender(SplitFileInserter parent, SplitFileInserterStorage storage) {
    super(
        parent.persistent,
        parent
            .realTime); // Persistence should be from the parent so that e.g., callbacks get run on
    // the
    // right jobRunner.
    this.parent = parent;
    this.storage = storage;
  }

  /**
   * Records a successful low‑level insert for the chosen block and updates segment state.
   *
   * <p>The storage layer persists the key for the inserted block and advances per‑segment
   * bookkeeping. Callers do not need to retry or reschedule the same block; selection will move on
   * to other pending items automatically.
   *
   * @param keyNum scheduler token identifying the block within a segment; expected to be a {@link
   *     SplitFileInserterSegmentStorage.BlockInsert}
   * @param key client key produced for the block; ownership is not transferred
   * @param context execution context used for later callbacks; not {@code null}
   */
  @Override
  public void onSuccess(SendableRequestItem keyNum, ClientKey key, ClientContext context) {
    BlockInsert block = (BlockInsert) keyNum;
    block.segment.onInsertedBlock(block.blockNumber, (ClientCHK) key);
  }

  /**
   * Converts a low‑level put failure into a client‑level {@link InsertException} and updates state.
   *
   * <p>When the scheduler has no block token ({@code keyNum == null}), the failure is applied at
   * the storage level so the entire insert can terminate. Otherwise, the containing segment is
   * notified with the converted exception and will decide whether to retry, count toward failure
   * thresholds, or fail the insert.
   *
   * @param e low‑level failure cause from the node put path; never {@code null}
   * @param keyNum block token supplied by the scheduler, or {@code null} when the failure occurred
   *     outside the context of a specific block
   * @param context execution context available for any follow‑up callbacks; not {@code null}
   */
  @Override
  public void onFailure(LowLevelPutException e, SendableRequestItem keyNum, ClientContext context) {
    InsertException e1 = InsertException.constructFrom(e);
    if (keyNum == null) {
      storage.fail(e1);
    } else {
      BlockInsert block = (BlockInsert) keyNum;
      block.segment.onFailure(block.blockNumber, e1);
    }
  }

  @Override
  public boolean canWriteClientCache() {
    return parent.ctx.isCanWriteClientCache();
  }

  @Override
  public boolean localRequestOnly() {
    return parent.ctx.isLocalRequestOnly();
  }

  @Override
  public boolean forkOnCacheable() {
    return parent.ctx.isForkOnCacheable();
  }

  /**
   * Reports the freshly encoded key for a block back to the segment storage.
   *
   * <p>This callback runs on the appropriate persistence‑aware job runner. If the insert has
   * already finished, the method returns immediately. I/O failures are considered disk errors and
   * delegated to {@link SplitFileInserterStorage#failOnDiskError(IOException)} which will terminate
   * or retry, according to policy.
   *
   * @param token block token identifying the segment and block number; expected to be a {@link
   *     SplitFileInserterSegmentStorage.BlockInsert}
   * @param key encoded {@link ClientCHK} for the block; not {@code null}
   * @param context execution context providing the job runner; not {@code null}
   */
  @Override
  public void onEncode(SendableRequestItem token, ClientKey key, ClientContext context) {
    BlockInsert block = (BlockInsert) token;
    // Should already be set. This is a sanity check.
    try {
      if (storage.hasFinished()) return;
      block.segment.setKey(block.blockNumber, (ClientCHK) key);
    } catch (IOException e) {
      if (storage.hasFinished()) return; // Race condition possible as this is a callback
      storage.failOnDiskError(e);
    }
  }

  @Override
  public boolean isEmpty() {
    return isCancelled();
  }

  @Override
  protected void innerOnResume(ClientContext context)
      throws InsertException, ResumeFailedException {
    throw new UnsupportedOperationException(); // Not persisted.
  }

  @Override
  public short getPriorityClass() {
    return parent.parent.getPriorityClass();
  }

  /**
   * Selects the next block to insert, or returns {@code null} when none are eligible.
   *
   * <p>Selection is delegated to the per‑segment chooser in {@link SplitFileInserterStorage}. The
   * returned token is stable for the duration of the attempted sending; the scheduler will not
   * select the same block concurrently for the same request.
   *
   * @param keys view of keys currently being inserted locally to avoid duplication
   * @param context execution context supplied by the scheduler; not used for selection
   * @return a {@link SplitFileInserterSegmentStorage.BlockInsert} when work is ready; otherwise
   *     {@code null}
   */
  @Override
  public SendableRequestItem chooseKey(KeysFetchingLocally keys, ClientContext context) {
    return storage.chooseBlock();
  }

  @Override
  public long countAllKeys(ClientContext context) {
    return storage.countAllKeys();
  }

  @Override
  public long countSendableKeys(ClientContext context) {
    return storage.countSendableKeys();
  }

  /**
   * Non‑persistent sender implementation used by the scheduler to execute a chosen block.
   *
   * <p>The implementation encodes the block, posts the {@link #onEncode(SendableRequestItem,
   * ClientKey, ClientContext)} callback on the correct job runner, and then performs a local store
   * or remote {@code realPut}. All exceptions (including {@link Throwable}) are converted to a
   * failure and reported to the scheduler so the request life‑cycle remains consistent.
   */
  class MySendableRequestSender implements SendableRequestSender {

    @Override
    @SuppressWarnings("java:S1181")
    public boolean send(
        NodeClientCore node,
        final RequestScheduler sched,
        ClientContext context,
        final ChosenBlock request) {
      final BlockInsert token = (BlockInsert) request.token;
      boolean initiated = true;
      try {
        ClientCHKBlock clientBlock = token.segment.encodeBlock(token.blockNumber);
        CHKBlock block = clientBlock.getBlock();
        final ClientCHK key = clientBlock.getClientKey();
        context
            .getJobRunner(request.isPersistent())
            .queueNormalOrDrop(
                context2 -> {
                  onEncode(token, key, context2);
                  return false;
                });
        if (request.localRequestOnly) {
          storeLocally(node, block, request.canWriteClientCache);
        } else {
          node.getTransfers()
              .realPut(
                  block,
                  request.canWriteClientCache,
                  request.forkOnCacheable,
                  Node.PREFER_INSERT_DEFAULT,
                  Node.IGNORE_LOW_BACKOFF_DEFAULT,
                  request.realTimeFlag,
                  request.getExternalRequestIdentifier());
        }
        request.onInsertSuccess(key, context);
      } catch (final LowLevelPutException e) {
        request.onFailure(e, context);
      } catch (final IOException e) {
        context
            .getJobRunner(request.isPersistent())
            .queueNormalOrDrop(
                context1 -> {
                  try {
                    storage.failOnDiskError(e);
                  } finally {
                    // Must terminate the request anyway.
                    request.onFailure(
                        new LowLevelPutException(
                            LowLevelPutException.INTERNAL_ERROR, "Disk error", e),
                        context1);
                  }
                  return true;
                });
      } catch (Throwable t) {
        LOG.error("Failed to send insert", t);
        // We still need to terminate the insert.
        request.onFailure(
            new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, "Failed: " + t, t),
            context);
      }
      return initiated;
    }

    private void storeLocally(NodeClientCore node, CHKBlock block, boolean canWriteClientCache)
        throws LowLevelPutException {
      try {
        node.getNode().storage().store(block, false, canWriteClientCache, true, false);
      } catch (KeyCollisionException _) {
        throw new LowLevelPutException(LowLevelPutException.COLLISION);
      }
    }

    @Override
    public boolean sendIsBlocking() {
      return true;
    }
  }

  final transient MySendableRequestSender sender = new MySendableRequestSender();

  /**
   * Returns the non‑persistent {@link SendableRequestSender} used to execute chosen blocks.
   *
   * <p>Callers may reuse the returned sender across multiple selections. It always reports success
   * or failure back to this request, converting unexpected throwables to an internal‑error failure.
   *
   * @param context execution context provided by the scheduler; not {@code null}
   * @return a sender that performs the blocking sending for this request instance
   */
  @Override
  public SendableRequestSender getSender(ClientContext context) {
    return sender;
  }

  /**
   * Indicates whether the request has finished or been canceled and should no longer run.
   *
   * @return {@code true} when the underlying storage reports that the insert has finished
   */
  @Override
  public boolean isCancelled() {
    return storage.hasFinished();
  }

  @Override
  public RequestClient getClient() {
    return parent.parent.getClient();
  }

  @Override
  public ClientRequester getClientRequest() {
    return parent.parent;
  }

  @Override
  public boolean isSSK() {
    return false;
  }

  /**
   * Registers this sender with the CHK insert scheduler when not already registered.
   *
   * <p>The registration uses the parent’s real‑time flag and persistence mode. When already
   * registered (for example, during priority changes), the method returns without side effects.
   *
   * @param context execution context that provides the CHK insert scheduler; must not be {@code
   *     null}
   */
  public void schedule(ClientContext context) {
    if (getParentGrabArray() != null) return; // If change priority will unregister first.
    context.getChkInsertScheduler(parent.realTime).registerInsert(this, persistent);
  }

  /**
   * Delegates wake‑up calculation to the storage layer so scheduling aligns with encoding progress.
   *
   * @param context execution context used for scheduler coordination
   * @param now current time in milliseconds since the epoch; may be ignored by the implementation
   * @return a non‑negative time for next wake‑up, {@code 0} for immediate, or {@code -1} if idle
   */
  @Override
  public long getWakeupTime(ClientContext context, long now) {
    return storage.getWakeupTime(context, now);
  }
}
