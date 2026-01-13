package network.crypta.node;

import network.crypta.crypt.CryptFormatException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import network.crypta.node.subsystem.NodeRoutingSubsystem;
import network.crypta.store.KeyCollisionException;
import network.crypta.support.ShortBuffer;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Processes a remote SSK insert from a peer.
 *
 * <p>This handler coordinates the reception of SSK insert parts (headers, data, and optional public
 * key), validates and assembles an {@link SSKBlock}, optionally forwards the insert via {@link
 * SSKInsertSender}, and replies to the originating peer with the appropriate protocol message. When
 * permitted, it commits the block to the datastore.
 *
 * <p>Concurrency and threading: - Implements {@link PrioRunnable}; {@link #run()} performs network
 * I/O and may block while waiting for messages. - Tracks traffic using {@link ByteCounter}. Calls
 * to byte counters may occur from different threads; internal counters are synchronized. - Uses a
 * final local reference to the {@code SSKInsertSender} for synchronization to avoid locking on a
 * mutable field.
 *
 * <p>Side effects: - Sends protocol messages to {@code source} and may store data in the node
 * datastore depending on status and configuration flags.
 */
public class SSKInsertHandler implements PrioRunnable, ByteCounter {
  private static final Logger LOG = LoggerFactory.getLogger(SSKInsertHandler.class);
  private static final String MSG_CONN_CLOSED = "Connection to source closed";
  private static final String MSG_LOST_CONN_UID = "Lost connection to source on {}";
  private static final String MSG_SEND_TIMEOUT_TO = "Send timeout for {} to {}";

  static final int DATA_INSERT_TIMEOUT = 30000;

  final Node node;
  final long uid;
  final PeerNode source;
  final NodeSSK key;
  final long startTime;
  private SSKBlock block;
  private DSAPublicKey pubKey;
  private final short htl;
  private SSKInsertSender sender;
  private byte[] data;
  private byte[] headers;
  private boolean canCommit;
  final InsertTag tag;
  private final boolean canWriteDatastore;
  private final boolean forkOnCacheable;
  private final boolean preferInsert;
  private final boolean ignoreLowBackoff;
  private final boolean realTimeFlag;

  private boolean collided = false;

  SSKInsertHandler(
      NodeSSK key,
      byte[] data,
      byte[] headers,
      short htl,
      InsertHandlerContext context,
      boolean canWriteDatastore) {
    this.node = context.node();
    this.uid = context.uid();
    this.source = context.source();
    this.startTime = context.startTime();
    this.key = key;
    this.htl = htl;
    this.data = data;
    this.headers = headers;
    this.tag = context.tag();
    this.canWriteDatastore = canWriteDatastore;
    byte[] pubKeyHash = key.getPubKeyHash();
    pubKey = node.storage().getPubKey().getKey(pubKeyHash, false, false, null);
    canCommit = false;

    InsertRoutingOptions options = context.routingOptions();
    this.forkOnCacheable = options.forkOnCacheable();
    this.preferInsert = options.preferInsert();
    this.ignoreLowBackoff = options.ignoreLowBackoff();
    this.realTimeFlag = context.realTimeFlag();
  }

  @Override
  public String toString() {
    return super.toString() + " for " + uid;
  }

  /**
   * Executes the insert flow.
   *
   * <p>Behavior: - Acknowledges the insert, receives remaining parts (headers, data, public key),
   * assembles and verifies the block, and if needed, forwards the insert. - Responds to the peer
   * with success, route-not-found, or overload messages as dictated by the sender status. - Always
   * unlocks the associated {@link InsertTag} on exit.
   *
   * <p>This method catches all throwables to prevent thread termination and logs any unexpected
   * failure.
   */
  @Override
  @SuppressWarnings("java:S1181")
  public void run() {
    try {
      realRun();
    } catch (Throwable t) {
      LOG.error("Unhandled exception: {}", t, t);
    } finally {
      if (LOG.isDebugEnabled()) LOG.debug("Exit SSKInsertHandler.run for uid={}", uid);
      tag.unlockHandler();
    }
  }

  private void realRun() {
    if (!sendAccepted()) return;
    if (!receiveRequiredParts()) return;
    if (!assembleBlock()) return;
    if (!handleStoredBlock()) return;
    if (LOG.isDebugEnabled()) LOG.debug("Assembled SSK block (key={}, uid={})", key, uid);
    if (htl > 0) createSender();
    processSenderResults();
  }

  private boolean sendAccepted() {
    Message accepted = DMT.createFNPSSKAccepted(uid, pubKey == null);
    try {
      source.transport().sendAsync(accepted, null, this);
      return true;
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug(MSG_CONN_CLOSED);
      return false;
    }
  }

  private boolean receiveRequiredParts() {
    while ((headers == null) || (data == null) || (pubKey == null)) {
      Message msg;
      try {
        msg = node.network().usm().waitFor(buildWaitFilter(), this);
      } catch (DisconnectedException _) {
        if (LOG.isDebugEnabled()) LOG.debug(MSG_LOST_CONN_UID, uid);
        return false;
      }
      if (!processIncomingMessage(msg)) return false;
    }
    return true;
  }

  private MessageFilter buildWaitFilter() {
    MessageFilter mf =
        MessageFilter.create()
            .setType(DMT.FNPDataInsertRejected)
            .setField(DMT.UID, uid)
            .setSource(source)
            .setTimeout(DATA_INSERT_TIMEOUT);
    if (headers == null) {
      MessageFilter m =
          MessageFilter.create()
              .setType(DMT.FNPSSKInsertRequestHeaders)
              .setField(DMT.UID, uid)
              .setSource(source)
              .setTimeout(DATA_INSERT_TIMEOUT);
      mf = m.or(mf);
    }
    if (data == null) {
      MessageFilter m =
          MessageFilter.create()
              .setType(DMT.FNPSSKInsertRequestData)
              .setField(DMT.UID, uid)
              .setSource(source)
              .setTimeout(DATA_INSERT_TIMEOUT);
      mf = m.or(mf);
    }
    if (pubKey == null) {
      MessageFilter m =
          MessageFilter.create()
              .setType(DMT.FNPSSKPubKey)
              .setField(DMT.UID, uid)
              .setSource(source)
              .setTimeout(DATA_INSERT_TIMEOUT);
      mf = m.or(mf);
    }
    return mf;
  }

  private boolean processIncomingMessage(Message msg) {
    if (msg == null) {
      LOG.info(
          "Did not receive all parts (data={} headers={} pk={}) for {}",
          data == null ? "null" : "ok",
          headers == null ? "null" : "ok",
          pubKey,
          uid);

      Message failed =
          DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_RECEIVE_FAILED);
      try {
        source.transport().sendSync(failed, this, realTimeFlag);
      } catch (NotConnectedException | SyncSendWaitedTooLongException _) {
        // Ignore
      }
      return false;
    }
    if (msg.getSpec() == DMT.FNPSSKInsertRequestHeaders) {
      headers = ((ShortBuffer) msg.getObject(DMT.BLOCK_HEADERS)).getData();
      return true;
    }
    if (msg.getSpec() == DMT.FNPSSKInsertRequestData) {
      data = ((ShortBuffer) msg.getObject(DMT.DATA)).getData();
      return true;
    }
    if (msg.getSpec() == DMT.FNPSSKPubKey) {
      return handlePubKeyMessage(msg);
    }
    if (msg.getSpec() == DMT.FNPDataInsertRejected) {
      try {
        source
            .transport()
            .sendAsync(
                DMT.createFNPDataInsertRejected(uid, msg.getShort(DMT.DATA_INSERT_REJECTED_REASON)),
                null,
                this);
      } catch (NotConnectedException _) {
        // Ignore
      }
      return false;
    }
    LOG.error("Unexpected message {} (handler={})", msg, this);
    return true;
  }

  private boolean handlePubKeyMessage(Message msg) {
    if (!createPubKeyFromMessage(msg)) return false;
    return ackPubKey();
  }

  private boolean createPubKeyFromMessage(Message msg) {
    byte[] pubkeyAsBytes = ((ShortBuffer) msg.getObject(DMT.PUBKEY_AS_BYTES)).getData();
    try {
      pubKey = DSAPublicKey.create(pubkeyAsBytes);
      if (LOG.isDebugEnabled()) LOG.debug("Receive pubkey for {}: {}", uid, pubKey);
      return true;
    } catch (CryptFormatException _) {
      LOG.error("Invalid pubkey from {} for {}", source, uid);
      Message rej = DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_SSK_ERROR);
      try {
        source.transport().sendSync(rej, this, realTimeFlag);
      } catch (NotConnectedException | SyncSendWaitedTooLongException _) {
        // Ignore
      }
      return false;
    }
  }

  private boolean ackPubKey() {
    try {
      sendPubKeyAccepted();
      return true;
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug(MSG_LOST_CONN_UID, uid);
      return false;
    }
  }

  private boolean assembleBlock() {
    try {
      key.setPubKey(pubKey);
      block = new SSKBlock(data, headers, key, false);
      return true;
    } catch (SSKVerifyException e1) {
      LOG.error("Invalid SSK block from {}", source, e1);
      Message msg = DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_SSK_ERROR);
      try {
        source.transport().sendSync(msg, this, realTimeFlag);
      } catch (NotConnectedException | SyncSendWaitedTooLongException _) {
        // Ignore
      }
      return false;
    }
  }

  private boolean handleStoredBlock() {
    SSKBlock storedBlock =
        node.storage().fetch(key, false, false, false, canWriteDatastore, false, null);
    if ((storedBlock != null) && !storedBlock.equals(block)) {
      try {
        RequestHandler.sendSSK(
            storedBlock.getRawHeaders(), storedBlock.getRawData(), source, uid, this, realTimeFlag);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled()) LOG.debug(MSG_LOST_CONN_UID, uid);
        // Preserve historical behavior: abort the handler when the source disconnects while
        // resending an existing stored block back to the originator.
        return false;
      }
      block = storedBlock;
    }
    return true;
  }

  private void createSender() {
    sender =
        node.routing()
            .makeInsertSender(
                block,
                htl,
                uid,
                tag,
                source,
                NodeRoutingSubsystem.SskInsertOptions.of()
                    .withFromStore(false)
                    .withCanWriteClientCache(false)
                    .withCanWriteDatastore(canWriteDatastore)
                    .withForkOnCacheable(forkOnCacheable)
                    .withPreferInsert(preferInsert)
                    .withIgnoreLowBackoff(ignoreLowBackoff)
                    .withRealTimeFlag(realTimeFlag));
  }

  private void processSenderResults() {
    boolean forwardedOverload = false;
    final SSKInsertSender senderRef = sender;
    while (true) {
      awaitStatusChange(senderRef);
      if (!forwardedOverload) forwardedOverload = forwardRejectedOverloadIfAny(senderRef);
      if (senderRef.hasRecentlyCollided()) handleRecentCollision(senderRef);
      int status = senderRef.getStatus();
      if (status == SSKInsertSender.NOT_FINISHED) continue;
      handleTerminalStatuses(senderRef, status);
      return;
    }
  }

  private void awaitStatusChange(SSKInsertSender senderRef) {
    // Delegate waiting to the sender's intrinsic monitor to avoid synchronizing on parameters.
    senderRef.waitIfNotFinished(5000);
  }

  private boolean forwardRejectedOverloadIfAny(SSKInsertSender senderRef) {
    if (!senderRef.receivedRejectedOverload()) return false;
    Message m = DMT.createFNPRejectedOverload(uid, false);
    try {
      source.transport().sendAsync(m, null, this);
      return true;
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug(MSG_CONN_CLOSED);
      return true; // treat as forwarded to break loop on connection loss
    }
  }

  private void handleRecentCollision(SSKInsertSender senderRef) {
    data = senderRef.getData();
    headers = senderRef.getHeaders();
    collided = true;
    try {
      block = new SSKBlock(data, headers, key, true);
    } catch (SSKVerifyException e1) {
      throw new IllegalStateException("Impossible: " + e1, e1);
    }
    try {
      RequestHandler.sendSSK(headers, data, source, uid, this, realTimeFlag);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug(MSG_LOST_CONN_UID, uid);
    }
  }

  private void handleTerminalStatuses(SSKInsertSender senderRef, int status) {
    if (isOverloadOrInternal(status)) {
      handleOverloadStatus(status);
      return;
    }
    if (isRouteNotFound(status)) {
      handleRouteNotFoundStatus(senderRef, status);
      return;
    }
    if (status == SSKInsertSender.SUCCESS) {
      handleSuccessStatus(status);
      return;
    }
    handleUnexpectedStatus(senderRef, status);
  }

  private boolean isOverloadOrInternal(int status) {
    return (status == SSKInsertSender.TIMED_OUT)
        || (status == SSKInsertSender.GENERATED_REJECTED_OVERLOAD)
        || (status == SSKInsertSender.INTERNAL_ERROR);
  }

  private boolean isRouteNotFound(int status) {
    return (status == SSKInsertSender.ROUTE_NOT_FOUND)
        || (status == SSKInsertSender.ROUTE_REALLY_NOT_FOUND);
  }

  private void handleOverloadStatus(int status) {
    tag.unlockHandler();
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      source.transport().sendSync(msg, this, realTimeFlag);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug(MSG_CONN_CLOSED);
      return;
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error(MSG_SEND_TIMEOUT_TO, msg, source);
      return;
    }
    if ((status == SSKInsertSender.TIMED_OUT)
        || (status == SSKInsertSender.GENERATED_REJECTED_OVERLOAD)) canCommit = true;
    finish(status);
  }

  private void handleRouteNotFoundStatus(SSKInsertSender senderRef, int status) {
    tag.unlockHandler();
    Message msg = DMT.createFNPRouteNotFound(uid, senderRef.getHTL());
    try {
      source.transport().sendSync(msg, this, realTimeFlag);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug(MSG_CONN_CLOSED);
      return;
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error("Send timeout for {} to source", msg);
    }
    canCommit = true;
    finish(status);
  }

  private void handleSuccessStatus(int status) {
    tag.unlockHandler();
    Message msg = DMT.createFNPInsertReply(uid);
    try {
      source.transport().sendSync(msg, this, realTimeFlag);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug(MSG_CONN_CLOSED);
      return;
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error(MSG_SEND_TIMEOUT_TO, msg, source);
    }
    canCommit = true;
    finish(status);
  }

  private void handleUnexpectedStatus(SSKInsertSender senderRef, int status) {
    LOG.error("Unexpected status: {}", senderRef.getStatusString());
    tag.unlockHandler();
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      source.transport().sendSync(msg, this, realTimeFlag);
    } catch (NotConnectedException _) {
      // Ignore
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error(MSG_SEND_TIMEOUT_TO, msg, source);
    }
    finish(status);
  }

  private void sendPubKeyAccepted() throws NotConnectedException {
    Message confirm = DMT.createFNPSSKPubKeyAccepted(uid);
    source.transport().sendAsync(confirm, null, this);
  }

  /** If allowed and all data verifies, commit the block to the datastore. */
  private void finish(int code) {
    if (LOG.isDebugEnabled()) LOG.debug("Finish insert flow");

    if (canCommit) {
      commit();
    }

    if (code != SSKInsertSender.TIMED_OUT
        && code != SSKInsertSender.GENERATED_REJECTED_OVERLOAD
        && code != SSKInsertSender.INTERNAL_ERROR
        && code != SSKInsertSender.ROUTE_REALLY_NOT_FOUND) {
      int totalSent = getTotalSentBytes();
      int totalReceived = getTotalReceivedBytes();
      if (sender != null) {
        totalSent += sender.getTotalSentBytes();
        totalReceived += sender.getTotalReceivedBytes();
      }
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Remote SSK insert sent/received bytes {}/{} (status={})",
            totalSent,
            totalReceived,
            code);
      node.network().stats().remoteSskInsertBytesSentAverage.report(totalSent);
      node.network().stats().remoteSskInsertBytesReceivedAverage.report(totalReceived);
      if (code == SSKInsertSender.SUCCESS) {
        // Can report both sides
        node.network().stats().successfulSskInsertBytesSentAverage.report(totalSent);
        node.network().stats().successfulSskInsertBytesReceivedAverage.report(totalReceived);
      }
    }
  }

  private void commit() {
    try {
      node.storage()
          .store(
              block,
              node.routing()
                  .shouldStoreDeep(
                      key, source, sender == null ? new PeerNode[0] : sender.getRoutedTo()),
              collided,
              false,
              canWriteDatastore,
              false);
    } catch (KeyCollisionException _) {
      LOG.info("Datastore collision on {}", this);
    }
  }

  private final Object totalBytesSync = new Object();
  private int totalBytesSent;
  private int totalBytesReceived;

  /**
   * Records sent bytes attributed to this handler.
   *
   * @param x number of bytes
   */
  @Override
  public void sentBytes(int x) {
    synchronized (totalBytesSync) {
      totalBytesSent += x;
    }
    node.network().stats().insertSentBytes(true, x);
  }

  /**
   * Records received bytes attributed to this handler.
   *
   * @param x number of bytes
   */
  @Override
  public void receivedBytes(int x) {
    synchronized (totalBytesSync) {
      totalBytesReceived += x;
    }
    node.network().stats().insertReceivedBytes(true, x);
  }

  /**
   * Returns the total number of bytes sent by this handler.
   *
   * <p>Returns a snapshot value; concurrent updates may occur.
   *
   * @return bytes sent
   */
  public int getTotalSentBytes() {
    return totalBytesSent;
  }

  /**
   * Returns the total number of bytes received by this handler.
   *
   * <p>Returns a snapshot value; concurrent updates may occur.
   *
   * @return bytes received
   */
  public int getTotalReceivedBytes() {
    return totalBytesReceived;
  }

  /**
   * Records payload bytes (excludes protocol overhead) that were sent.
   *
   * @param x number of payload bytes
   */
  @Override
  public void sentPayload(int x) {
    node.sentPayload(x);
    node.network().stats().insertSentBytes(true, -x);
  }

  /**
   * Returns the scheduling priority for this handler.
   *
   * @return priority value compatible with {@link NativeThread}
   */
  @Override
  public int getPriority() {
    return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
  }
}
