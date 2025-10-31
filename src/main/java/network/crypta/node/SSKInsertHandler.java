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
      PeerNode source,
      long id,
      Node node,
      long startTime,
      InsertTag tag,
      boolean canWriteDatastore,
      boolean forkOnCacheable,
      boolean preferInsert,
      boolean ignoreLowBackoff,
      boolean realTimeFlag) {
    this.node = node;
    this.uid = id;
    this.source = source;
    this.startTime = startTime;
    this.key = key;
    this.htl = htl;
    this.data = data;
    this.headers = headers;
    this.tag = tag;
    this.canWriteDatastore = canWriteDatastore;
    byte[] pubKeyHash = key.getPubKeyHash();
    pubKey = node.getGetPubKey().getKey(pubKeyHash, false, false, null);
    canCommit = false;

    this.forkOnCacheable = forkOnCacheable;
    this.preferInsert = preferInsert;
    this.ignoreLowBackoff = ignoreLowBackoff;
    this.realTimeFlag = realTimeFlag;
  }

  @Override
  public String toString() {
    return super.toString() + " for " + uid;
  }

  /**
   * Executes the insert flow.
   *
   * <p>Behavior: - Acknowledges the insert, receives remaining parts (headers, data, public key),
   * assembles and verifies the block, and if needed forwards the insert. - Responds to the peer
   * with success, route-not-found, or overload messages as dictated by the sender status. - Always
   * unlocks the associated {@link InsertTag} on exit.
   *
   * <p>This method catches all throwables to prevent thread termination and logs any unexpected
   * failure.
   */
  @Override
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
    // Send Accepted: acknowledge the insert and indicate whether a public key is required.
    Message accepted = DMT.createFNPSSKAccepted(uid, pubKey == null);

    try {
      source.sendAsync(accepted, null, this);
    } catch (NotConnectedException e1) {
      if (LOG.isDebugEnabled()) LOG.debug("Connection to source closed");
      return;
    }

    while (headers == null || data == null || pubKey == null) {
      // Build a composite filter to wait for whichever required part arrives first, including a
      // terminal rejection from the peer.
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
      Message msg;
      try {
        msg = node.getUSM().waitFor(mf, this);
      } catch (DisconnectedException e) {
        if (LOG.isDebugEnabled()) LOG.debug("Lost connection to source on {}", uid);
        return;
      }
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
          source.sendSync(failed, this, realTimeFlag);
        } catch (NotConnectedException | SyncSendWaitedTooLongException e) {
          // Ignore
        }
        return;
      } else if (msg.getSpec() == DMT.FNPSSKInsertRequestHeaders) {
        headers = ((ShortBuffer) msg.getObject(DMT.BLOCK_HEADERS)).getData();
      } else if (msg.getSpec() == DMT.FNPSSKInsertRequestData) {
        data = ((ShortBuffer) msg.getObject(DMT.DATA)).getData();
      } else if (msg.getSpec() == DMT.FNPSSKPubKey) {
        byte[] pubkeyAsBytes = ((ShortBuffer) msg.getObject(DMT.PUBKEY_AS_BYTES)).getData();
        try {
          pubKey = DSAPublicKey.create(pubkeyAsBytes);
          if (LOG.isDebugEnabled()) LOG.debug("Receive pubkey for {}: {}", uid, pubKey);
          Message confirm = DMT.createFNPSSKPubKeyAccepted(uid);
          try {
            source.sendAsync(confirm, null, this);
          } catch (NotConnectedException e) {
            if (LOG.isDebugEnabled()) LOG.debug("Lost connection to source on {}", uid);
            return;
          }
        } catch (CryptFormatException e) {
          LOG.error("Invalid pubkey from {} for {}", source, uid);
          msg = DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_SSK_ERROR);
          try {
            source.sendSync(msg, this, realTimeFlag);
          } catch (NotConnectedException | SyncSendWaitedTooLongException ee) {
            // Ignore
          }
          return;
        }
      } else if (msg.getSpec() == DMT.FNPDataInsertRejected) {
        try {
          source.sendAsync(
              DMT.createFNPDataInsertRejected(uid, msg.getShort(DMT.DATA_INSERT_REJECTED_REASON)),
              null,
              this);
        } catch (NotConnectedException e) {
          // Ignore.
        }
        return;
      } else {
        LOG.error("Unexpected message {} (handler={})", msg, this);
      }
    }

    try {
      key.setPubKey(pubKey);
      block = new SSKBlock(data, headers, key, false);
    } catch (SSKVerifyException e1) {
      LOG.error("Invalid SSK block from {}", source, e1);
      Message msg = DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_SSK_ERROR);
      try {
        source.sendSync(msg, this, realTimeFlag);
      } catch (NotConnectedException | SyncSendWaitedTooLongException e) {
        // Ignore
      }
      return;
    }

    SSKBlock storedBlock = node.fetch(key, false, false, false, canWriteDatastore, false, null);

    if ((storedBlock != null) && !storedBlock.equals(block)) {
      try {
        RequestHandler.sendSSK(
            storedBlock.getRawHeaders(), storedBlock.getRawData(), source, uid, this, realTimeFlag);
      } catch (NotConnectedException e1) {
        if (LOG.isDebugEnabled()) LOG.debug("Lost connection to source on {}", uid);
        return;
      }
      block = storedBlock;
    }

    if (LOG.isDebugEnabled()) LOG.debug("Assembled SSK block (key={}, uid={})", key, uid);

    if (htl > 0)
      sender =
          node.makeInsertSender(
              block,
              htl,
              uid,
              tag,
              source,
              false,
              false,
              canWriteDatastore,
              forkOnCacheable,
              preferInsert,
              ignoreLowBackoff,
              realTimeFlag);

    boolean receivedRejectedOverload = false;

    // Synchronize on a final local reference to avoid locking on a non-final field.
    final SSKInsertSender senderRef = sender;

    while (true) {
      synchronized (senderRef) {
        try {
          if (senderRef.getStatus() == SSKInsertSender.NOT_FINISHED) senderRef.wait(5000);
        } catch (InterruptedException e) {
          // Ignore
        }
      }

      if ((!receivedRejectedOverload) && senderRef.receivedRejectedOverload()) {
        receivedRejectedOverload = true;
        // Forward it. Non-terminal; asynchronous send is sufficient.
        Message m = DMT.createFNPRejectedOverload(uid, false);
        try {
          source.sendAsync(m, null, this);
        } catch (NotConnectedException e) {
          if (LOG.isDebugEnabled()) LOG.debug("Connection to source closed");
          return;
        }
      }

      if (senderRef.hasRecentlyCollided()) {
        // Forward collision
        data = senderRef.getData();
        headers = senderRef.getHeaders();
        collided = true;
        try {
          block = new SSKBlock(data, headers, key, true);
        } catch (SSKVerifyException e1) {
          // Verified elsewhere; construction here should not fail.
          throw new Error("Impossible: " + e1, e1);
        }
        try {
          RequestHandler.sendSSK(headers, data, source, uid, this, realTimeFlag);
        } catch (NotConnectedException e1) {
          if (LOG.isDebugEnabled()) LOG.debug("Lost connection to source on {}", uid);
          return;
        }
      }

      int status = senderRef.getStatus();

      if (status == SSKInsertSender.NOT_FINISHED) {
        continue;
      }

      // Local RejectedOverload (fatal).
      // Treat internal errors as overload to avoid a long timeout that yields the same outcome.
      // Frequent RejectedOverload responses from certain peers remain a known operational issue.
      if ((status == SSKInsertSender.TIMED_OUT)
          || (status == SSKInsertSender.GENERATED_REJECTED_OVERLOAD)
          || (status == SSKInsertSender.INTERNAL_ERROR)) {
        // Unlock early for originator, late for target; see UIDTag comments.
        tag.unlockHandler();
        Message msg = DMT.createFNPRejectedOverload(uid, true);
        try {
          source.sendSync(msg, this, realTimeFlag);
        } catch (NotConnectedException e) {
          if (LOG.isDebugEnabled()) LOG.debug("Connection to source closed");
          return;
        } catch (SyncSendWaitedTooLongException e) {
          LOG.error("Send timeout for {} to {}", msg, source);
          return;
        }
        // Might as well store it anyway.
        if ((status == SSKInsertSender.TIMED_OUT)
            || (status == SSKInsertSender.GENERATED_REJECTED_OVERLOAD)) canCommit = true;
        finish(status);
        return;
      }

      if ((status == SSKInsertSender.ROUTE_NOT_FOUND)
          || (status == SSKInsertSender.ROUTE_REALLY_NOT_FOUND)) {
        // Unlock early for originator, late for target; see UIDTag comments.
        tag.unlockHandler();
        Message msg = DMT.createFNPRouteNotFound(uid, senderRef.getHTL());
        try {
          source.sendSync(msg, this, realTimeFlag);
        } catch (NotConnectedException e) {
          if (LOG.isDebugEnabled()) LOG.debug("Connection to source closed");
          return;
        } catch (SyncSendWaitedTooLongException e) {
          LOG.error("Send timeout for {} to source", msg);
        }
        canCommit = true;
        finish(status);
        return;
      }

      if (status == SSKInsertSender.SUCCESS) {
        // Unlock early for originator, late for target; see UIDTag comments.
        tag.unlockHandler();
        Message msg = DMT.createFNPInsertReply(uid);
        try {
          source.sendSync(msg, this, realTimeFlag);
        } catch (NotConnectedException e) {
          if (LOG.isDebugEnabled()) LOG.debug("Connection to source closed");
          return;
        } catch (SyncSendWaitedTooLongException e) {
          LOG.error("Send timeout for {} to {}", msg, source);
        }
        canCommit = true;
        finish(status);
        return;
      }

      // Otherwise...?
      LOG.error("Unexpected status: {}", senderRef.getStatusString());
      // Unlock early for originator, late for target; see UIDTag comments.
      tag.unlockHandler();
      Message msg = DMT.createFNPRejectedOverload(uid, true);
      try {
        source.sendSync(msg, this, realTimeFlag);
      } catch (NotConnectedException e) {
        // Ignore
      } catch (SyncSendWaitedTooLongException e) {
        LOG.error("Send timeout for {} to {}", msg, source);
      }
      finish(status);
      return;
    }
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
      node.getNodeStats().remoteSskInsertBytesSentAverage.report(totalSent);
      node.getNodeStats().remoteSskInsertBytesReceivedAverage.report(totalReceived);
      if (code == SSKInsertSender.SUCCESS) {
        // Can report both sides
        node.getNodeStats().successfulSskInsertBytesSentAverage.report(totalSent);
        node.getNodeStats().successfulSskInsertBytesReceivedAverage.report(totalReceived);
      }
    }
  }

  private void commit() {
    try {
      node.store(
          block,
          node.shouldStoreDeep(
              key, source, sender == null ? new PeerNode[0] : sender.getRoutedTo()),
          collided,
          false,
          canWriteDatastore,
          false);
    } catch (KeyCollisionException e) {
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
    node.getNodeStats().insertSentBytes(true, x);
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
    node.getNodeStats().insertReceivedBytes(true, x);
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
    node.getNodeStats().insertSentBytes(true, -x);
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
