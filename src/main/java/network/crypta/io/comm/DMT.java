package network.crypta.io.comm;

import network.crypta.crypt.DSAPublicKey;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.node.probe.Error;
import network.crypta.node.probe.Type;
import network.crypta.support.BitArray;
import network.crypta.support.Buffer;
import network.crypta.support.Fields;
import network.crypta.support.ShortBuffer;

/**
 * Registry of data message types (DMT) and field keys used by the Crypta node-to-node communication
 * layer.
 *
 * <p>This utility exposes:
 *
 * <ul>
 *   <li>String constants for field names used when declaring {@link MessageType} schemas.
 *   <li>Static {@link MessageType} instances describing request and response payloads.
 *   <li>Factory helpers that create correctly typed {@link Message} instances.
 * </ul>
 *
 * <p>All members are static; the class is non-instantiable. Priorities indicate relative scheduling
 * on the link; lower numeric values are more urgent. See the {@code PRIORITY_*} constants for
 * semantics.
 *
 * <p>Thread-safety: message type definitions are initialized once and then immutable. Factory
 * methods allocate new {@link Message} objects and are thread-safe.
 */
@SuppressWarnings("unused")
public class DMT {

  private DMT() {
    throw new IllegalStateException("Utility class");
  }

  public static final String UID = "uid";
  /*
   * Field name constants used by {@link MessageType#addField(String, Class)} and by callers when
   * reading/writing {@link Message} values. Names are part of the on-wire schema; avoid renaming.
   */
  public static final String SEND_TIME = "sendTime";
  public static final String EXTERNAL_ADDRESS = "externalAddress";
  public static final String BUILD = "build";
  public static final String FIRST_GOOD_BUILD = "firstGoodBuild";
  public static final String JOINER = "joiner";
  public static final String REASON = "reason";
  public static final String DESCRIPTION = "description";
  public static final String TTL = "ttl";
  public static final String PEERS = "peers";
  public static final String URL = "url";
  public static final String FORWARDERS = "forwarders";
  public static final String FILE_LENGTH = "fileLength";
  public static final String LAST_MODIFIED = "lastModified";
  public static final String CHUNK_NO = "chunkNo";
  public static final String DATA_SOURCE = "dataSource";
  public static final String CACHED = "cached";
  public static final String PACKET_NO = "packetNo";
  public static final String DATA = "data";
  public static final String IS_HASH = "isHash";
  public static final String HASH = "hash";
  public static final String SENT = "sent";
  public static final String MISSING = "missing";
  public static final String KEY = "key";
  public static final String CHK_HEADER = "chkHeader";
  public static final String FREENET_URI = "freenetURI";
  public static final String FREENET_ROUTING_KEY = "freenetRoutingKey";
  public static final String TEST_CHK_HEADERS = "testCHKHeaders";
  public static final String HTL = "hopsToLive";
  public static final String SUCCESS = "success";
  public static final String FNP_SOURCE_PEERNODE = "sourcePeerNode";
  public static final String PING_SEQNO = "pingSequenceNumber";
  public static final String LOCATION = "location";
  public static final String NEAREST_LOCATION = "nearestLocation";
  public static final String BEST_LOCATION = "bestLocation";
  public static final String TARGET_LOCATION = "targetLocation";
  public static final String TYPE = "type";
  public static final String PAYLOAD = "payload";
  public static final String COUNTER = "counter";
  public static final String UNIQUE_COUNTER = "uniqueCounter";
  public static final String LINEAR_COUNTER = "linearCounter";
  public static final String RETURN_LOCATION = "returnLocation";
  public static final String BLOCK_HEADERS = "blockHeaders";
  public static final String DATA_INSERT_REJECTED_REASON = "dataInsertRejectedReason";
  public static final String STREAM_SEQNO = "streamSequenceNumber";
  public static final String IS_LOCAL = "isLocal";
  public static final String ANY_TIMED_OUT = "anyTimedOut";
  public static final String PUBKEY_HASH = "pubkeyHash";
  public static final String NEED_PUB_KEY = "needPubKey";
  public static final String PUBKEY_AS_BYTES = "pubkeyAsBytes";
  public static final String SOURCE_NODENAME = "sourceNodename";
  public static final String TARGET_NODENAME = "targetNodename";
  public static final String NODE_TO_NODE_MESSAGE_TYPE = "nodeToNodeMessageType";
  public static final String NODE_TO_NODE_MESSAGE_TEXT = "nodeToNodeMessageText";
  public static final String NODE_TO_NODE_MESSAGE_DATA = "nodeToNodeMessageData";
  public static final String NODE_UIDS = "nodeUIDs";
  public static final String MY_UID = "myUID";
  public static final String PEER_LOCATIONS = "peerLocations";
  public static final String PEER_UIDS = "peerUIDs";
  public static final String BEST_LOCATIONS_NOT_VISITED = "bestLocationsNotVisited";
  public static final String MAIN_JAR_KEY = "mainJarKey";
  public static final String EXTRA_JAR_KEY = "extraJarKey";
  public static final String REVOCATION_KEY = "revocationKey";
  public static final String HAVE_REVOCATION_KEY = "haveRevocationKey";
  public static final String MAIN_JAR_VERSION = "mainJarVersion";
  public static final String EXTRA_JAR_VERSION = "extJarVersion";
  public static final String REVOCATION_KEY_TIME_LAST_TRIED = "revocationKeyTimeLastTried";
  public static final String REVOCATION_KEY_DNF_COUNT = "revocationKeyDNFCount";
  public static final String REVOCATION_KEY_FILE_LENGTH = "revocationKeyFileLength";
  public static final String MAIN_JAR_FILE_LENGTH = "mainJarFileLength";
  public static final String EXTRA_JAR_FILE_LENGTH = "extraJarFileLength";
  public static final String PING_TIME = "pingTime";
  public static final String BWLIMIT_DELAY_TIME = "bwlimitDelayTime";
  public static final String TIME = "time";
  public static final String FORK_COUNT = "forkCount";
  public static final String TIME_LEFT = "timeLeft";
  public static final String PREV_UID = "prevUID";
  public static final String OPENNET_NODEREF = "opennetNoderef";
  public static final String REMOVE = "remove";
  public static final String PURGE = "purge";
  public static final String TRANSFER_UID = "transferUID";
  public static final String NODEREF_LENGTH = "noderefLength";
  public static final String PADDED_LENGTH = "paddedLength";
  public static final String TIME_DELTAS = "timeDeltas";
  public static final String HASHES = "hashes";
  public static final String REJECT_CODE = "rejectCode";
  public static final String ROUTING_ENABLED = "routingEnabled";
  public static final String OFFER_AUTHENTICATOR = "offerAuthenticator";
  public static final String DAWN_HTL = "dawnHtl";
  public static final String SECRET = "secret";
  public static final String NODE_IDENTITY = "nodeIdentity";
  public static final String UPTIME_PERCENT_48H = "uptimePercent48H";
  public static final String FRIEND_VISIBILITY = "friendVisibility";
  public static final String ENABLE_INSERT_FORK_WHEN_CACHEABLE = "enableInsertForkWhenCacheable";
  public static final String PREFER_INSERT = "preferInsert";
  public static final String IGNORE_LOW_BACKOFF = "ignoreLowBackoff";
  public static final String LIST_OF_UIDS = "listOfUIDs";
  public static final String UID_STILL_RUNNING_FLAGS = "UIDStillRunningFlags";
  public static final String PROBE_IDENTIFIER = "probeIdentifier";
  public static final String STORE_SIZE = "storeSize";
  public static final String LINK_LENGTHS = "linkLengths";
  public static final String UPTIME_PERCENT = "uptimePercent";
  public static final String EXPECTED_HASH = "expectedHash";
  public static final String REJECT_STATS = "rejectStats";
  public static final String OUTPUT_BANDWIDTH_CLASS = "outputBandwidthClass";
  public static final String CAPACITY_USAGE = "capacityUsage";

  // Load management constants
  public static final String AVERAGE_TRANSFERS_OUT_PER_INSERT = "averageTransfersOutPerInsert";
  public static final String OTHER_TRANSFERS_OUT_CHK = "otherTransfersOutCHK";
  public static final String OTHER_TRANSFERS_IN_CHK = "otherTransfersInCHK";
  public static final String OTHER_TRANSFERS_OUT_SSK = "otherTransfersOutSSK";
  public static final String OTHER_TRANSFERS_IN_SSK = "otherTransfersInSSK";

  /**
   * Maximum transfers out, hard limit based on congestion control; we will be rejected if our usage
   * is over this.
   */
  public static final String MAX_TRANSFERS_OUT = "maxTransfersOut";

  /**
   * Maximum transfers out, peer limit. If total is over the lower limit and our usage is over the
   * peer limit, we will be rejected.
   */
  public static final String MAX_TRANSFERS_OUT_PEER_LIMIT = "maxTransfersOutPeerLimit";

  /**
   * Maximum transfers out, lower limit. If total is over the lower limit and our usage is over the
   * peer limit, we will be rejected.
   */
  public static final String MAX_TRANSFERS_OUT_LOWER_LIMIT = "maxTransfersOutLowerLimit";

  /**
   * Maximum transfers out, upper limit. If total is over the upper limit, everything is rejected.
   */
  public static final String MAX_TRANSFERS_OUT_UPPER_LIMIT = "maxTransfersOutUpperLimit";

  public static final String OUTPUT_BANDWIDTH_LOWER_LIMIT = "outputBandwidthLowerLimit";
  public static final String OUTPUT_BANDWIDTH_UPPER_LIMIT = "outputBandwidthUpperLimit";
  public static final String OUTPUT_BANDWIDTH_PEER_LIMIT = "outputBandwidthPeerLimit";
  public static final String INPUT_BANDWIDTH_LOWER_LIMIT = "inputBandwidthLowerLimit";
  public static final String INPUT_BANDWIDTH_UPPER_LIMIT = "inputBandwidthUpperLimit";
  public static final String INPUT_BANDWIDTH_PEER_LIMIT = "inputBandwidthPeerLimit";

  public static final String REAL_TIME_FLAG = "realTimeFlag";

  /** Very urgent control messages. */
  public static final short PRIORITY_NOW = 0;

  /** Short timeout or otherwise urgent (for example, accepts and loop rejections). */
  public static final short PRIORITY_HIGH = 1; //

  /** Routine control messages and completions. */
  public static final short PRIORITY_UNSPECIFIED = 2;

  /** Request initiators; may tolerate longer timeouts. */
  public static final short PRIORITY_LOW = 3; // long timeout, or moderately urgent

  /**
   * Bulk data for realtime requests. Not strictly inferior to {@link #PRIORITY_BULK_DATA};
   * scheduling enforces fairness so realtime data does not starve bulk data.
   */
  public static final short PRIORITY_REALTIME_DATA = 4;

  /**
   * Bulk data transfer (lowest priority). Higher-level admission control must ensure feasibility;
   * persistent starvation raises {@code bwlimitDelayTime} and causes request rejection.
   */
  public static final short PRIORITY_BULK_DATA = 5;

  public static final short NUM_PRIORITIES = 6;

  // Segmented bulk transfer primitives

  /** Message carrying one data packet in a segmented bulk transfer. */
  public static final MessageType packetTransmit =
      new MessageType("packetTransmit", PRIORITY_BULK_DATA);

  static {
    packetTransmit.addField(UID, Long.class);
    packetTransmit.addField(PACKET_NO, Integer.class);
    packetTransmit.addField(SENT, BitArray.class);
    packetTransmit.addField(DATA, Buffer.class);
  }

  /**
   * Creates a {@code packetTransmit} for a segmented bulk transfer.
   *
   * @param uid Transfer identifier shared by the bulk session.
   * @param packetNo Zero-based packet index.
   * @param sent Bitset of packets known to be sent; helps coalesce ACK/resend state.
   * @param data Payload for this packet.
   * @param realTime When true, boosts priority to {@link #PRIORITY_REALTIME_DATA}.
   * @return Initialized message.
   */
  public static Message createPacketTransmit(
      long uid, int packetNo, BitArray sent, Buffer data, boolean realTime) {
    Message msg = new Message(packetTransmit);
    msg.set(UID, uid);
    msg.set(PACKET_NO, packetNo);
    msg.set(SENT, sent);
    msg.set(DATA, data);
    if (realTime) {
      msg.boostPriority();
    }
    return msg;
  }

  /**
   * Computes approximate on-wire size in bytes for a {@code packetTransmit} message.
   *
   * @param size Payload size in bytes.
   * @param packets Number of packets in the transfer (for the {@link BitArray}).
   * @return Payload size plus header/metadata overhead.
   */
  public static int packetTransmitSize(int size, int packets) {
    return size
        + 8 /* uid */
        + 4 /* packet# */
        + BitArray.serializedLength(packets)
        + 4 /* Message header */;
  }

  /**
   * Computes approximate on-wire size for a bulk packet message that does not carry a BitArray.
   *
   * @param size Payload size in bytes.
   * @return Payload size plus header/metadata overhead.
   */
  public static int bulkPacketTransmitSize(int size) {
    return size + 8 /* uid */ + 4 /* packet# */ + 4 /* Message header */;
  }

  // Use BULK_DATA to reduce spurious resend requests; queued after the packets it represents.
  /** Signals that all packets in the current transfer have been enqueued by the sender. */
  public static final MessageType allSent = new MessageType("allSent", PRIORITY_BULK_DATA);

  static {
    allSent.addField(UID, Long.class);
  }

  /**
   * Creates an {@code allSent} notification for the given transfer.
   *
   * @param uid Transfer identifier.
   * @return Initialized message.
   */
  public static Message createAllSent(long uid) {
    Message msg = new Message(allSent);
    msg.set(UID, uid);
    return msg;
  }

  /** Signals that all packets in the current transfer have been received. */
  public static final MessageType allReceived =
      new MessageType("allReceived", PRIORITY_UNSPECIFIED);

  static {
    allReceived.addField(UID, Long.class);
  }

  /**
   * Creates an {@code allReceived} notification for the given transfer.
   *
   * @param uid Transfer identifier.
   * @return Initialized message.
   */
  public static Message createAllReceived(long uid) {
    Message msg = new Message(allReceived);
    msg.set(UID, uid);
    return msg;
  }

  /** Indicates that a transfer was aborted and will not complete. */
  public static final MessageType sendAborted =
      new MessageType("sendAborted", PRIORITY_UNSPECIFIED);

  static {
    sendAborted.addField(UID, Long.class);
    sendAborted.addField(DESCRIPTION, String.class);
    sendAborted.addField(REASON, Integer.class);
  }

  /**
   * Creates a {@code sendAborted} message.
   *
   * @param uid Transfer identifier.
   * @param reason Implementation-defined error code.
   * @param description Human-readable reason.
   * @return Initialized message.
   */
  public static Message createSendAborted(long uid, int reason, String description) {
    Message msg = new Message(sendAborted);
    msg.set(UID, uid);
    msg.set(REASON, reason);
    msg.set(DESCRIPTION, description);
    return msg;
  }

  /**
   * Bulk transfer packet using {@link ShortBuffer} for payload. Used by the bulk transmitter when
   * BitArray acknowledgments are not included inline.
   */
  public static final MessageType FNPBulkPacketSend =
      new MessageType("FNPBulkPacketSend", PRIORITY_BULK_DATA);

  static {
    FNPBulkPacketSend.addField(UID, Long.class);
    FNPBulkPacketSend.addField(PACKET_NO, Integer.class);
    FNPBulkPacketSend.addField(DATA, ShortBuffer.class);
  }

  /**
   * Creates an {@code FNPBulkPacketSend} for a segmented bulk transfer.
   *
   * @param uid Transfer identifier.
   * @param packetNo Zero-based packet index.
   * @param data Packet payload as a {@link ShortBuffer}.
   * @return Initialized message.
   */
  public static Message createFNPBulkPacketSend(long uid, int packetNo, ShortBuffer data) {
    Message msg = new Message(FNPBulkPacketSend);
    msg.set(UID, uid);
    msg.set(PACKET_NO, packetNo);
    msg.set(DATA, data);
    return msg;
  }

  /** Convenience overload that wraps a byte array into {@link ShortBuffer}. */
  public static Message createFNPBulkPacketSend(long uid, int packetNo, byte[] data) {
    return createFNPBulkPacketSend(uid, packetNo, new ShortBuffer(data));
  }

  /** Sender aborted a bulk transfer; no further packets will be sent. */
  public static final MessageType FNPBulkSendAborted =
      new MessageType("FNPBulkSendAborted", PRIORITY_UNSPECIFIED);

  static {
    FNPBulkSendAborted.addField(UID, Long.class);
  }

  /** Creates an {@code FNPBulkSendAborted} for the given transfer. */
  public static Message createFNPBulkSendAborted(long uid) {
    Message msg = new Message(FNPBulkSendAborted);
    msg.set(UID, uid);
    return msg;
  }

  /** Receiver aborted a bulk transfer; subsequent packets should be discarded. */
  public static final MessageType FNPBulkReceiveAborted =
      new MessageType("FNPBulkReceiveAborted", PRIORITY_UNSPECIFIED);

  static {
    FNPBulkReceiveAborted.addField(UID, Long.class);
  }

  /** Creates an {@code FNPBulkReceiveAborted} for the given transfer. */
  public static Message createFNPBulkReceiveAborted(long uid) {
    Message msg = new Message(FNPBulkReceiveAborted);
    msg.set(UID, uid);
    return msg;
  }

  /** Receiver acknowledges that all expected packets were received. */
  public static final MessageType FNPBulkReceivedAll =
      new MessageType("FNPBulkReceivedAll", PRIORITY_UNSPECIFIED);

  static {
    FNPBulkReceivedAll.addField(UID, Long.class);
  }

  /** Creates an {@code FNPBulkReceivedAll} acknowledgment. */
  public static Message createFNPBulkReceivedAll(long uid) {
    Message msg = new Message(FNPBulkReceivedAll);
    msg.set(UID, uid);
    return msg;
  }

  /** Test harness: request that the peer start a trivial transfer. */
  public static final MessageType testTransferSend =
      new MessageType("testTransferSend", PRIORITY_UNSPECIFIED);

  static {
    testTransferSend.addField(UID, Long.class);
  }

  /** Creates a {@code testTransferSend} request. */
  public static Message createTestTransferSend(long uid) {
    Message msg = new Message(testTransferSend);
    msg.set(UID, uid);
    return msg;
  }

  /** Test harness: acknowledgment of {@code testTransferSend}. */
  public static final MessageType testTransferSendAck =
      new MessageType("testTransferSendAck", PRIORITY_UNSPECIFIED);

  static {
    testTransferSendAck.addField(UID, Long.class);
  }

  /** Creates a {@code testTransferSendAck}. */
  public static Message createTestTransferSendAck(long uid) {
    Message msg = new Message(testTransferSendAck);
    msg.set(UID, uid);
    return msg;
  }

  /** Test harness: send a CHK URI and header for validation. */
  public static final MessageType testSendCHK =
      new MessageType("testSendCHK", PRIORITY_UNSPECIFIED);

  static {
    testSendCHK.addField(UID, Long.class);
    testSendCHK.addField(FREENET_URI, String.class);
    testSendCHK.addField(CHK_HEADER, Buffer.class);
  }

  /**
   * Creates a {@code testSendCHK} with a URI string and header buffer.
   *
   * @param uid Test identifier.
   * @param uri CHK URI as a string.
   * @param header Serialized header.
   * @return Initialized message.
   */
  public static Message createTestSendCHK(long uid, String uri, Buffer header) {
    Message msg = new Message(testSendCHK);
    msg.set(UID, uid);
    msg.set(FREENET_URI, uri);
    msg.set(CHK_HEADER, header);
    return msg;
  }

  /** Test harness: request data by routing key with an explicit HTL. */
  public static final MessageType testRequest =
      new MessageType("testRequest", PRIORITY_UNSPECIFIED);

  static {
    testRequest.addField(UID, Long.class);
    testRequest.addField(FREENET_ROUTING_KEY, Key.class);
    testRequest.addField(HTL, Integer.class);
  }

  /**
   * Creates a {@code testRequest} for a routing key.
   *
   * @param key Routing key.
   * @param id Test identifier.
   * @param htl Hops-to-live.
   * @return Initialized message.
   */
  public static Message createTestRequest(Key key, long id, int htl) {
    Message msg = new Message(testRequest);
    msg.set(UID, id);
    msg.set(FREENET_ROUTING_KEY, key);
    msg.set(HTL, htl);
    return msg;
  }

  /** Test harness: negative lookup result. */
  public static final MessageType testDataNotFound =
      new MessageType("testDataNotFound", PRIORITY_UNSPECIFIED);

  static {
    testDataNotFound.addField(UID, Long.class);
  }

  /** Creates a {@code testDataNotFound}. */
  public static Message createTestDataNotFound(long uid) {
    Message msg = new Message(testDataNotFound);
    msg.set(UID, uid);
    return msg;
  }

  /** Test harness: successful reply carrying serialized headers. */
  public static final MessageType testDataReply =
      new MessageType("testDataReply", PRIORITY_UNSPECIFIED);

  static {
    testDataReply.addField(UID, Long.class);
    testDataReply.addField(TEST_CHK_HEADERS, Buffer.class);
  }

  /**
   * Creates a {@code testDataReply} with serialized headers.
   *
   * @param uid Test identifier.
   * @param headers Serialized headers.
   * @return Initialized message.
   */
  public static Message createTestDataReply(long uid, byte[] headers) {
    Message msg = new Message(testDataReply);
    msg.set(UID, uid);
    msg.set(TEST_CHK_HEADERS, new Buffer(headers));
    return msg;
  }

  /** Test harness: acknowledgment to {@code testSendCHK}. */
  public static final MessageType testSendCHKAck =
      new MessageType("testSendCHKAck", PRIORITY_UNSPECIFIED);

  static {
    testSendCHKAck.addField(UID, Long.class);
    testSendCHKAck.addField(FREENET_URI, String.class);
  }

  /**
   * Creates a {@code testSendCHKAck} echoing the provided key.
   *
   * @param uid Test identifier.
   * @param key Echo of the CHK key string.
   * @return Initialized message.
   */
  public static Message createTestSendCHKAck(long uid, String key) {
    Message msg = new Message(testSendCHKAck);
    msg.set(UID, uid);
    msg.set(FREENET_URI, key);
    return msg;
  }

  /** Test harness: acknowledgment of {@code testDataReply}. */
  public static final MessageType testDataReplyAck =
      new MessageType("testDataReplyAck", PRIORITY_UNSPECIFIED);

  static {
    testDataReplyAck.addField(UID, Long.class);
  }

  /** Creates a {@code testDataReplyAck}. */
  public static Message createTestDataReplyAck(long id) {
    Message msg = new Message(testDataReplyAck);
    msg.set(UID, id);
    return msg;
  }

  /** Test harness: acknowledgment of {@code testDataNotFound}. */
  public static final MessageType testDataNotFoundAck =
      new MessageType("testDataNotFoundAck", PRIORITY_UNSPECIFIED);

  static {
    testDataNotFoundAck.addField(UID, Long.class);
  }

  /** Creates a {@code testDataNotFoundAck}. */
  public static Message createTestDataNotFoundAck(long id) {
    Message msg = new Message(testDataNotFoundAck);
    msg.set(UID, id);
    return msg;
  }

  // Internal only messages

  /** Internal: indicates completion of a test receive, with success flag and reason. */
  public static final MessageType testReceiveCompleted =
      new MessageType("testReceiveCompleted", PRIORITY_UNSPECIFIED, true, false);

  static {
    testReceiveCompleted.addField(UID, Long.class);
    testReceiveCompleted.addField(SUCCESS, Boolean.class);
    testReceiveCompleted.addField(REASON, String.class);
  }

  /**
   * Creates a {@code testReceiveCompleted}.
   *
   * @param id Test identifier.
   * @param success Whether the reception completed successfully.
   * @param reason Optional reason text.
   * @return Initialized message.
   */
  public static Message createTestReceiveCompleted(long id, boolean success, String reason) {
    Message msg = new Message(testReceiveCompleted);
    msg.set(UID, id);
    msg.set(SUCCESS, success);
    msg.set(REASON, reason);
    return msg;
  }

  /** Internal: indicates completion of a test send, with success flag and reason. */
  public static final MessageType testSendCompleted =
      new MessageType("testSendCompleted", PRIORITY_UNSPECIFIED, true, false);

  static {
    testSendCompleted.addField(UID, Long.class);
    testSendCompleted.addField(SUCCESS, Boolean.class);
    testSendCompleted.addField(REASON, String.class);
  }

  /**
   * Creates a {@code testSendCompleted}.
   *
   * @param id Test identifier.
   * @param success Whether the sending completed successfully.
   * @param reason Optional reason text.
   * @return Initialized message.
   */
  public static Message createTestSendCompleted(long id, boolean success, String reason) {
    Message msg = new Message(testSendCompleted);
    msg.set(UID, id);
    msg.set(SUCCESS, success);
    msg.set(REASON, reason);
    return msg;
  }

  /** Generic node-to-node message carrying a small typed payload. */
  public static final MessageType nodeToNodeMessage =
      new MessageType("nodeToNodeMessage", PRIORITY_LOW, false, false);

  static {
    nodeToNodeMessage.addField(NODE_TO_NODE_MESSAGE_TYPE, Integer.class);
    nodeToNodeMessage.addField(NODE_TO_NODE_MESSAGE_DATA, ShortBuffer.class);
  }

  /**
   * Creates a generic node-to-node message with a caller-defined {@code type} and opaque payload.
   *
   * @param type Application-specific subtype.
   * @param data Opaque payload; interpreted by the receiver based on {@code type}.
   * @return Initialized message.
   */
  public static Message createNodeToNodeMessage(int type, byte[] data) {
    Message msg = new Message(nodeToNodeMessage);
    msg.set(NODE_TO_NODE_MESSAGE_TYPE, type);
    msg.set(NODE_TO_NODE_MESSAGE_DATA, new ShortBuffer(data));
    return msg;
  }

  // FNP messages
  /** Request for CHK data (content-hash key) routed by location. */
  public static final MessageType FNPCHKDataRequest =
      new MessageType("FNPCHKDataRequest", PRIORITY_LOW);

  static {
    FNPCHKDataRequest.addField(UID, Long.class);
    FNPCHKDataRequest.addField(HTL, Short.class);
    FNPCHKDataRequest.addField(NEAREST_LOCATION, Double.class);
    FNPCHKDataRequest.addField(FREENET_ROUTING_KEY, NodeCHK.class);
  }

  /**
   * Creates an {@code FNPCHKDataRequest}.
   *
   * @param id Request identifier.
   * @param htl Hops-to-live.
   * @param key Routing key (CHK).
   * @return Initialized message.
   */
  public static Message createFNPCHKDataRequest(long id, short htl, NodeCHK key) {
    Message msg = new Message(FNPCHKDataRequest);
    msg.set(UID, id);
    msg.set(HTL, htl);
    msg.set(FREENET_ROUTING_KEY, key);
    msg.set(NEAREST_LOCATION, 0.0);
    return msg;
  }

  /** Request for SSK data (signed-subspace key) routed by location. */
  public static final MessageType FNPSSKDataRequest =
      new MessageType("FNPSSKDataRequest", PRIORITY_LOW);

  static {
    FNPSSKDataRequest.addField(UID, Long.class);
    FNPSSKDataRequest.addField(HTL, Short.class);
    FNPSSKDataRequest.addField(NEAREST_LOCATION, Double.class);
    FNPSSKDataRequest.addField(FREENET_ROUTING_KEY, NodeSSK.class);
    FNPSSKDataRequest.addField(NEED_PUB_KEY, Boolean.class);
  }

  /**
   * Creates an {@code FNPSSKDataRequest}.
   *
   * @param id Request identifier.
   * @param htl Hops-to-live.
   * @param key Routing key (SSK).
   * @param needPubKey Whether the caller requires the public key to be returned.
   * @return Initialized message.
   */
  public static Message createFNPSSKDataRequest(
      long id, short htl, NodeSSK key, boolean needPubKey) {
    Message msg = new Message(FNPSSKDataRequest);
    msg.set(UID, id);
    msg.set(HTL, htl);
    msg.set(FREENET_ROUTING_KEY, key);
    msg.set(NEAREST_LOCATION, 0.0);
    msg.set(NEED_PUB_KEY, needPubKey);
    return msg;
  }

  // Loop detected: choose a different peer.
  /** Rejection indicating a routing loop was encountered. */
  public static final MessageType FNPRejectedLoop = new MessageType("FNPRejectLoop", PRIORITY_HIGH);

  static {
    FNPRejectedLoop.addField(UID, Long.class);
  }

  /**
   * Creates an {@code FNPRejectedLoop} for the given request.
   *
   * @param id Request identifier.
   * @return Initialized message.
   */
  public static Message createFNPRejectedLoop(long id) {
    Message msg = new Message(FNPRejectedLoop);
    msg.set(UID, id);
    return msg;
  }

  // Too many concurrent requests for current capacity.
  /** Rejection due to overload; caller may reduce rate or choose another peer. */
  public static final MessageType FNPRejectedOverload =
      new MessageType("FNPRejectOverload", PRIORITY_HIGH);

  static {
    FNPRejectedOverload.addField(UID, Long.class);
    FNPRejectedOverload.addField(IS_LOCAL, Boolean.class);
  }

  /**
   * Creates an {@code FNPRejectedOverload}.
   *
   * @param id Request identifier.
   * @param isLocal Whether the rejecting peer is the local node.
   * @return Initialized message.
   */
  public static Message createFNPRejectedOverload(long id, boolean isLocal) {
    Message msg = new Message(FNPRejectedOverload);
    msg.set(UID, id);
    msg.set(IS_LOCAL, isLocal);
    return msg;
  }

  /** Acknowledge that a request was accepted and will proceed. */
  public static final MessageType FNPAccepted = new MessageType("FNPAccepted", PRIORITY_HIGH);

  static {
    FNPAccepted.addField(UID, Long.class);
  }

  /**
   * Creates an {@code FNPAccepted} acknowledgment.
   *
   * @param id Request identifier.
   * @return Initialized message.
   */
  public static Message createFNPAccepted(long id) {
    Message msg = new Message(FNPAccepted);
    msg.set(UID, id);
    return msg;
  }

  /** Negative result indicating the requested data was not found. */
  public static final MessageType FNPDataNotFound =
      new MessageType("FNPDataNotFound", PRIORITY_UNSPECIFIED);

  static {
    FNPDataNotFound.addField(UID, Long.class);
  }

  /**
   * Creates an {@code FNPDataNotFound} for the given request.
   *
   * @param id Request identifier.
   * @return Initialized message.
   */
  public static Message createFNPDataNotFound(long id) {
    Message msg = new Message(FNPDataNotFound);
    msg.set(UID, id);
    return msg;
  }

  /** Indicates a recent failure; used to guide backoff and avoid repeated attempts. */
  public static final MessageType FNPRecentlyFailed =
      new MessageType("FNPRecentlyFailed", PRIORITY_HIGH);

  static {
    FNPRecentlyFailed.addField(UID, Long.class);
    FNPRecentlyFailed.addField(TIME_LEFT, Integer.class);
  }

  /**
   * Creates an {@code FNPRecentlyFailed} with a remaining-wait hint.
   *
   * @param id Request identifier.
   * @param timeLeft Remaining time to wait before retrying (unit implementation-defined).
   * @return Initialized message.
   */
  public static Message createFNPRecentlyFailed(long id, int timeLeft) {
    Message msg = new Message(FNPRecentlyFailed);
    msg.set(UID, id);
    msg.set(TIME_LEFT, timeLeft);
    return msg;
  }

  /** Positive result for CHK requests carrying block headers. */
  public static final MessageType FNPCHKDataFound =
      new MessageType("FNPCHKDataFound", PRIORITY_UNSPECIFIED);

  static {
    FNPCHKDataFound.addField(UID, Long.class);
    FNPCHKDataFound.addField(BLOCK_HEADERS, ShortBuffer.class);
  }

  /**
   * Creates an {@code FNPCHKDataFound} with serialized block headers.
   *
   * @param id Request identifier.
   * @param buf Serialized headers.
   * @return Initialized message.
   */
  public static Message createFNPCHKDataFound(long id, byte[] buf) {
    Message msg = new Message(FNPCHKDataFound);
    msg.set(UID, id);
    msg.set(BLOCK_HEADERS, new ShortBuffer(buf));
    return msg;
  }

  /** No route found for the request; includes remaining HTL. */
  public static final MessageType FNPRouteNotFound =
      new MessageType("FNPRouteNotFound", PRIORITY_UNSPECIFIED);

  static {
    FNPRouteNotFound.addField(UID, Long.class);
    FNPRouteNotFound.addField(HTL, Short.class);
  }

  /**
   * Creates an {@code FNPRouteNotFound}.
   *
   * @param id Request identifier.
   * @param htl Remaining hops-to-live.
   * @return Initialized message.
   */
  public static Message createFNPRouteNotFound(long id, short htl) {
    Message msg = new Message(FNPRouteNotFound);
    msg.set(UID, id);
    msg.set(HTL, htl);
    return msg;
  }

  /** Insert request routed by location (CHK/SSK-agnostic key interface). */
  public static final MessageType FNPInsertRequest =
      new MessageType("FNPInsertRequest", PRIORITY_LOW);

  static {
    FNPInsertRequest.addField(UID, Long.class);
    FNPInsertRequest.addField(HTL, Short.class);
    FNPInsertRequest.addField(NEAREST_LOCATION, Double.class);
    FNPInsertRequest.addField(FREENET_ROUTING_KEY, Key.class);
  }

  /**
   * Creates an {@code FNPInsertRequest}.
   *
   * @param id Request identifier.
   * @param htl Hops-to-live.
   * @param key Routing key.
   * @return Initialized message.
   */
  public static Message createFNPInsertRequest(long id, short htl, Key key) {
    Message msg = new Message(FNPInsertRequest);
    msg.set(UID, id);
    msg.set(HTL, htl);
    msg.set(FREENET_ROUTING_KEY, key);
    msg.set(NEAREST_LOCATION, 0.0);
    return msg;
  }

  /** Acknowledgment that an insert request was accepted downstream. */
  public static final MessageType FNPInsertReply =
      new MessageType("FNPInsertReply", PRIORITY_UNSPECIFIED);

  static {
    FNPInsertReply.addField(UID, Long.class);
  }

  /**
   * Creates an {@code FNPInsertReply} acknowledgment.
   *
   * @param id Request identifier.
   * @return Initialized message.
   */
  public static Message createFNPInsertReply(long id) {
    Message msg = new Message(FNPInsertReply);
    msg.set(UID, id);
    return msg;
  }

  /** Carries serialized block headers for a data insert. */
  public static final MessageType FNPDataInsert = new MessageType("FNPDataInsert", PRIORITY_HIGH);

  static {
    FNPDataInsert.addField(UID, Long.class);
    FNPDataInsert.addField(BLOCK_HEADERS, ShortBuffer.class);
  }

  /**
   * Creates an {@code FNPDataInsert} message with serialized block headers.
   *
   * @param uid Insert identifier.
   * @param headers Serialized headers.
   * @return Initialized message.
   */
  public static Message createFNPDataInsert(long uid, byte[] headers) {
    Message msg = new Message(FNPDataInsert);
    msg.set(UID, uid);
    msg.set(BLOCK_HEADERS, new ShortBuffer(headers));
    return msg;
  }

  /** Indicates that all transfer segments for an insert completed (possibly with timeouts). */
  public static final MessageType FNPInsertTransfersCompleted =
      new MessageType("FNPInsertTransfersCompleted", PRIORITY_UNSPECIFIED);

  static {
    FNPInsertTransfersCompleted.addField(UID, Long.class);
    FNPInsertTransfersCompleted.addField(ANY_TIMED_OUT, Boolean.class);
  }

  /**
   * Creates an {@code FNPInsertTransfersCompleted}.
   *
   * @param uid Insert identifier.
   * @param anyTimedOut Whether any segment timed out.
   * @return Initialized message.
   */
  public static Message createFNPInsertTransfersCompleted(long uid, boolean anyTimedOut) {
    Message msg = new Message(FNPInsertTransfersCompleted);
    msg.set(UID, uid);
    msg.set(ANY_TIMED_OUT, anyTimedOut);
    return msg;
  }

  // This is used by CHK inserts when the DataInsert isn't received.
  // SSK inserts just use DataInsertRejected with a timeout reason.
  // Consider using a single message for both. One complication is that
  // CHKs have a single DataInsert (followed by a transfer), whereas SSKs have 2-3 messages,
  // any of which can time out independently. We could send one message now that we have the new
  // packet format; see the discussion on FNPSSKInsertRequestNew vs the old version.
  /** Timeout for CHK inserts when {@code FNPDataInsert} was not received in time. */
  public static final MessageType FNPRejectedTimeout =
      new MessageType("FNPTooSlow", PRIORITY_UNSPECIFIED);

  static {
    FNPRejectedTimeout.addField(UID, Long.class);
  }

  /**
   * Creates an {@code FNPRejectedTimeout} notification.
   *
   * @param uid Insert identifier.
   * @return Initialized message.
   */
  public static Message createFNPRejectedTimeout(long uid) {
    Message msg = new Message(FNPRejectedTimeout);
    msg.set(UID, uid);
    return msg;
  }

  /**
   * Insert rejected with a reason code (see constants and {@link #getDataInsertRejectedReason}).
   */
  public static final MessageType FNPDataInsertRejected =
      new MessageType("FNPDataInsertRejected", PRIORITY_UNSPECIFIED);

  static {
    FNPDataInsertRejected.addField(UID, Long.class);
    FNPDataInsertRejected.addField(DATA_INSERT_REJECTED_REASON, Short.class);
  }

  /**
   * Creates an {@code FNPDataInsertRejected} with a reason code.
   *
   * @param uid Insert identifier.
   * @param reason Reason code constant.
   * @return Initialized message.
   */
  public static Message createFNPDataInsertRejected(long uid, short reason) {
    Message msg = new Message(FNPDataInsertRejected);
    msg.set(UID, uid);
    msg.set(DATA_INSERT_REJECTED_REASON, reason);
    return msg;
  }

  public static final short DATA_INSERT_REJECTED_VERIFY_FAILED = 1;
  public static final short DATA_INSERT_REJECTED_RECEIVE_FAILED = 2;
  public static final short DATA_INSERT_REJECTED_SSK_ERROR = 3;
  public static final short DATA_INSERT_REJECTED_TIMEOUT_WAITING_FOR_ACCEPTED = 4;

  /** Returns a human-readable description for an insert rejection {@code reason} code. */
  public static String getDataInsertRejectedReason(short reason) {
    if (reason == DATA_INSERT_REJECTED_VERIFY_FAILED) {
      return "Verify failed";
    } else if (reason == DATA_INSERT_REJECTED_RECEIVE_FAILED) {
      return "Receive failed";
    } else if (reason == DATA_INSERT_REJECTED_SSK_ERROR) {
      return "SSK error";
    } else if (reason == DATA_INSERT_REJECTED_TIMEOUT_WAITING_FOR_ACCEPTED) {
      return "Timeout waiting for Accepted (moved on)";
    }
    return "Unknown reason code: " + reason;
  }

  // Consider using this again now we have a packet format that can handle big messages on any
  // connection.
  // If re-enabled, ensure priority handling for realtime and be mindful of timeouts associated
  // with sending a request at BULK.

  /** Legacy SSK insert request carrying headers, data, and pubkey hash in one message. */
  public static final MessageType FNPSSKInsertRequest =
      new MessageType("FNPSSKInsertRequest", PRIORITY_BULK_DATA);

  static {
    FNPSSKInsertRequest.addField(UID, Long.class);
    FNPSSKInsertRequest.addField(HTL, Short.class);
    FNPSSKInsertRequest.addField(FREENET_ROUTING_KEY, NodeSSK.class);
    FNPSSKInsertRequest.addField(NEAREST_LOCATION, Double.class);
    FNPSSKInsertRequest.addField(BLOCK_HEADERS, ShortBuffer.class);
    FNPSSKInsertRequest.addField(PUBKEY_HASH, ShortBuffer.class);
    FNPSSKInsertRequest.addField(DATA, ShortBuffer.class);
  }

  /**
   * Creates a legacy {@code FNPSSKInsertRequest} bundling metadata and data.
   *
   * @param uid Insert identifier.
   * @param htl Hops-to-live.
   * @param myKey Routing key (SSK).
   * @param headers Serialized block headers.
   * @param data Serialized content.
   * @param pubKeyHash Hash of the public key.
   * @param realTime Boost to realtime if {@code true}.
   * @return Initialized message.
   */
  public static Message createFNPSSKInsertRequest(
      long uid,
      short htl,
      NodeSSK myKey,
      byte[] headers,
      byte[] data,
      byte[] pubKeyHash,
      boolean realTime) {
    Message msg = new Message(FNPSSKInsertRequest);
    msg.set(UID, uid);
    msg.set(HTL, htl);
    msg.set(FREENET_ROUTING_KEY, myKey);
    msg.set(NEAREST_LOCATION, 0.0);
    msg.set(BLOCK_HEADERS, new ShortBuffer(headers));
    msg.set(PUBKEY_HASH, new ShortBuffer(pubKeyHash));
    msg.set(DATA, new ShortBuffer(data));
    if (realTime) {
      msg.boostPriority();
    }
    return msg;
  }

  /** Modern SSK insert request; headers and data are sent in follow-up bulk messages. */
  public static final MessageType FNPSSKInsertRequestNew =
      new MessageType("FNPSSKInsertRequestNew", PRIORITY_LOW);

  static {
    FNPSSKInsertRequestNew.addField(UID, Long.class);
    FNPSSKInsertRequestNew.addField(HTL, Short.class);
    FNPSSKInsertRequestNew.addField(FREENET_ROUTING_KEY, NodeSSK.class);
  }

  /**
   * Creates the initial {@code FNPSSKInsertRequestNew} handshake.
   *
   * @param uid Insert identifier.
   * @param htl Hops-to-live.
   * @param myKey Routing key (SSK).
   * @return Initialized message.
   */
  public static Message createFNPSSKInsertRequestNew(long uid, short htl, NodeSSK myKey) {
    Message msg = new Message(FNPSSKInsertRequestNew);
    msg.set(UID, uid);
    msg.set(HTL, htl);
    msg.set(FREENET_ROUTING_KEY, myKey);
    return msg;
  }

  // SSK inserts data and headers. These are BULK_DATA or REALTIME.

  /** Follow-up message carrying SSK insert block headers. */
  public static final MessageType FNPSSKInsertRequestHeaders =
      new MessageType("FNPSSKInsertRequestHeaders", PRIORITY_BULK_DATA);

  static {
    FNPSSKInsertRequestHeaders.addField(UID, Long.class);
    FNPSSKInsertRequestHeaders.addField(BLOCK_HEADERS, ShortBuffer.class);
  }

  /**
   * Creates {@code FNPSSKInsertRequestHeaders} with serialized block headers.
   *
   * @param uid Insert identifier.
   * @param headers Serialized headers.
   * @param realTime Boost to realtime if {@code true}.
   * @return Initialized message.
   */
  public static Message createFNPSSKInsertRequestHeaders(
      long uid, byte[] headers, boolean realTime) {
    Message msg = new Message(FNPSSKInsertRequestHeaders);
    msg.set(UID, uid);
    msg.set(BLOCK_HEADERS, new ShortBuffer(headers));
    if (realTime) {
      msg.boostPriority();
    }
    return msg;
  }

  /** Follow-up message carrying SSK insert payload data. */
  public static final MessageType FNPSSKInsertRequestData =
      new MessageType("FNPSSKInsertRequestData", PRIORITY_BULK_DATA);

  static {
    FNPSSKInsertRequestData.addField(UID, Long.class);
    FNPSSKInsertRequestData.addField(DATA, ShortBuffer.class);
  }

  /**
   * Creates {@code FNPSSKInsertRequestData} with serialized payload.
   *
   * @param uid Insert identifier.
   * @param data Serialized content bytes.
   * @param realTime Boost to realtime if {@code true}.
   * @return Initialized message.
   */
  public static Message createFNPSSKInsertRequestData(long uid, byte[] data, boolean realTime) {
    Message msg = new Message(FNPSSKInsertRequestData);
    msg.set(UID, uid);
    msg.set(DATA, new ShortBuffer(data));
    if (realTime) {
      msg.boostPriority();
    }
    return msg;
  }

  // SSK pubkeys, data and headers are all BULK_DATA or REALTIME.
  // Requests wait for them all equally, so there is no reason for them to be different,
  // plus everything is throttled now.

  /** SSK positive result containing block headers. */
  public static final MessageType FNPSSKDataFoundHeaders =
      new MessageType("FNPSSKDataFoundHeaders", PRIORITY_BULK_DATA);

  static {
    FNPSSKDataFoundHeaders.addField(UID, Long.class);
    FNPSSKDataFoundHeaders.addField(BLOCK_HEADERS, ShortBuffer.class);
  }

  /**
   * Creates {@code FNPSSKDataFoundHeaders}.
   *
   * @param uid Request identifier.
   * @param headers Serialized headers.
   * @param realTime Boost to realtime if {@code true}.
   * @return Initialized message.
   */
  public static Message createFNPSSKDataFoundHeaders(long uid, byte[] headers, boolean realTime) {
    Message msg = new Message(FNPSSKDataFoundHeaders);
    msg.set(UID, uid);
    msg.set(BLOCK_HEADERS, new ShortBuffer(headers));
    if (realTime) {
      msg.boostPriority();
    }
    return msg;
  }

  /** SSK positive result containing payload data. */
  public static final MessageType FNPSSKDataFoundData =
      new MessageType("FNPSSKDataFoundData", PRIORITY_BULK_DATA);

  static {
    FNPSSKDataFoundData.addField(UID, Long.class);
    FNPSSKDataFoundData.addField(DATA, ShortBuffer.class);
  }

  /**
   * Creates {@code FNPSSKDataFoundData}.
   *
   * @param uid Request identifier.
   * @param data Serialized content bytes.
   * @param realTime Boost to realtime if {@code true}.
   * @return Initialized message.
   */
  public static Message createFNPSSKDataFoundData(long uid, byte[] data, boolean realTime) {
    Message msg = new Message(FNPSSKDataFoundData);
    msg.set(UID, uid);
    msg.set(DATA, new ShortBuffer(data));
    if (realTime) {
      msg.boostPriority();
    }
    return msg;
  }

  /** Acknowledges an SSK request and indicates whether a public key is needed. */
  public static final MessageType FNPSSKAccepted = new MessageType("FNPSSKAccepted", PRIORITY_HIGH);

  static {
    FNPSSKAccepted.addField(UID, Long.class);
    FNPSSKAccepted.addField(NEED_PUB_KEY, Boolean.class);
  }

  /**
   * Creates an {@code FNPSSKAccepted}.
   *
   * @param uid Request identifier.
   * @param needPubKey Whether the receiver requires the public key.
   * @return Initialized message.
   */
  public static Message createFNPSSKAccepted(long uid, boolean needPubKey) {
    Message msg = new Message(FNPSSKAccepted);
    msg.set(UID, uid);
    msg.set(NEED_PUB_KEY, needPubKey);
    return msg;
  }

  /** SSK public key payload. */
  public static final MessageType FNPSSKPubKey =
      new MessageType("FNPSSKPubKey", PRIORITY_BULK_DATA);

  static {
    FNPSSKPubKey.addField(UID, Long.class);
    FNPSSKPubKey.addField(PUBKEY_AS_BYTES, ShortBuffer.class);
  }

  /**
   * Creates an {@code FNPSSKPubKey} containing a padded public key.
   *
   * @param uid Request identifier.
   * @param pubkey Public key to send.
   * @param realTime Boost to realtime if {@code true}.
   * @return Initialized message.
   */
  public static Message createFNPSSKPubKey(long uid, DSAPublicKey pubkey, boolean realTime) {
    Message msg = new Message(FNPSSKPubKey);
    msg.set(UID, uid);
    msg.set(PUBKEY_AS_BYTES, new ShortBuffer(pubkey.asPaddedBytes()));
    if (realTime) {
      msg.boostPriority();
    }
    return msg;
  }

  /** Acknowledges receipt of an SSK public key. */
  public static final MessageType FNPSSKPubKeyAccepted =
      new MessageType("FNPSSKPubKeyAccepted", PRIORITY_HIGH);

  static {
    FNPSSKPubKeyAccepted.addField(UID, Long.class);
  }

  /**
   * Creates an {@code FNPSSKPubKeyAccepted} acknowledgment.
   *
   * @param uid Request identifier.
   * @return Initialized message.
   */
  public static Message createFNPSSKPubKeyAccepted(long uid) {
    Message msg = new Message(FNPSSKPubKeyAccepted);
    msg.set(UID, uid);
    return msg;
  }

  // Opennet completions (not sent to darknet nodes)

  /**
   * Sent when a request to an opennet node completes and the data source does not path-fold. Also
   * used on darknet.
   */
  public static final MessageType FNPOpennetCompletedAck =
      new MessageType("FNPOpennetCompletedAck", PRIORITY_HIGH);

  static {
    FNPOpennetCompletedAck.addField(UID, Long.class);
  }

  /**
   * Creates an {@code FNPOpennetCompletedAck} for the given request.
   *
   * @param uid Original request identifier.
   * @return Initialized message.
   */
  public static Message createFNPOpennetCompletedAck(long uid) {
    Message msg = new Message(FNPOpennetCompletedAck);
    msg.set(UID, uid);
    return msg;
  }

  /** Sent when we wait for an FNP transfer or a completion from upstream, and it never comes. */
  public static final MessageType FNPOpennetCompletedTimeout =
      new MessageType("FNPOpennetCompletedTimeout", PRIORITY_HIGH);

  static {
    FNPOpennetCompletedTimeout.addField(UID, Long.class);
  }

  /**
   * Creates an {@code FNPOpennetCompletedTimeout} when the expected transfer or completion never
   * arrived.
   *
   * @param uid Original request identifier.
   * @return Initialized message.
   */
  public static Message createFNPOpennetCompletedTimeout(long uid) {
    Message msg = new Message(FNPOpennetCompletedTimeout);
    msg.set(UID, uid);
    return msg;
  }

  /**
   * Sent when a request completes and the data source wants to path fold. Starts a bulk data
   * transfer including the (padded) noderef.
   */
  public static final MessageType FNPOpennetConnectDestinationNew =
      new MessageType("FNPConnectDestinationNew", PRIORITY_UNSPECIFIED);

  static {
    FNPOpennetConnectDestinationNew.addField(UID, Long.class); // UID of original message chain
    FNPOpennetConnectDestinationNew.addField(TRANSFER_UID, Long.class); // UID of data transfer
    FNPOpennetConnectDestinationNew.addField(NODEREF_LENGTH, Integer.class); // Size of noderef
    FNPOpennetConnectDestinationNew.addField(
        PADDED_LENGTH, Integer.class); // Size of actual transfer i.e. padded length
  }

  /**
   * Creates an {@code FNPOpennetConnectDestinationNew} to initiate path folding with a noderef
   * transfer.
   *
   * @param uid Original request identifier.
   * @param transferUID Transfer identifier for the noderef payload.
   * @param noderefLength Unpadded noderef length in bytes.
   * @param paddedLength Padded transfer length in bytes.
   * @return Initialized message.
   */
  public static Message createFNPOpennetConnectDestinationNew(
      long uid, long transferUID, int noderefLength, int paddedLength) {
    Message msg = new Message(FNPOpennetConnectDestinationNew);
    msg.set(UID, uid);
    msg.set(TRANSFER_UID, transferUID);
    msg.set(NODEREF_LENGTH, noderefLength);
    msg.set(PADDED_LENGTH, paddedLength);
    return msg;
  }

  /**
   * Path folding response. Sent when the requestor wants to path fold and has received a noderef
   * from the data source. Starts a bulk data transfer including the (padded) noderef.
   */
  public static final MessageType FNPOpennetConnectReplyNew =
      new MessageType("FNPConnectReplyNew", PRIORITY_UNSPECIFIED);

  static {
    FNPOpennetConnectReplyNew.addField(UID, Long.class); // UID of original message chain
    FNPOpennetConnectReplyNew.addField(TRANSFER_UID, Long.class); // UID of data transfer
    FNPOpennetConnectReplyNew.addField(NODEREF_LENGTH, Integer.class); // Size of noderef
    FNPOpennetConnectReplyNew.addField(
        PADDED_LENGTH, Integer.class); // Size of actual transfer i.e. padded length
  }

  /**
   * Creates an {@code FNPOpennetConnectReplyNew} to accept path folding and start the transfer.
   *
   * @param uid Original request identifier.
   * @param transferUID Transfer identifier for the noderef payload.
   * @param noderefLength Unpadded noderef length in bytes.
   * @param paddedLength Padded transfer length in bytes.
   * @return Initialized message.
   */
  public static Message createFNPOpennetConnectReplyNew(
      long uid, long transferUID, int noderefLength, int paddedLength) {
    Message msg = new Message(FNPOpennetConnectReplyNew);
    msg.set(UID, uid);
    msg.set(TRANSFER_UID, transferUID);
    msg.set(NODEREF_LENGTH, noderefLength);
    msg.set(PADDED_LENGTH, paddedLength);
    return msg;
  }

  // Opennet announcement

  /**
   * Announcement request. Noderef is attached, will be transferred before anything else is done.
   */
  public static final MessageType FNPOpennetAnnounceRequest =
      new MessageType("FNPOpennetAnnounceRequest", PRIORITY_HIGH);

  static {
    FNPOpennetAnnounceRequest.addField(UID, Long.class);
    FNPOpennetAnnounceRequest.addField(TRANSFER_UID, Long.class);
    FNPOpennetAnnounceRequest.addField(NODEREF_LENGTH, Integer.class);
    FNPOpennetAnnounceRequest.addField(PADDED_LENGTH, Integer.class);
    FNPOpennetAnnounceRequest.addField(HTL, Short.class);
    FNPOpennetAnnounceRequest.addField(NEAREST_LOCATION, Double.class);
    FNPOpennetAnnounceRequest.addField(TARGET_LOCATION, Double.class);
  }

  /**
   * Creates an {@code FNPOpennetAnnounceRequest} with a padded noderef to be transferred first.
   *
   * @param request announce request metadata
   * @return Initialized message.
   */
  public static Message createFNPOpennetAnnounceRequest(OpennetAnnounceRequest request) {
    Message msg = new Message(FNPOpennetAnnounceRequest);
    msg.set(UID, request.uid());
    msg.set(TRANSFER_UID, request.transferUID());
    msg.set(NODEREF_LENGTH, request.noderefLength());
    msg.set(PADDED_LENGTH, request.paddedLength());
    msg.set(HTL, request.htl());
    msg.set(NEAREST_LOCATION, 0.0);
    msg.set(TARGET_LOCATION, request.target());
    return msg;
  }

  /**
   * Announcement reply. Noderef is attached and transferred; both nodes add the other. A single
   * request may result in many replies. When the announcement is done, we return a DataNotFound; if
   * we run into a dead-end, we return a RejectedLoop; if we can't accept it, RejectedOverload.
   */
  public static final MessageType FNPOpennetAnnounceReply =
      new MessageType("FNPOpennetAnnounceReply", PRIORITY_UNSPECIFIED);

  static {
    FNPOpennetAnnounceReply.addField(UID, Long.class);
    FNPOpennetAnnounceReply.addField(TRANSFER_UID, Long.class);
    FNPOpennetAnnounceReply.addField(NODEREF_LENGTH, Integer.class);
    FNPOpennetAnnounceReply.addField(PADDED_LENGTH, Integer.class);
  }

  /**
   * Creates an {@code FNPOpennetAnnounceReply} referencing an attached noderef transfer.
   *
   * @param uid Original request identifier.
   * @param transferUID Transfer identifier for the noderef payload.
   * @param noderefLength Unpadded noderef length in bytes.
   * @param paddedLength Padded transfer length in bytes.
   * @return Initialized message.
   */
  public static Message createFNPOpennetAnnounceReply(
      long uid, long transferUID, int noderefLength, int paddedLength) {
    Message msg = new Message(FNPOpennetAnnounceReply);
    msg.set(UID, uid);
    msg.set(TRANSFER_UID, transferUID);
    msg.set(NODEREF_LENGTH, noderefLength);
    msg.set(PADDED_LENGTH, paddedLength);
    return msg;
  }

  public static final MessageType FNPOpennetAnnounceCompleted =
      new MessageType("FNPOpennetAnnounceCompleted", PRIORITY_UNSPECIFIED);

  static {
    FNPOpennetAnnounceCompleted.addField(UID, Long.class);
  }

  /** Creates an {@code FNPOpennetAnnounceCompleted} notification. */
  public static Message createFNPOpennetAnnounceCompleted(long uid) {
    Message msg = new Message(FNPOpennetAnnounceCompleted);
    msg.set(UID, uid);
    return msg;
  }

  /** Indicates that opennet functionality is disabled on the peer. */
  public static final MessageType FNPOpennetDisabled =
      new MessageType("FNPOpennetDisabled", PRIORITY_HIGH);

  static {
    FNPOpennetDisabled.addField(UID, Long.class);
  }

  /** Creates an {@code FNPOpennetDisabled} notification. */
  public static Message createFNPOpennetDisabled(long uid) {
    Message msg = new Message(FNPOpennetDisabled);
    msg.set(UID, uid);
    return msg;
  }

  /** Noderef was rejected during path folding; includes a rejection code. */
  public static final MessageType FNPOpennetNoderefRejected =
      new MessageType("FNPOpennetNoderefRejected", PRIORITY_HIGH);

  static {
    FNPOpennetNoderefRejected.addField(UID, Long.class);
    FNPOpennetNoderefRejected.addField(REJECT_CODE, Integer.class);
  }

  /**
   * Creates an {@code FNPOpennetNoderefRejected} with a reason code.
   *
   * @param uid Original request identifier.
   * @param rejectCode One of the {@code NODEREF_REJECTED_*} constants.
   * @return Initialized message.
   */
  public static Message createFNPOpennetNoderefRejected(long uid, int rejectCode) {
    Message msg = new Message(FNPOpennetNoderefRejected);
    msg.set(UID, uid);
    msg.set(REJECT_CODE, rejectCode);
    return msg;
  }

  /** Returns a human-readable description for an opennet noderef rejection code. */
  public static String getOpennetRejectedCode(int x) {
    return switch (x) {
      case NODEREF_REJECTED_TOO_BIG -> "Too big";
      case NODEREF_REJECTED_REAL_BIGGER_THAN_PADDED -> "Real length bigger than padded length";
      case NODEREF_REJECTED_TRANSFER_FAILED -> "Transfer failed";
      case NODEREF_REJECTED_INVALID -> "Invalid noderef";
      default -> "Unknown rejection code " + x;
    };
  }

  public static final int NODEREF_REJECTED_TOO_BIG = 1;
  public static final int NODEREF_REJECTED_REAL_BIGGER_THAN_PADDED = 2;
  public static final int NODEREF_REJECTED_TRANSFER_FAILED = 3;
  public static final int NODEREF_REJECTED_INVALID = 4;

  // Legacy message retained; evaluate removal in a future cleanup.

  /** Announcement declined: peer is not accepting new opennet links. */
  public static final MessageType FNPOpennetAnnounceNodeNotWanted =
      new MessageType("FNPOpennetAnnounceNodeNotWanted", PRIORITY_LOW);

  static {
    FNPOpennetAnnounceNodeNotWanted.addField(UID, Long.class);
  }

  public static Message createFNPOpennetAnnounceNodeNotWanted(long uid) {
    Message msg = new Message(FNPOpennetAnnounceNodeNotWanted);
    msg.set(UID, uid);
    return msg;
  }

  // Key offers (ULPRs)

  /** Offer a key (ULPR) out-of-band prior to a get. */
  public static final MessageType FNPOfferKey = new MessageType("FNPOfferKey", PRIORITY_LOW);

  static {
    FNPOfferKey.addField(KEY, Key.class);
    FNPOfferKey.addField(OFFER_AUTHENTICATOR, ShortBuffer.class);
  }

  /**
   * Creates an {@code FNPOfferKey} with a keyed authenticator.
   *
   * @param key Offered key.
   * @param authenticator Authenticator bytes.
   * @return Initialized message.
   */
  public static Message createFNPOfferKey(Key key, byte[] authenticator) {
    Message msg = new Message(FNPOfferKey);
    msg.set(KEY, key);
    msg.set(OFFER_AUTHENTICATOR, new ShortBuffer(authenticator));
    return msg;
  }

  // Short timeout; priority choice is explicit below.
  public static final MessageType FNPGetOfferedKey =
      new MessageType("FNPGetOfferedKey", PRIORITY_LOW);

  static {
    FNPGetOfferedKey.addField(KEY, Key.class);
    FNPGetOfferedKey.addField(OFFER_AUTHENTICATOR, ShortBuffer.class);
    FNPGetOfferedKey.addField(NEED_PUB_KEY, Boolean.class);
    FNPGetOfferedKey.addField(UID, Long.class);
  }

  /**
   * Requests data for a previously offered key.
   *
   * @param key Key to fetch.
   * @param authenticator Authenticator matching the offer.
   * @param needPubkey Whether a public key should be returned when applicable.
   * @param uid Request identifier.
   * @return Initialized message.
   */
  public static Message createFNPGetOfferedKey(
      Key key, byte[] authenticator, boolean needPubkey, long uid) {
    Message msg = new Message(FNPGetOfferedKey);
    msg.set(KEY, key);
    msg.set(OFFER_AUTHENTICATOR, new ShortBuffer(authenticator));
    msg.set(NEED_PUB_KEY, needPubkey);
    msg.set(UID, uid);
    return msg;
  }

  // Permanently rejected. {@code FNPRejectedOverload} is temporary.
  public static final MessageType FNPGetOfferedKeyInvalid =
      new MessageType("FNPGetOfferedKeyInvalid", PRIORITY_HIGH);

  static { // short timeout
    FNPGetOfferedKeyInvalid.addField(UID, Long.class);
    FNPGetOfferedKeyInvalid.addField(REASON, Short.class);
  }

  /**
   * Creates an {@code FNPGetOfferedKeyInvalid} with a reason code.
   *
   * @param uid Request identifier.
   * @param reason One of the {@code GET_OFFERED_KEY_REJECTED_*} constants.
   * @return Initialized message.
   */
  public static Message createFNPGetOfferedKeyInvalid(long uid, short reason) {
    Message msg = new Message(FNPGetOfferedKeyInvalid);
    msg.set(UID, uid);
    msg.set(REASON, reason);
    return msg;
  }

  public static final short GET_OFFERED_KEY_REJECTED_BAD_AUTHENTICATOR = 1;
  public static final short GET_OFFERED_KEY_REJECTED_NO_KEY = 2;

  /** Link-level ping for reachability/latency checks. */
  public static final MessageType FNPPing = new MessageType("FNPPing", PRIORITY_HIGH);

  static {
    FNPPing.addField(PING_SEQNO, Integer.class);
  }

  /**
   * Creates a ping with a sequence number echoed by {@code FNPPong}.
   *
   * @param seqNo Sequence number.
   * @return Initialized message.
   */
  public static Message createFNPPing(int seqNo) {
    Message msg = new Message(FNPPing);
    msg.set(PING_SEQNO, seqNo);
    return msg;
  }

  /** Ping response echoing the sequence number. */
  public static final MessageType FNPPong = new MessageType("FNPPong", PRIORITY_HIGH);

  static {
    FNPPong.addField(PING_SEQNO, Integer.class);
  }

  /**
   * Creates a pong echoing the sequence number from a ping.
   *
   * @param seqNo Sequence number.
   * @return Initialized message.
   */
  public static Message createFNPPong(int seqNo) {
    Message msg = new Message(FNPPong);
    msg.set(PING_SEQNO, seqNo);
    return msg;
  }

  /** Reply containing routing-hints metrics gathered during a probe. */
  public static final MessageType FNPRHProbeReply =
      new MessageType("FNPRHProbeReply", PRIORITY_UNSPECIFIED);

  static {
    FNPRHProbeReply.addField(UID, Long.class);
    FNPRHProbeReply.addField(NEAREST_LOCATION, Double.class);
    FNPRHProbeReply.addField(BEST_LOCATION, Double.class);
    FNPRHProbeReply.addField(COUNTER, Short.class);
    FNPRHProbeReply.addField(UNIQUE_COUNTER, Short.class);
    FNPRHProbeReply.addField(LINEAR_COUNTER, Short.class);
  }

  /**
   * Creates an {@code FNPRHProbeReply}.
   *
   * @param uid Probe identifier.
   * @param nearest Nearest known location.
   * @param best Best known location.
   * @param counter General counter value.
   * @param uniqueCounter Distinct path count (semantics implementation-defined).
   * @param linearCounter Linearized counter (semantics implementation-defined).
   * @return Initialized message.
   */
  public static Message createFNPRHProbeReply(
      long uid,
      double nearest,
      double best,
      short counter,
      short uniqueCounter,
      short linearCounter) {
    Message msg = new Message(FNPRHProbeReply);
    msg.set(UID, uid);
    msg.set(NEAREST_LOCATION, nearest);
    msg.set(BEST_LOCATION, best);
    msg.set(COUNTER, counter);
    msg.set(UNIQUE_COUNTER, uniqueCounter);
    msg.set(LINEAR_COUNTER, linearCounter);
    return msg;
  }

  public static final MessageType ProbeRequest = new MessageType("ProbeRequest", PRIORITY_HIGH);

  static {
    ProbeRequest.addField(HTL, Byte.class);
    ProbeRequest.addField(UID, Long.class);
    ProbeRequest.addField(TYPE, Byte.class);
  }

  /**
   * Constructs a probe request.
   *
   * @param htl hopsToLive: hops until result is requested.
   * @param uid Probe identifier: should be unique.
   * @return Message with requested attributes.
   */
  public static Message createProbeRequest(byte htl, long uid, Type type) {
    Message msg = new Message(ProbeRequest);
    msg.set(HTL, htl);
    msg.set(UID, uid);
    msg.set(TYPE, type.code);
    return msg;
  }

  public static final MessageType ProbeError = new MessageType("ProbeError", PRIORITY_HIGH);

  static {
    ProbeError.addField(UID, Long.class);
    ProbeError.addField(TYPE, Byte.class);
  }

  /**
   * Creates a probe response which indicates there was an error.
   *
   * @param uid Probe identifier.
   * @param error The type of error that occurred. Can be one of Probe.ProbeError.
   * @return Message with the requested attributes.
   */
  public static Message createProbeError(long uid, Error error) {
    Message msg = new Message(ProbeError);
    msg.set(UID, uid);
    msg.set(TYPE, error.code);
    return msg;
  }

  public static final MessageType ProbeRefused = new MessageType("ProbeRefused", PRIORITY_HIGH);

  static {
    ProbeRefused.addField(DMT.UID, Long.class);
  }

  /**
   * Creates a probe response which indicates that the endpoint opted not to respond with the
   * requested result.
   *
   * @param uid Probe identifier.
   * @return Message with the requested attribute.
   */
  public static Message createProbeRefused(long uid) {
    Message msg = new Message(ProbeRefused);
    msg.set(UID, uid);
    return msg;
  }

  public static final MessageType ProbeBandwidth = new MessageType("ProbeBandwidth", PRIORITY_HIGH);

  static {
    ProbeBandwidth.addField(UID, Long.class);
    ProbeBandwidth.addField(OUTPUT_BANDWIDTH_UPPER_LIMIT, Float.class);
  }

  /**
   * Creates a probe response to a query for bandwidth limits.
   *
   * @param uid Probe identifier.
   * @param limit Endpoint output bandwidth limit in KiB per second.
   * @return Message with requested attributes.
   */
  public static Message createProbeBandwidth(long uid, float limit) {
    Message msg = new Message(ProbeBandwidth);
    msg.set(UID, uid);
    msg.set(OUTPUT_BANDWIDTH_UPPER_LIMIT, limit);
    return msg;
  }

  public static final MessageType ProbeBuild = new MessageType("ProbeBuild", PRIORITY_HIGH);

  static {
    ProbeBuild.addField(UID, Long.class);
    ProbeBuild.addField(BUILD, Integer.class);
  }

  /**
   * Creates a probe response to a query for build.
   *
   * @param uid Probe identifier.
   * @param build Endpoint build of Freenet.
   * @return Message with requested attributes.
   */
  public static Message createProbeBuild(long uid, int build) {
    Message msg = new Message(ProbeBuild);
    msg.set(UID, uid);
    msg.set(BUILD, build);
    return msg;
  }

  public static final MessageType ProbeIdentifier =
      new MessageType("ProbeIdentifier", PRIORITY_HIGH);

  static {
    ProbeIdentifier.addField(UID, Long.class);
    ProbeIdentifier.addField(PROBE_IDENTIFIER, Long.class);
    ProbeIdentifier.addField(UPTIME_PERCENT, Byte.class);
  }

  /**
   * Creates a probe response to a query for identifier.
   *
   * @param uid Probe UID.
   * @param probeIdentifierValue Endpoint identifier.
   * @param uptimePercentage 7-day uptime percentage.
   * @return Message with requested attributes.
   */
  public static Message createProbeIdentifier(
      long uid, long probeIdentifierValue, byte uptimePercentage) {
    Message msg = new Message(ProbeIdentifier);
    msg.set(UID, uid);
    msg.set(PROBE_IDENTIFIER, probeIdentifierValue);
    msg.set(UPTIME_PERCENT, uptimePercentage);
    return msg;
  }

  public static final MessageType ProbeLinkLengths =
      new MessageType("ProbeLinkLengths", PRIORITY_HIGH);

  static {
    ProbeLinkLengths.addField(UID, Long.class);
    ProbeLinkLengths.addField(LINK_LENGTHS, float[].class);
  }

  /**
   * Creates a probe response to a query for link lengths.
   *
   * @param uid Probe identifier.
   * @param linkLengths Endpoint link lengths.
   * @return Message with requested attributes.
   */
  public static Message createProbeLinkLengths(long uid, float[] linkLengths) {
    Message msg = new Message(ProbeLinkLengths);
    msg.set(UID, uid);
    msg.set(LINK_LENGTHS, linkLengths);
    return msg;
  }

  public static final MessageType ProbeLocation = new MessageType("ProbeLocation", PRIORITY_HIGH);

  static {
    ProbeLocation.addField(UID, Long.class);
    ProbeLocation.addField(LOCATION, Float.class);
  }

  /**
   * Creates a probe response to a query for location.
   *
   * @param uid Probe identifier.
   * @param location Endpoint location.
   * @return Message with the requested attributes.
   */
  public static Message createProbeLocation(long uid, float location) {
    Message msg = new Message(ProbeLocation);
    msg.set(UID, uid);
    msg.set(LOCATION, location);
    return msg;
  }

  public static final MessageType ProbeStoreSize = new MessageType("ProbeStoreSize", PRIORITY_HIGH);

  static {
    ProbeStoreSize.addField(UID, Long.class);
    ProbeStoreSize.addField(STORE_SIZE, Float.class);
  }

  /**
   * Creates a probe response to a query for store size.
   *
   * @param uid Probe identifier.
   * @param storeSize Endpoint store size in GiB multiplied by Gaussian noise.
   * @return Message with requested attributes.
   */
  public static Message createProbeStoreSize(long uid, float storeSize) {
    Message msg = new Message(ProbeStoreSize);
    msg.set(UID, uid);
    msg.set(STORE_SIZE, storeSize);
    return msg;
  }

  public static final MessageType ProbeUptime = new MessageType("ProbeUptime", PRIORITY_HIGH);

  static {
    ProbeUptime.addField(UID, Long.class);
    ProbeUptime.addField(UPTIME_PERCENT, Float.class);
  }

  /**
   * Creates a probe response to a query for uptime.
   *
   * @param uid Probe identifier.
   * @param uptimePercent Percent of the requested period (48 hours or 7 days) which the endpoint
   *     was online.
   * @return Message with requested attributes.
   */
  public static Message createProbeUptime(long uid, float uptimePercent) {
    Message msg = new Message(ProbeUptime);
    msg.set(UID, uid);
    msg.set(UPTIME_PERCENT, uptimePercent);
    return msg;
  }

  public static final MessageType ProbeRejectStats =
      new MessageType("ProbeRejectStats", PRIORITY_HIGH);

  static {
    ProbeRejectStats.addField(UID, Long.class);
    ProbeRejectStats.addField(REJECT_STATS, ShortBuffer.class);
  }

  public static Message createProbeRejectStats(long uid, byte[] rejectStats) {
    Message msg = new Message(ProbeRejectStats);
    msg.set(UID, uid);
    msg.set(REJECT_STATS, new ShortBuffer(rejectStats));
    return msg;
  }

  /** Divide output bandwidth limit by this to get bandwidth class. */
  static final int CAPACITY_USAGE_MULTIPLIER = 10 * 1024;

  /** Maximum value of bandwidth class */
  static final byte CAPACITY_USAGE_MAX = 10;

  /** Minimum value of bandwidth class */
  static final byte CAPACITY_USAGE_MIN = 1;

  public static final MessageType ProbeOverallBulkOutputCapacityUsage =
      new MessageType("ProbeOverallBulkOutputCapacityUsage", PRIORITY_HIGH);

  static {
    ProbeOverallBulkOutputCapacityUsage.addField(UID, Long.class); // UID for the probe
    ProbeOverallBulkOutputCapacityUsage.addField(
        OUTPUT_BANDWIDTH_CLASS, Byte.class); // Approximate bandwidth, severely truncated.
    ProbeOverallBulkOutputCapacityUsage.addField(
        CAPACITY_USAGE, Float.class); // Noisy capacity usage.
  }

  /**
   * Coarsens a bandwidth limit to a small ordinal class for probes.
   *
   * @param bandwidthLimit Output bandwidth limit in bytes per second.
   * @return A class in the range [{@link #CAPACITY_USAGE_MIN}, {@link #CAPACITY_USAGE_MAX}].
   */
  public static byte bandwidthClassForCapacityUsage(int bandwidthLimit) {
    bandwidthLimit /= CAPACITY_USAGE_MULTIPLIER;
    bandwidthLimit = Math.min(bandwidthLimit, CAPACITY_USAGE_MAX);
    return (byte) Math.max(bandwidthLimit, CAPACITY_USAGE_MIN);
  }

  /**
   * Creates a probe message with an approximate output bandwidth class and a noisy capacity usage
   * estimate.
   *
   * @param uid Probe identifier.
   * @param outputBandwidthClass Ordinal class from {@link #bandwidthClassForCapacityUsage(int)}.
   * @param capacityUsage Noisy capacity usage (unit-less fraction).
   * @return Initialized message.
   */
  public static Message createProbeOverallBulkOutputCapacityUsage(
      long uid, byte outputBandwidthClass, float capacityUsage) {
    Message msg = new Message(ProbeOverallBulkOutputCapacityUsage);
    msg.set(UID, uid);
    msg.set(OUTPUT_BANDWIDTH_CLASS, outputBandwidthClass);
    msg.set(CAPACITY_USAGE, capacityUsage);
    return msg;
  }

  /** Start of a four-phase location swap handshake. */
  public static final MessageType FNPSwapRequest = new MessageType("FNPSwapRequest", PRIORITY_HIGH);

  static {
    FNPSwapRequest.addField(UID, Long.class);
    FNPSwapRequest.addField(HASH, ShortBuffer.class);
    FNPSwapRequest.addField(HTL, Integer.class);
  }

  /**
   * Creates an {@code FNPSwapRequest}.
   *
   * @param uid Swap identifier.
   * @param buf Hash or token bytes.
   * @param htl Hops-to-live.
   * @return Initialized message.
   */
  public static Message createFNPSwapRequest(long uid, byte[] buf, int htl) {
    Message msg = new Message(FNPSwapRequest);
    msg.set(UID, uid);
    msg.set(HASH, new ShortBuffer(buf));
    msg.set(HTL, htl);
    return msg;
  }

  /** Swap rejected; aborts the handshake. */
  public static final MessageType FNPSwapRejected =
      new MessageType("FNPSwapRejected", PRIORITY_HIGH);

  static {
    FNPSwapRejected.addField(UID, Long.class);
  }

  /**
   * Creates an {@code FNPSwapRejected}.
   *
   * @param uid Swap identifier.
   * @return Initialized message.
   */
  public static Message createFNPSwapRejected(long uid) {
    Message msg = new Message(FNPSwapRejected);
    msg.set(UID, uid);
    return msg;
  }

  /** Swap reply carrying a hash/token. */
  public static final MessageType FNPSwapReply = new MessageType("FNPSwapReply", PRIORITY_HIGH);

  static {
    FNPSwapReply.addField(UID, Long.class);
    FNPSwapReply.addField(HASH, ShortBuffer.class);
  }

  /**
   * Creates an {@code FNPSwapReply}.
   *
   * @param uid Swap identifier.
   * @param buf Hash or token bytes.
   * @return Initialized message.
   */
  public static Message createFNPSwapReply(long uid, byte[] buf) {
    Message msg = new Message(FNPSwapReply);
    msg.set(UID, uid);
    msg.set(HASH, new ShortBuffer(buf));
    return msg;
  }

  /** Commit step of the swap handshake, carrying final parameters. */
  public static final MessageType FNPSwapCommit = new MessageType("FNPSwapCommit", PRIORITY_HIGH);

  static {
    FNPSwapCommit.addField(UID, Long.class);
    FNPSwapCommit.addField(DATA, ShortBuffer.class);
  }

  /**
   * Creates an {@code FNPSwapCommit}.
   *
   * @param uid Swap identifier.
   * @param buf Commit data bytes.
   * @return Initialized message.
   */
  public static Message createFNPSwapCommit(long uid, byte[] buf) {
    Message msg = new Message(FNPSwapCommit);
    msg.set(UID, uid);
    msg.set(DATA, new ShortBuffer(buf));
    return msg;
  }

  /** Final state of the swap; both sides complete. */
  public static final MessageType FNPSwapComplete =
      new MessageType("FNPSwapComplete", PRIORITY_HIGH);

  static {
    FNPSwapComplete.addField(UID, Long.class);
    FNPSwapComplete.addField(DATA, ShortBuffer.class);
  }

  /**
   * Creates an {@code FNPSwapComplete}.
   *
   * @param uid Swap identifier.
   * @param buf Completion data bytes.
   * @return Initialized message.
   */
  public static Message createFNPSwapComplete(long uid, byte[] buf) {
    Message msg = new Message(FNPSwapComplete);
    msg.set(UID, uid);
    msg.set(DATA, new ShortBuffer(buf));
    return msg;
  }

  /** Notifies peers of a location change and provides peer location hints. */
  public static final MessageType FNPLocChangeNotificationNew =
      new MessageType("FNPLocationChangeNotification2", PRIORITY_LOW);

  static {
    FNPLocChangeNotificationNew.addField(LOCATION, Double.class);
    FNPLocChangeNotificationNew.addField(PEER_LOCATIONS, ShortBuffer.class);
  }

  /**
   * Creates an {@code FNPLocChangeNotificationNew}.
   *
   * @param myLocation This node's new location.
   * @param locations Neighbor location hints.
   * @return Initialized message.
   */
  public static Message createFNPLocChangeNotificationNew(double myLocation, double[] locations) {
    Message msg = new Message(FNPLocChangeNotificationNew);
    ShortBuffer dst = new ShortBuffer(Fields.doublesToBytes(locations));
    msg.set(LOCATION, myLocation);
    msg.set(PEER_LOCATIONS, dst);

    return msg;
  }

  /** Routed ping targeting a location (used beyond direct neighbors). */
  public static final MessageType FNPRoutedPing = new MessageType("FNPRoutedPing", PRIORITY_LOW);

  static {
    FNPRoutedPing.addRoutedToNodeMessageFields();
    FNPRoutedPing.addField(COUNTER, Integer.class);
  }

  /**
   * Creates an {@code FNPRoutedPing} targeting a location.
   *
   * @param uid Request identifier.
   * @param targetLocation Target location in keyspace.
   * @param htl Hops-to-live.
   * @param counter Counter for correlation by caller.
   * @param nodeIdentity Identity bytes of the destination node.
   * @return Initialized message.
   */
  public static Message createFNPRoutedPing(
      long uid, double targetLocation, short htl, int counter, byte[] nodeIdentity) {
    Message msg = new Message(FNPRoutedPing);
    msg.setRoutedToNodeFields(uid, targetLocation, htl, nodeIdentity);
    msg.set(COUNTER, counter);
    return msg;
  }

  /** Reply to a routed ping. */
  public static final MessageType FNPRoutedPong = new MessageType("FNPRoutedPong", PRIORITY_LOW);

  static {
    FNPRoutedPong.addField(UID, Long.class);
    FNPRoutedPong.addField(COUNTER, Integer.class);
  }

  /**
   * Creates an {@code FNPRoutedPong} reply.
   *
   * @param uid Request identifier.
   * @param counter Counter echoed from the routed ping.
   * @return Initialized message.
   */
  public static Message createFNPRoutedPong(long uid, int counter) {
    Message msg = new Message(FNPRoutedPong);
    msg.set(UID, uid);
    msg.set(COUNTER, counter);
    return msg;
  }

  /** Routed request was rejected; includes remaining HTL. */
  public static final MessageType FNPRoutedRejected =
      new MessageType("FNPRoutedRejected", PRIORITY_UNSPECIFIED);

  static {
    FNPRoutedRejected.addField(UID, Long.class);
    FNPRoutedRejected.addField(HTL, Short.class);
  }

  /**
   * Creates an {@code FNPRoutedRejected}.
   *
   * @param uid Request identifier.
   * @param htl Remaining hops-to-live.
   * @return Initialized message.
   */
  public static Message createFNPRoutedRejected(long uid, short htl) {
    Message msg = new Message(FNPRoutedRejected);
    msg.set(UID, uid);
    msg.set(HTL, htl);
    return msg;
  }

  /** Announces a detected external address for the remote peer. */
  public static final MessageType FNPDetectedIPAddress =
      new MessageType("FNPDetectedIPAddress", PRIORITY_HIGH);

  static {
    FNPDetectedIPAddress.addField(EXTERNAL_ADDRESS, Peer.class);
  }

  /**
   * Creates an {@code FNPDetectedIPAddress} containing a detected external address.
   *
   * @param peer Peering information with external address.
   * @return Initialized message.
   */
  public static Message createFNPDetectedIPAddress(Peer peer) {
    Message msg = new Message(FNPDetectedIPAddress);
    msg.set(EXTERNAL_ADDRESS, peer);
    return msg;
  }

  /** Wall-clock time synchronization hint. */
  public static final MessageType FNPTime = new MessageType("FNPTime", PRIORITY_HIGH);

  static {
    FNPTime.addField(TIME, Long.class);
  }

  /**
   * Creates an {@code FNPTime} message.
   *
   * @param time Time in milliseconds since epoch.
   * @return Initialized message.
   */
  public static Message createFNPTime(long time) {
    Message msg = new Message(FNPTime);
    msg.set(TIME, time);
    return msg;
  }

  /** Uptime percentage over a short window for visibility sharing. */
  public static final MessageType FNPUptime = new MessageType("FNPUptime", PRIORITY_LOW);

  static {
    FNPUptime.addField(UPTIME_PERCENT_48H, Byte.class);
  }

  /**
   * Creates an {@code FNPUptime} message.
   *
   * @param uptimePercent Percent uptime over the recent window.
   * @return Initialized message.
   */
  public static Message createFNPUptime(byte uptimePercent) {
    Message msg = new Message(FNPUptime);
    msg.set(UPTIME_PERCENT_48H, uptimePercent);
    return msg;
  }

  /** Visibility setting toward friends (link-level trust/visibility). */
  public static final MessageType FNPVisibility = new MessageType("FNPVisibility", PRIORITY_HIGH);

  static {
    FNPVisibility.addField(FRIEND_VISIBILITY, Short.class);
  }

  /**
   * Creates an {@code FNPVisibility} message.
   *
   * @param visibility Visibility code (implementation-defined).
   * @return Initialized message.
   */
  public static Message createFNPVisibility(short visibility) {
    Message msg = new Message(FNPVisibility);
    msg.set(FRIEND_VISIBILITY, visibility);
    return msg;
  }

  // Legacy message retained for compatibility.
  public static final MessageType FNPSentPackets = new MessageType("FNPSentPackets", PRIORITY_HIGH);

  static {
    FNPSentPackets.addField(TIME_DELTAS, ShortBuffer.class);
    FNPSentPackets.addField(HASHES, ShortBuffer.class);
    FNPSentPackets.addField(TIME, Long.class);
  }

  /** Empty no-op message used as a keepalive or placeholder. */
  public static final MessageType FNPVoid = new MessageType("FNPVoid", PRIORITY_LOW, false, true);

  public static Message createFNPVoid() {
    return new Message(FNPVoid);
  }

  /** Informs peer about disconnect intent and optional cleanup behavior. */
  public static final MessageType FNPDisconnect = new MessageType("FNPDisconnect", PRIORITY_HIGH);

  static {
    // If true, remove from active routing table, likely to be down for a while.
    // Otherwise, just dump all current connection state and keep trying to connect.
    FNPDisconnect.addField(REMOVE, Boolean.class);
    // If true, purge all references to this node. Otherwise, we can keep the node
    // around in secondary tables etc. in order to more easily reconnect later.
    // (Mostly used on opennet)
    FNPDisconnect.addField(PURGE, Boolean.class);
    // Parting message, may be empty. A SimpleFieldSet in exactly the same format
    // as an N2NTM.
    FNPDisconnect.addField(NODE_TO_NODE_MESSAGE_TYPE, Integer.class);
    FNPDisconnect.addField(NODE_TO_NODE_MESSAGE_DATA, ShortBuffer.class);
  }

  /**
   * Creates an {@code FNPDisconnect} message with optional purge instructions and a parting note.
   *
   * @param remove Remove from active routing table if {@code true}.
   * @param purge Purge references to the node if {@code true}.
   * @param messageType Parting note type (node-to-node message type).
   * @param messageData Parting note payload; may be empty.
   * @return Initialized message.
   */
  public static Message createFNPDisconnect(
      boolean remove, boolean purge, int messageType, ShortBuffer messageData) {
    Message msg = new Message(FNPDisconnect);
    msg.set(REMOVE, remove);
    msg.set(PURGE, purge);
    msg.set(NODE_TO_NODE_MESSAGE_TYPE, messageType);
    msg.set(NODE_TO_NODE_MESSAGE_DATA, messageData);
    return msg;
  }

  // Update over mandatory. Not strictly part of FNP. Only goes between nodes at the link
  // level, and will be sent, and parsed, even if the node is out of date. Should be stable
  // long-term.

  /**
   * Announces core update metadata (keys, versions, and recent revocation fetch state) at link
   * level.
   */
  public static final MessageType CryptadUOMAnnouncement =
      new MessageType("CryptadUOMAnnouncement", PRIORITY_LOW);

  static {
    CryptadUOMAnnouncement.addField(MAIN_JAR_KEY, String.class);
    CryptadUOMAnnouncement.addField(REVOCATION_KEY, String.class);
    CryptadUOMAnnouncement.addField(HAVE_REVOCATION_KEY, Boolean.class);
    CryptadUOMAnnouncement.addField(MAIN_JAR_VERSION, Integer.class);
    // Last time (ms ago) we had 3 DNFs in a row on the revocation checker.
    CryptadUOMAnnouncement.addField(REVOCATION_KEY_TIME_LAST_TRIED, Long.class);
    // Number of DNFs so far this time.
    CryptadUOMAnnouncement.addField(REVOCATION_KEY_DNF_COUNT, Integer.class);
    // For convenience, may change
    CryptadUOMAnnouncement.addField(REVOCATION_KEY_FILE_LENGTH, Long.class);
    CryptadUOMAnnouncement.addField(MAIN_JAR_FILE_LENGTH, Long.class);
    CryptadUOMAnnouncement.addField(PING_TIME, Integer.class);
    CryptadUOMAnnouncement.addField(BWLIMIT_DELAY_TIME, Integer.class);
  }

  /** Fluent builder for {@link #CryptadUOMAnnouncement} messages. */
  public static final class UOMAnnouncementBuilder {
    private String mainKey;
    private String revocationKey;
    private boolean haveRevocation;
    private int mainJarVersion;
    private long timeLastTriedRevocationFetch;
    private int revocationDNFCount;
    private long revocationKeyLength;
    private long mainJarLength;
    private int pingTime;
    private int bwlimitDelayTime;

    public UOMAnnouncementBuilder mainKey(String v) {
      this.mainKey = v;
      return this;
    }

    public UOMAnnouncementBuilder revocationKey(String v) {
      this.revocationKey = v;
      return this;
    }

    public UOMAnnouncementBuilder haveRevocation(boolean v) {
      this.haveRevocation = v;
      return this;
    }

    public UOMAnnouncementBuilder mainJarVersion(int v) {
      this.mainJarVersion = v;
      return this;
    }

    public UOMAnnouncementBuilder timeLastTriedRevocationFetch(long v) {
      this.timeLastTriedRevocationFetch = v;
      return this;
    }

    public UOMAnnouncementBuilder revocationDNFCount(int v) {
      this.revocationDNFCount = v;
      return this;
    }

    public UOMAnnouncementBuilder revocationKeyLength(long v) {
      this.revocationKeyLength = v;
      return this;
    }

    public UOMAnnouncementBuilder mainJarLength(long v) {
      this.mainJarLength = v;
      return this;
    }

    public UOMAnnouncementBuilder pingTime(int v) {
      this.pingTime = v;
      return this;
    }

    public UOMAnnouncementBuilder bwlimitDelayTime(int v) {
      this.bwlimitDelayTime = v;
      return this;
    }

    public Message build() {
      Message msg = new Message(CryptadUOMAnnouncement);
      msg.set(MAIN_JAR_KEY, mainKey);
      msg.set(REVOCATION_KEY, revocationKey);
      msg.set(HAVE_REVOCATION_KEY, haveRevocation);
      msg.set(MAIN_JAR_VERSION, mainJarVersion);
      msg.set(REVOCATION_KEY_TIME_LAST_TRIED, timeLastTriedRevocationFetch);
      msg.set(REVOCATION_KEY_DNF_COUNT, revocationDNFCount);
      msg.set(REVOCATION_KEY_FILE_LENGTH, revocationKeyLength);
      msg.set(MAIN_JAR_FILE_LENGTH, mainJarLength);
      msg.set(PING_TIME, pingTime);
      msg.set(BWLIMIT_DELAY_TIME, bwlimitDelayTime);
      return msg;
    }
  }

  /** Requests the revocation file referenced in the announcement. */
  public static final MessageType CryptadUOMRequestRevocation =
      new MessageType("CryptadUOMRequestRevocation", PRIORITY_HIGH);

  static {
    CryptadUOMRequestRevocation.addField(UID, Long.class);
  }

  /**
   * Creates a {@code CryptadUOMRequestRevocation} using {@code uid} as the transfer identifier.
   *
   * @param uid Transfer identifier.
   * @return Initialized message.
   */
  public static Message createUOMRequestRevocation(long uid) {
    Message msg = new Message(CryptadUOMRequestRevocation);
    msg.set(UID, uid);
    return msg;
  }

  // Used by new UOM.
  /** Requests the main JAR referenced in the announcement. */
  public static final MessageType CryptadUOMRequestMainJar =
      new MessageType("CryptadUOMRequestMainJar", PRIORITY_LOW);

  static {
    CryptadUOMRequestMainJar.addField(UID, Long.class);
  }

  /**
   * Creates a {@code CryptadUOMRequestMainJar} using {@code uid} as the transfer identifier.
   *
   * @param uid Transfer identifier.
   * @return Initialized message.
   */
  public static Message createUOMRequestMainJar(long uid) {
    Message msg = new Message(CryptadUOMRequestMainJar);
    msg.set(UID, uid);
    return msg;
  }

  /** Announces that a revocation file will be sent, with length and key. */
  public static final MessageType CryptadUOMSendingRevocation =
      new MessageType("CryptadUOMSendingRevocation", PRIORITY_HIGH);

  static {
    CryptadUOMSendingRevocation.addField(UID, Long.class);
    // Probably excessive, but lengths are always long's, and wasting a few bytes here
    // doesn't matter in the least, as it's very rarely called.
    CryptadUOMSendingRevocation.addField(FILE_LENGTH, Long.class);
    CryptadUOMSendingRevocation.addField(REVOCATION_KEY, String.class);
  }

  /**
   * Creates a {@code CryptadUOMSendingRevocation}.
   *
   * @param uid Transfer identifier.
   * @param length File length in bytes.
   * @param key Revocation key (URI string).
   * @return Initialized message.
   */
  public static Message createUOMSendingRevocation(long uid, long length, String key) {
    Message msg = new Message(CryptadUOMSendingRevocation);
    msg.set(UID, uid);
    msg.set(FILE_LENGTH, length);
    msg.set(REVOCATION_KEY, key);
    return msg;
  }

  // Used by new UOM. We need to distinguish them in NodeDispatcher.
  /** Announces that the main JAR will be sent, with length, key, and version. */
  public static final MessageType CryptadUOMSendingMainJar =
      new MessageType("CryptadUOMSendingMainJar", PRIORITY_LOW);

  static {
    CryptadUOMSendingMainJar.addField(UID, Long.class);
    CryptadUOMSendingMainJar.addField(FILE_LENGTH, Long.class);
    CryptadUOMSendingMainJar.addField(MAIN_JAR_KEY, String.class);
    CryptadUOMSendingMainJar.addField(MAIN_JAR_VERSION, Integer.class);
  }

  /**
   * Creates a {@code CryptadUOMSendingMainJar}.
   *
   * @param uid Transfer identifier.
   * @param length File length in bytes.
   * @param key Key (URI string) for the main JAR.
   * @param version Build version.
   * @return Initialized message.
   */
  public static Message createUOMSendingMainJar(long uid, long length, String key, int version) {
    Message msg = new Message(CryptadUOMSendingMainJar);
    msg.set(UID, uid);
    msg.set(FILE_LENGTH, length);
    msg.set(MAIN_JAR_KEY, key);
    msg.set(MAIN_JAR_VERSION, version);
    return msg;
  }

  /**
   * Used to fetch a file required for deploying an update. The client knows both the size and hash
   * of the file. If we don't want to send the data we should send an FNPBulkReceiveAborted,
   * otherwise we just send the data as a BulkTransmitter transfer.
   */
  public static final MessageType CryptadUOMFetchDependency =
      new MessageType("CryptadUOMFetchDependency", PRIORITY_LOW);

  static {
    CryptadUOMFetchDependency.addField(UID, Long.class); // This will be used for the transfer.
    CryptadUOMFetchDependency.addField(EXPECTED_HASH, ShortBuffer.class); // Fetch by hash
    CryptadUOMFetchDependency.addField(FILE_LENGTH, Long.class); // Length is known by both sides.
  }

  /**
   * Creates a {@code CryptadUOMFetchDependency} request.
   *
   * @param uid Transfer identifier.
   * @param hash Expected content hash.
   * @param length Expected file length in bytes.
   * @return Initialized message.
   */
  public static Message createUOMFetchDependency(long uid, byte[] hash, long length) {
    Message msg = new Message(CryptadUOMFetchDependency);
    msg.set(UID, uid);
    msg.set(EXPECTED_HASH, new ShortBuffer(hash));
    msg.set(FILE_LENGTH, length);
    return msg;
  }

  // Secondary messages (debug messages attached to primary messages)

  /** Secondary diagnostic message listing node UIDs relevant to a swap. */
  public static final MessageType FNPSwapNodeUIDs =
      new MessageType("FNPSwapNodeUIDs", PRIORITY_UNSPECIFIED);

  static {
    FNPSwapNodeUIDs.addField(NODE_UIDS, ShortBuffer.class);
  }

  /**
   * Creates an {@code FNPSwapNodeUIDs} diagnostic message.
   *
   * @param uids Node UID list.
   * @return Initialized message.
   */
  public static Message createFNPSwapLocations(long[] uids) {
    Message msg = new Message(FNPSwapNodeUIDs);
    msg.set(NODE_UIDS, new ShortBuffer(Fields.longsToBytes(uids)));
    return msg;
  }

  // More permanent secondary messages (should perhaps be replaced by new main messages when stable)

  /** Diagnostics: best alternative routes that were not selected. */
  public static final MessageType FNPBestRoutesNotTaken =
      new MessageType("FNPBestRoutesNotTaken", PRIORITY_UNSPECIFIED);

  static {
    // Maybe this should be some sort of typed array?
    // It's just a bunch of double's anyway.
    FNPBestRoutesNotTaken.addField(BEST_LOCATIONS_NOT_VISITED, ShortBuffer.class);
  }

  /**
   * Creates {@code FNPBestRoutesNotTaken} with serialized locations.
   *
   * @param locs Serialized double array.
   * @return Initialized message.
   */
  public static Message createFNPBestRoutesNotTaken(byte[] locs) {
    Message msg = new Message(FNPBestRoutesNotTaken);
    msg.set(BEST_LOCATIONS_NOT_VISITED, new ShortBuffer(locs));
    return msg;
  }

  /** Convenience overload that serializes {@code double[]} to bytes. */
  public static Message createFNPBestRoutesNotTaken(double[] locs) {
    return createFNPBestRoutesNotTaken(Fields.doublesToBytes(locs));
  }

  /** Convenience overload for {@code Double[]} collections. */
  public static Message createFNPBestRoutesNotTaken(Double[] doubles) {
    double[] locs = new double[doubles.length];
    for (int i = 0; i < locs.length; i++) {
      locs[i] = doubles[i];
    }
    return createFNPBestRoutesNotTaken(locs);
  }

  /** Advertises whether routing of requests is currently enabled. */
  public static final MessageType FNPRoutingStatus =
      new MessageType("FNPRoutingStatus", PRIORITY_HIGH);

  static {
    FNPRoutingStatus.addField(ROUTING_ENABLED, Boolean.class);
  }

  /**
   * Creates an {@code FNPRoutingStatus} message.
   *
   * @param routeRequests {@code true} to enable routing; {@code false} to disable.
   * @return Initialized message.
   */
  public static Message createRoutingStatus(boolean routeRequests) {
    Message msg = new Message(FNPRoutingStatus);
    msg.set(ROUTING_ENABLED, routeRequests);

    return msg;
  }

  /** Sub-insert hint: allow fork when cacheable (tunable control for insert behavior). */
  public static final MessageType FNPSubInsertForkControl =
      new MessageType("FNPSubInsertForkControl", PRIORITY_HIGH);

  static {
    FNPSubInsertForkControl.addField(ENABLE_INSERT_FORK_WHEN_CACHEABLE, Boolean.class);
  }

  /**
   * Creates a {@code FNPSubInsertForkControl} hint.
   *
   * @param enableInsertForkWhenCacheable Enable fork when cacheable.
   * @return Initialized message.
   */
  public static Message createFNPSubInsertForkControl(boolean enableInsertForkWhenCacheable) {
    Message msg = new Message(FNPSubInsertForkControl);
    msg.set(ENABLE_INSERT_FORK_WHEN_CACHEABLE, enableInsertForkWhenCacheable);
    return msg;
  }

  /** Sub-insert hint: prefer insert over other options when possible. */
  public static final MessageType FNPSubInsertPreferInsert =
      new MessageType("FNPSubInsertPreferInsert", PRIORITY_HIGH);

  static {
    FNPSubInsertPreferInsert.addField(PREFER_INSERT, Boolean.class);
  }

  /**
   * Creates a {@code FNPSubInsertPreferInsert} hint.
   *
   * @param preferInsert Prefer insert when {@code true}.
   * @return Initialized message.
   */
  public static Message createFNPSubInsertPreferInsert(boolean preferInsert) {
    Message msg = new Message(FNPSubInsertPreferInsert);
    msg.set(PREFER_INSERT, preferInsert);
    return msg;
  }

  /** Sub-insert hint: ignore low backoff threshold. */
  public static final MessageType FNPSubInsertIgnoreLowBackoff =
      new MessageType("FNPSubInsertIgnoreLowBackoff", PRIORITY_HIGH);

  static {
    FNPSubInsertIgnoreLowBackoff.addField(IGNORE_LOW_BACKOFF, Boolean.class);
  }

  /**
   * Creates a {@code FNPSubInsertIgnoreLowBackoff} hint.
   *
   * @param ignoreLowBackoff Ignore low backoff when {@code true}.
   * @return Initialized message.
   */
  public static Message createFNPSubInsertIgnoreLowBackoff(boolean ignoreLowBackoff) {
    Message msg = new Message(FNPSubInsertIgnoreLowBackoff);
    msg.set(IGNORE_LOW_BACKOFF, ignoreLowBackoff);
    return msg;
  }

  /** Indicates that the preceding rejection is soft (retryable). */
  public static final MessageType FNPRejectIsSoft =
      new MessageType("FNPRejectIsSoft", PRIORITY_HIGH);

  /** Creates an {@code FNPRejectIsSoft} marker message. */
  public static Message createFNPRejectIsSoft() {
    return new Message(FNPRejectIsSoft);
  }

  // New load management

  public static final MessageType FNPPeerLoadStatusByte =
      new MessageType("FNPPeerLoadStatusByte", PRIORITY_HIGH, false, true);

  static {
    FNPPeerLoadStatusByte.addField(OTHER_TRANSFERS_OUT_CHK, Byte.class);
    FNPPeerLoadStatusByte.addField(OTHER_TRANSFERS_IN_CHK, Byte.class);
    FNPPeerLoadStatusByte.addField(OTHER_TRANSFERS_OUT_SSK, Byte.class);
    FNPPeerLoadStatusByte.addField(OTHER_TRANSFERS_IN_SSK, Byte.class);
    FNPPeerLoadStatusByte.addField(AVERAGE_TRANSFERS_OUT_PER_INSERT, Byte.class);
    FNPPeerLoadStatusByte.addField(OUTPUT_BANDWIDTH_LOWER_LIMIT, Integer.class);
    FNPPeerLoadStatusByte.addField(OUTPUT_BANDWIDTH_UPPER_LIMIT, Integer.class);
    FNPPeerLoadStatusByte.addField(OUTPUT_BANDWIDTH_PEER_LIMIT, Integer.class);
    FNPPeerLoadStatusByte.addField(INPUT_BANDWIDTH_LOWER_LIMIT, Integer.class);
    FNPPeerLoadStatusByte.addField(INPUT_BANDWIDTH_UPPER_LIMIT, Integer.class);
    FNPPeerLoadStatusByte.addField(INPUT_BANDWIDTH_PEER_LIMIT, Integer.class);
    FNPPeerLoadStatusByte.addField(MAX_TRANSFERS_OUT, Byte.class);
    FNPPeerLoadStatusByte.addField(MAX_TRANSFERS_OUT_PEER_LIMIT, Byte.class);
    FNPPeerLoadStatusByte.addField(MAX_TRANSFERS_OUT_LOWER_LIMIT, Byte.class);
    FNPPeerLoadStatusByte.addField(MAX_TRANSFERS_OUT_UPPER_LIMIT, Byte.class);
    FNPPeerLoadStatusByte.addField(REAL_TIME_FLAG, Boolean.class);
  }

  public static final MessageType FNPPeerLoadStatusShort =
      new MessageType("FNPPeerLoadStatusShort", PRIORITY_HIGH, false, true);

  static {
    FNPPeerLoadStatusShort.addField(OTHER_TRANSFERS_OUT_CHK, Short.class);
    FNPPeerLoadStatusShort.addField(OTHER_TRANSFERS_IN_CHK, Short.class);
    FNPPeerLoadStatusShort.addField(OTHER_TRANSFERS_OUT_SSK, Short.class);
    FNPPeerLoadStatusShort.addField(OTHER_TRANSFERS_IN_SSK, Short.class);
    FNPPeerLoadStatusShort.addField(AVERAGE_TRANSFERS_OUT_PER_INSERT, Short.class);
    FNPPeerLoadStatusShort.addField(OUTPUT_BANDWIDTH_LOWER_LIMIT, Integer.class);
    FNPPeerLoadStatusShort.addField(OUTPUT_BANDWIDTH_UPPER_LIMIT, Integer.class);
    FNPPeerLoadStatusShort.addField(OUTPUT_BANDWIDTH_PEER_LIMIT, Integer.class);
    FNPPeerLoadStatusShort.addField(INPUT_BANDWIDTH_LOWER_LIMIT, Integer.class);
    FNPPeerLoadStatusShort.addField(INPUT_BANDWIDTH_UPPER_LIMIT, Integer.class);
    FNPPeerLoadStatusShort.addField(INPUT_BANDWIDTH_PEER_LIMIT, Integer.class);
    FNPPeerLoadStatusShort.addField(MAX_TRANSFERS_OUT, Short.class);
    FNPPeerLoadStatusShort.addField(MAX_TRANSFERS_OUT_PEER_LIMIT, Short.class);
    FNPPeerLoadStatusShort.addField(MAX_TRANSFERS_OUT_LOWER_LIMIT, Short.class);
    FNPPeerLoadStatusShort.addField(MAX_TRANSFERS_OUT_UPPER_LIMIT, Short.class);
    FNPPeerLoadStatusShort.addField(REAL_TIME_FLAG, Boolean.class);
  }

  public static final MessageType FNPPeerLoadStatusInt =
      new MessageType("FNPPeerLoadStatusInt", PRIORITY_HIGH, false, true);

  static {
    FNPPeerLoadStatusInt.addField(OTHER_TRANSFERS_OUT_CHK, Integer.class);
    FNPPeerLoadStatusInt.addField(OTHER_TRANSFERS_IN_CHK, Integer.class);
    FNPPeerLoadStatusInt.addField(OTHER_TRANSFERS_OUT_SSK, Integer.class);
    FNPPeerLoadStatusInt.addField(OTHER_TRANSFERS_IN_SSK, Integer.class);
    FNPPeerLoadStatusInt.addField(AVERAGE_TRANSFERS_OUT_PER_INSERT, Integer.class);
    FNPPeerLoadStatusInt.addField(OUTPUT_BANDWIDTH_LOWER_LIMIT, Integer.class);
    FNPPeerLoadStatusInt.addField(OUTPUT_BANDWIDTH_UPPER_LIMIT, Integer.class);
    FNPPeerLoadStatusInt.addField(OUTPUT_BANDWIDTH_PEER_LIMIT, Integer.class);
    FNPPeerLoadStatusInt.addField(INPUT_BANDWIDTH_LOWER_LIMIT, Integer.class);
    FNPPeerLoadStatusInt.addField(INPUT_BANDWIDTH_UPPER_LIMIT, Integer.class);
    FNPPeerLoadStatusInt.addField(INPUT_BANDWIDTH_PEER_LIMIT, Integer.class);
    FNPPeerLoadStatusInt.addField(MAX_TRANSFERS_OUT, Integer.class);
    FNPPeerLoadStatusInt.addField(MAX_TRANSFERS_OUT_PEER_LIMIT, Integer.class);
    FNPPeerLoadStatusInt.addField(MAX_TRANSFERS_OUT_LOWER_LIMIT, Integer.class);
    FNPPeerLoadStatusInt.addField(MAX_TRANSFERS_OUT_UPPER_LIMIT, Integer.class);
    FNPPeerLoadStatusInt.addField(REAL_TIME_FLAG, Boolean.class);
  }

  /** Secondary message toggling realtime/bulk handling on a per-message basis. */
  public static final MessageType FNPRealTimeFlag =
      new MessageType("FNPRealTimeFlag", PRIORITY_HIGH);

  static {
    FNPRealTimeFlag.addField(REAL_TIME_FLAG, Boolean.class);
  }

  /**
   * Creates a {@code FNPRealTimeFlag} submessage.
   *
   * @param isBulk Flag value; interpretation is implementation-defined.
   * @return Initialized message.
   */
  public static Message createFNPRealTimeFlag(boolean isBulk) {
    Message msg = new Message(FNPRealTimeFlag);
    msg.set(REAL_TIME_FLAG, isBulk);
    return msg;
  }

  /**
   * Extracts the flag value from an optional {@code FNPRealTimeFlag} submessage.
   *
   * @param m Message that may carry the submessage.
   * @return Flag value when present; otherwise {@code false}.
   */
  public static boolean getRealTimeFlag(Message m) {
    Message bulk = m.getSubMessage(FNPRealTimeFlag);
    if (bulk == null) {
      return false;
    }
    return bulk.getBoolean(REAL_TIME_FLAG);
  }

  /** Returns {@code true} if the message is one of the peer-load status variants. */
  public static boolean isPeerLoadStatusMessage(Message m) {
    MessageType spec = m.getSpec();
    return FNPPeerLoadStatusByte.equals(spec)
        || FNPPeerLoadStatusShort.equals(spec)
        || FNPPeerLoadStatusInt.equals(spec);
  }

  /** Returns {@code true} if the message is a request type subject to load limiting. */
  public static boolean isLoadLimitedRequest(Message m) {
    MessageType spec = m.getSpec();
    return FNPCHKDataRequest.equals(spec)
        || FNPSSKDataRequest.equals(spec)
        || FNPSSKInsertRequest.equals(spec)
        || FNPInsertRequest.equals(spec)
        || FNPSSKInsertRequestNew.equals(spec)
        || FNPGetOfferedKey.equals(spec);
  }

  // Extended fatal timeout handling.
  /**
   * Queries whether a set of upstream request UIDs is still running. Reply is {@link
   * #FNPIsStillRunning}.
   */
  public static final MessageType FNPCheckStillRunning =
      new MessageType("FNPCheckStillRunning", PRIORITY_HIGH);

  static {
    FNPCheckStillRunning.addField(UID, Long.class); // UID for this message, used to identify reply
    FNPCheckStillRunning.addField(LIST_OF_UIDS, ShortBuffer.class);
  }

  /** Reply indicating which UIDs are still running using a bitset. */
  public static final MessageType FNPIsStillRunning =
      new MessageType("FNPIsStillRunning", PRIORITY_HIGH);

  static {
    FNPIsStillRunning.addField(UID, Long.class);
    FNPIsStillRunning.addField(UID_STILL_RUNNING_FLAGS, BitArray.class);
  }

  // Friend-of-a-friend (FOAF) related messages

  /** FOAF: request the peer's full noderef. */
  public static final MessageType FNPGetYourFullNoderef =
      new MessageType("FNPGetYourFullNoderef", PRIORITY_LOW);

  /** Creates an {@code FNPGetYourFullNoderef} request. */
  public static Message createFNPGetYourFullNoderef() {
    return new Message(FNPGetYourFullNoderef);
  }

  /** FOAF: reply conveying the sender's full noderef length (payload transferred separately). */
  public static final MessageType FNPMyFullNoderef =
      new MessageType("FNPMyFullNoderef", PRIORITY_LOW);

  static {
    FNPMyFullNoderef.addField(UID, Long.class);
    // Not necessary to pad it since it's not propagated across the network.
    // It might be relayed one hop, but there's enough padding elsewhere, don't worry about
    // it.
    // As opposed to opennet refs, which are relayed long distances, down request paths which
    // they might reveal, so do need to be padded.
    FNPMyFullNoderef.addField(NODEREF_LENGTH, Integer.class);
  }

  /**
   * Creates an {@code FNPMyFullNoderef} reply.
   *
   * @param uid Request identifier associated with the original FOAF query.
   * @param length Unpadded length in bytes of the noderef to follow.
   * @return Initialized message.
   */
  public static Message createFNPMyFullNoderef(long uid, int length) {
    Message m = new Message(FNPMyFullNoderef);
    m.set(UID, uid);
    m.set(NODEREF_LENGTH, length);
    return m;
  }
}
