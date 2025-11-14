package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.PersistentTempBucketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for all Freenet Client Protocol (FCP) messages exchanged between external clients and
 * the node's FCP server.
 *
 * <p>Each instance represents a single message on the wire, consisting of a textual message name
 * followed by a {@link SimpleFieldSet} of name–value pairs. Subclasses provide the concrete mapping
 * between protocol-level fields and internal structures, as well as the handling logic executed by
 * {@link #run(FCPConnectionHandler, Node)}.
 *
 * <p>The core responsibilities of this type are:
 *
 * <ul>
 *   <li>serializing messages to an {@link OutputStream} via {@link #send(OutputStream)}
 *   <li>providing factory methods {@link #create(String, SimpleFieldSet, BucketFactory,
 *       PersistentTempBucketFactory)} and {@link #create(String, SimpleFieldSet)} to reify messages
 *       received from the network
 *   <li>defining an execution hook {@link #run(FCPConnectionHandler, Node)} for processing messages
 *       on the server side
 * </ul>
 *
 * <p>This abstraction does not define any concurrency guarantees. Callers should treat message
 * instances and their underlying field sets as not inherently thread-safe and avoid sharing them
 * across threads without external synchronization.
 */
public abstract class FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(FCPMessage.class);

  /*
   * Fields used by FCP messages. These are in TitleCaps by convention.
   */
  /**
   * Field name constant for the {@code Build} attribute.
   *
   * <p>This key is used in FCP messages that expose the node's build identifier or software
   * version, allowing clients to inspect compatibility and display diagnostics to users.
   */
  public static final String BUILD = "Build";

  /**
   * Field name constant for the {@code Code} attribute.
   *
   * <p>Messages that report success, failure, or other status information use this key to carry an
   * implementation-specific numeric or symbolic code describing the outcome.
   */
  public static final String CODE = "Code";

  /**
   * Field name constant for the {@code HopsToLive} attribute.
   *
   * <p>This key is used in request messages to express how far a request is allowed to propagate
   * through the network before being discarded, typically in terms of routing hops.
   */
  public static final String HTL = "HopsToLive";

  /**
   * Field name constant for the {@code Identifier} attribute.
   *
   * <p>The identifier associates messages and asynchronous responses with a client-specified token,
   * enabling clients to correlate protocol events without relying on transport-level state.
   */
  public static final String IDENTIFIER = "Identifier";

  /**
   * Field name constant for the {@code LinkLengths} attribute.
   *
   * <p>Messages that carry node or network statistics may use this key to encode a representation
   * of link-length distribution or related routing metrics for diagnostic purposes.
   */
  public static final String LINK_LENGTHS = "LinkLengths";

  /**
   * Field name constant for the {@code Local} attribute.
   *
   * <p>This key distinguishes between information that applies only to the local node and data that
   * has been derived from network-wide observations, depending on the message type that uses it.
   */
  public static final String LOCAL = "Local";

  /**
   * Field name constant for the {@code Location} attribute.
   *
   * <p>Messages that expose positioning information in the routing space or clustering metrics use
   * this key to publish a node's relative location as seen by the protocol.
   */
  public static final String LOCATION = "Location";

  /**
   * Field name constant for the {@code OutputBandwidth} attribute.
   *
   * <p>This key identifies fields that describe the node's available or configured outbound
   * bandwidth, typically expressed in bytes per second or an equivalent unit understood by clients.
   */
  public static final String OUTPUT_BANDWIDTH = "OutputBandwidth";

  /**
   * Field name constant for the {@code ProbeIdentifier} attribute.
   *
   * <p>Probe- and statistics-related messages use this key to associate individual probes or
   * samples with a particular identifier so that clients can match responses to requests.
   */
  public static final String PROBE_IDENTIFIER = "ProbeIdentifier";

  /**
   * Field name constant for the {@code StoreSize} attribute.
   *
   * <p>Messages that report or negotiate datastore sizes use this key to carry the logical size of
   * the store, often expressed in bytes or an implementation-specific capacity unit.
   */
  public static final String STORE_SIZE = "StoreSize";

  /**
   * Field name constant for the {@code Type} attribute.
   *
   * <p>This key is used by various messages to distinguish subtypes or operation kinds within a
   * single message family, with concrete values interpreted by the corresponding handler.
   */
  public static final String TYPE = "Type";

  /**
   * Field name constant for the {@code UptimePercent} attribute.
   *
   * <p>Probe and statistics messages use this key to convey a percentage representing how long a
   * node has been available over a given observation window, enabling clients to reason about
   * reliability.
   */
  public static final String UPTIME_PERCENT = "UptimePercent";

  /**
   * Field name constant for {@code Rejects.Bulk.Request.CHK}.
   *
   * <p>This key is typically used in diagnostic or monitoring messages that expose how many bulk
   * CHK requests have been rejected, allowing clients to detect overload or policy issues.
   */
  public static final String BULK_CHK_REQUEST_REJECTS = "Rejects.Bulk.Request.CHK";

  /**
   * Field name constant for {@code Rejects.Bulk.Request.SSK}.
   *
   * <p>Messages that report statistics on bulk SSK requests can use this key to expose the number
   * of rejected operations, without prescribing a particular interpretation of the underlying
   * policy.
   */
  public static final String BULK_SSK_REQUEST_REJECTS = "Rejects.Bulk.Request.SSK";

  /**
   * Field name constant for {@code Rejects.Bulk.Insert.CHK}.
   *
   * <p>This key appears in messages that track rejected bulk CHK insert attempts, allowing tooling
   * to monitor how often large-scale insert workloads fail due to local limits or validation
   * errors.
   */
  public static final String BULK_CHK_INSERT_REJECTS = "Rejects.Bulk.Insert.CHK";

  /**
   * Field name constant for {@code Rejects.Bulk.Insert.SSK}.
   *
   * <p>Statistics- and diagnostics-oriented messages use this key when exposing the count of bulk
   * SSK insert operations that have been rejected for a node over some period or probing run.
   */
  public static final String BULK_SSK_INSERT_REJECTS = "Rejects.Bulk.Insert.SSK";

  /**
   * Field name constant for {@code OutputBandwidthClass}.
   *
   * <p>This key encodes a coarse-grained classification of the node's outbound bandwidth capacity,
   * allowing user interfaces and tools to group nodes into classes instead of dealing with raw
   * numeric throughput values.
   */
  public static final String OUTPUT_BANDWIDTH_CLASS = "OutputBandwidthClass";

  /**
   * Field name constant for {@code OverallBulkOutputCapacityUsage}.
   *
   * <p>Messages that summarize how much bulk output capacity is currently in use employ this key to
   * publish a ratio or percentage, enabling clients to detect saturation or headroom in bulk
   * traffic.
   */
  public static final String OVERALL_BULK_OUTPUT_CAPACITY_USAGE = "OverallBulkOutputCapacityUsage";

  // Legacy threshold callback removed.

  /**
   * Serializes this message to the given FCP output stream.
   *
   * <p>The method writes the message name followed by the textual representation of the associated
   * {@link SimpleFieldSet}. If {@link #getFieldSet()} returns {@code null}, the method logs a
   * warning and does not write anything to the stream.
   *
   * <p>The stream is neither flushed nor closed by this method; callers remain responsible for any
   * higher-level framing, flushing policy, and resource management.
   *
   * @param os output stream to receive the encoded FCP message; must remain writable for the
   *     duration of the call and is not closed by this method
   * @throws IOException if writing the message header or body to the stream fails for any reason
   */
  public void send(OutputStream os) throws IOException {
    SimpleFieldSet sfs = getFieldSet();
    if (sfs == null) {
      LOG.warn("Not sending message {}", this);
      return;
    }
    sfs.setEndMarker(getEndString());
    String msg = sfs.toString();
    os.write((getName() + '\n').getBytes(StandardCharsets.UTF_8));
    os.write(msg.getBytes(StandardCharsets.UTF_8));
    if (LOG.isTraceEnabled()) {
      LOG.trace("Outgoing FCP message:\n{}\n{}", getName(), sfs);
      LOG.trace("Being handled by {}", this);
    }
  }

  String getEndString() {
    return "EndMessage";
  }

  /**
   * Returns the {@link SimpleFieldSet} representation of this message.
   *
   * <p>The returned field set is used for on-the-wire serialization in {@link #send(OutputStream)}
   * and may also be consulted by callers that wish to inspect the low-level protocol fields.
   * Implementations may return {@code null} when a message should not be sent, in which case {@link
   * #send(OutputStream)} simply logs a warning and returns.
   *
   * @return mutable or immutable field set describing this message, or {@code null} if this
   *     instance should not currently be serialized and sent
   */
  public abstract SimpleFieldSet getFieldSet();

  /**
   * Returns the FCP message name used on the wire.
   *
   * <p>The name is written as the first line of the serialized message output and is also used by
   * the static {@link #create(String, SimpleFieldSet, BucketFactory, PersistentTempBucketFactory)}
   * method to select a concrete implementation when decoding messages from clients.
   *
   * @return non-{@code null} message name token that uniquely identifies the concrete FCP message
   *     type within the protocol
   */
  public abstract String getName();

  /**
   * Creates a concrete FCP message instance for the given protocol name and fields.
   *
   * <p>This factory is used when decoding messages received from a client connection. It inspects
   * {@code name} to choose the corresponding {@link FCPMessage} subclass and passes the supplied
   * {@link SimpleFieldSet} and optional bucket factories to the appropriate constructor. For the
   * special name {@code "Void"}, this method returns {@code null}, matching historical FCP
   * behavior.
   *
   * <p>Messages that require temporary or persistent bucket storage, such as directory uploads or
   * filter operations, expect the supplied factories to be non-{@code null}. Callers that do not
   * need those features can instead use the convenience overload {@link #create(String,
   * SimpleFieldSet)} for message types that do not depend on buckets.
   *
   * @param name protocol message name as read from the wire; used to select the concrete message
   *     type
   * @param fs field set containing the decoded protocol fields; must at least contain the fields
   *     required by the target message implementation
   * @param bfTemp factory used for transient bucket storage, for example while constructing complex
   *     directory upload messages; may be {@code null} when not needed
   * @param bfPersistent factory used for longer-lived bucket storage backing persistent operations;
   *     may be {@code null} when the selected message does not use it
   * @return a fully constructed {@link FCPMessage} instance matching {@code name}, or {@code null}
   *     when {@code name} is {@code "Void"}
   * @throws MessageInvalidException if {@code name} is unknown or if {@code fs} does not satisfy
   *     the requirements of the corresponding message constructor
   */
  public static FCPMessage create(
      String name,
      SimpleFieldSet fs,
      BucketFactory bfTemp,
      PersistentTempBucketFactory bfPersistent)
      throws MessageInvalidException {
    FCPMessage message = createClientMessages(name, fs);
    if (message != null) {
      return message;
    }
    message = createConfigAndStatusMessages(name, fs);
    if (message != null) {
      return message;
    }
    message = createPeerAndWatchMessages(name, fs);
    if (message != null) {
      return message;
    }
    message = createSubscriptionAndProbeMessages(name, fs, bfTemp, bfPersistent);
    if (message != null) {
      return message;
    }
    if ("Void".equals(name)) {
      return null;
    }
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE, "Unknown message name " + name, null, false);
  }

  private static FCPMessage createClientMessages(String name, SimpleFieldSet fs)
      throws MessageInvalidException {
    return switch (name) {
      case AddPeer.NAME -> new AddPeer(fs);
      case ClientGetMessage.NAME -> new ClientGetMessage(fs);
      case ClientHelloMessage.NAME -> new ClientHelloMessage(fs);
      case ClientPutDiskDirMessage.NAME -> new ClientPutDiskDirMessage(fs);
      case ClientPutMessage.NAME -> new ClientPutMessage(fs);
      case SendBookmarkMessage.NAME -> new SendBookmarkMessage(fs);
      case SendURIMessage.NAME -> new SendURIMessage(fs);
      case SendTextMessage.NAME -> new SendTextMessage(fs);
      case DisconnectMessage.NAME -> new DisconnectMessage(fs);
      case FCPPluginClientMessage.NAME -> new FCPPluginClientMessage(fs);
      default -> null;
    };
  }

  private static FCPMessage createConfigAndStatusMessages(String name, SimpleFieldSet fs)
      throws MessageInvalidException {
    return switch (name) {
      case GenerateSSKMessage.NAME -> new GenerateSSKMessage(fs);
      case GetConfig.NAME -> new GetConfig(fs);
      case GetNode.NAME -> new GetNode(fs);
      case GetPluginInfo.NAME -> new GetPluginInfo(fs);
      case GetRequestStatusMessage.NAME -> new GetRequestStatusMessage(fs);
      case ListPeerMessage.NAME -> new ListPeerMessage(fs);
      case ListPeersMessage.NAME -> new ListPeersMessage(fs);
      case ListPeerNotesMessage.NAME -> new ListPeerNotesMessage(fs);
      case ListPersistentRequestsMessage.NAME -> new ListPersistentRequestsMessage(fs);
      case LoadPlugin.NAME -> new LoadPlugin(fs);
      case ReloadPlugin.NAME -> new ReloadPlugin(fs);
      default -> null;
    };
  }

  private static FCPMessage createPeerAndWatchMessages(String name, SimpleFieldSet fs)
      throws MessageInvalidException {
    return switch (name) {
      case ModifyConfig.NAME -> new ModifyConfig(fs);
      case ModifyPeer.NAME -> new ModifyPeer(fs);
      case ModifyPeerNote.NAME -> new ModifyPeerNote(fs);
      case ModifyPersistentRequest.NAME -> new ModifyPersistentRequest(fs);
      case RemovePeer.NAME -> new RemovePeer(fs);
      case RemovePersistentRequest.NAME, RemovePersistentRequest.ALT_NAME ->
          new RemovePersistentRequest(fs);
      case RemovePlugin.NAME -> new RemovePlugin(fs);
      case WatchFeedsMessage.NAME -> new WatchFeedsMessage(fs);
      case WatchGlobal.NAME -> new WatchGlobal(fs);
      case ShutdownMessage.NAME -> new ShutdownMessage();
      default -> null;
    };
  }

  private static FCPMessage createSubscriptionAndProbeMessages(
      String name,
      SimpleFieldSet fs,
      BucketFactory bfTemp,
      PersistentTempBucketFactory bfPersistent)
      throws MessageInvalidException {
    return switch (name) {
      case ClientPutComplexDirMessage.NAME ->
          new ClientPutComplexDirMessage(fs, bfTemp, bfPersistent);
      case SubscribeUSKMessage.NAME -> new SubscribeUSKMessage(fs);
      case UnsubscribeUSKMessage.NAME -> new UnsubscribeUSKMessage(fs);
      case TestDDARequestMessage.NAME -> new TestDDARequestMessage(fs);
      case TestDDAResponseMessage.NAME -> new TestDDAResponseMessage(fs);
      case ProbeRequest.NAME -> new ProbeRequest(fs);
      case FilterMessage.NAME -> new FilterMessage(fs, bfTemp);
      default -> null;
    };
  }

  /**
   * Convenience overload that creates a message without bucket factories.
   *
   * <p>This method delegates to {@link #create(String, SimpleFieldSet, BucketFactory,
   * PersistentTempBucketFactory)} with {@code null} factories and is therefore only suitable for
   * message types that do not require temporary or persistent bucket storage.
   *
   * @param name protocol message name to resolve to a concrete implementation
   * @param fs decoded field set representing the message payload received from the client
   *     connection
   * @return constructed {@link FCPMessage} instance, or {@code null} when {@code name} is the
   *     special {@code "Void"} marker
   * @throws MessageInvalidException if the name is unknown or {@code fs} is not valid for the
   *     resolved message type
   */
  public static FCPMessage create(String name, SimpleFieldSet fs) throws MessageInvalidException {
    return FCPMessage.create(name, fs, null, null);
  }

  /**
   * Returns an FCP message that wraps another message and adds a list request identifier.
   *
   * <p>The returned wrapper delegates {@link #send(OutputStream)}, {@link #getFieldSet()}, {@link
   * #getName()} and {@link #run(FCPConnectionHandler, Node)} to the supplied {@code fcpMessage},
   * but injects a {@code "ListRequestIdentifier"} field into the {@link SimpleFieldSet} returned by
   * {@link #getFieldSet()}. This is useful when the same underlying message needs to be associated
   * with a particular list operation on the client side without changing the original
   * implementation.
   *
   * <p>If either {@code fcpMessage} or {@code listRequestIdentifier} is {@code null}, this method
   * simply returns {@code fcpMessage} unchanged.
   *
   * @param fcpMessage original message instance to be wrapped; may be {@code null} when no message
   *     is available
   * @param listRequestIdentifier identifier to attach using the {@code ListRequestIdentifier}
   *     field; if {@code null} the message is returned as-is
   * @return a new delegating {@link FCPMessage} that adds the identifier field, or the original
   *     {@code fcpMessage} reference when no wrapping is required
   */
  public static FCPMessage withListRequestIdentifier(
      final FCPMessage fcpMessage, final String listRequestIdentifier) {
    if ((listRequestIdentifier == null) || (fcpMessage == null)) {
      return fcpMessage;
    }
    return new FCPMessage() {
      @Override
      public void send(OutputStream os) throws IOException {
        fcpMessage.send(os);
      }

      @Override
      String getEndString() {
        return fcpMessage.getEndString();
      }

      @Override
      public SimpleFieldSet getFieldSet() {
        SimpleFieldSet fieldSet = fcpMessage.getFieldSet();
        fieldSet.putOverwrite("ListRequestIdentifier", listRequestIdentifier);
        return fieldSet;
      }

      @Override
      public String getName() {
        return fcpMessage.getName();
      }

      @Override
      public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
        fcpMessage.run(handler, node);
      }
    };
  }

  /**
   * Executes the server-side processing logic associated with this message.
   *
   * <p>This method is typically invoked by an {@link FCPConnectionHandler} after a message has been
   * parsed from the client connection. Implementations are expected to inspect the message fields,
   * interact with the supplied {@link Node}, and send any responses or follow-up messages through
   * the handler. The exact side effects depend on the concrete message type.
   *
   * @param handler connection handler representing the client session that sent this message; used
   *     to enqueue replies and status updates
   * @param node running node instance on which the message should operate; provides access to core
   *     services and configuration
   * @throws MessageInvalidException if the message is syntactically correct but cannot be processed
   *     due to invalid field combinations or state constraints
   */
  public abstract void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException;
}
