package network.crypta.clients.fcp;

import java.util.function.Consumer;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.support.Fields;
import network.crypta.support.SimpleFieldSet;

/**
 * Handles the FCP {@code ModifyPeer} command, allowing a client to toggle operational flags on an
 * existing darknet peer. The message is constructed from a {@link SimpleFieldSet} that contains the
 * peer identifier and optional boolean switches. During execution, the handler verifies that the
 * caller has full access, resolves the target peer, enforces that it is a darknet node, and then
 * applies the requested changes before returning the updated peer description to the client.
 *
 * <p>Use this class when a client needs to adjust connectivity characteristics for a known peer
 * without recreating or deleting it. Typical call patterns originate from the FCP server loop,
 * which instantiates this message from incoming fields and delegates execution to {@link #run}. The
 * implementation delegates synchronization and persistence concerns to {@link Node} and peer
 * implementations; it performs only the protocol-level validation and flag translation. Flags are
 * optional and omitted values leave existing peer settings unchanged.
 *
 * <ul>
 *   <li>Checks for full-access permissions before applying any change.
 *   <li>Supports toggling disabled, listen-only, burst-only, source-port ignoring, and
 *       local-address allowance states.
 *   <li>Always responds with a refreshed {@link PeerMessage} so clients can observe the resulting
 *       configuration.
 * </ul>
 *
 * @see FCPMessage
 * @see PeerMessage
 * @see DarknetPeerNode
 */
public class ModifyPeer extends FCPMessage {
  static final String NAME = "ModifyPeer";

  final SimpleFieldSet fs;
  final String requestIdentifier;

  /**
   * Creates a new message instance sourced from the provided field set and extracts the request
   * identifier for later error reporting. The constructor removes the {@code Identifier} entry from
   * the payload so it is not forwarded when the message is echoed back to clients after processing.
   * The field set is not deep-copied; callers should avoid reusing it after construction if they
   * need the identifier value.
   *
   * @param fs field set containing incoming {@code ModifyPeer} parameters; must include an {@code
   *     Identifier} token and peer-selection fields.
   */
  public ModifyPeer(SimpleFieldSet fs) {
    this.fs = fs;
    this.requestIdentifier = fs.get(IDENTIFIER);
    fs.removeValue("Identifier");
  }

  /**
   * Returns the outgoing field set for this message. {@code ModifyPeer} replies do not carry
   * additional fields at this stage because the updated peer details are encapsulated in the
   * resulting {@link PeerMessage}. A fresh, empty {@link SimpleFieldSet} is returned to satisfy the
   * FCP message contract while avoiding redundant data.
   *
   * @return new {@link SimpleFieldSet} with no entries, ready for protocol serialization.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Provides the protocol-level name used to register and dispatch this message type within the FCP
   * handler. The name is stable and matches the {@code ModifyPeer} verb understood by clients,
   * enabling straightforward routing from the message parser to this implementation without
   * additional aliasing or negotiation steps.
   *
   * @return constant string {@code "ModifyPeer"} representing this FCP message name.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the {@code ModifyPeer} request against the supplied node on behalf of the current
   * connection. The method enforces full-access permissions, validates that a {@code
   * NodeIdentifier} is provided, and confirms that the referenced peer exists and belongs to the
   * darknet cohort. For each optional flag supplied in the field set, it toggles the corresponding
   * state on the peer; absent flags leave existing settings unchanged. After updates, it returns
   * the refreshed peer description to the client.
   *
   * @param handler connection handler that mediates access checks and message delivery for the
   *     caller; must support full-access operations.
   * @param node node instance that stores peer records and applies requested state changes.
   * @throws MessageInvalidException if access is denied, required fields are missing, or the target
   *     peer is not available as a darknet peer.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "ModifyPeer requires full access",
          requestIdentifier,
          false);
    }
    String nodeIdentifier = fs.get("NodeIdentifier");
    if (nodeIdentifier == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Error: NodeIdentifier field missing",
          requestIdentifier,
          false);
    }
    PeerNode pn = node.getPeerNode(nodeIdentifier);
    if (pn == null) {
      FCPMessage msg = new UnknownNodeIdentifierMessage(nodeIdentifier, requestIdentifier);
      handler.send(msg);
      return;
    }
    if (!(pn instanceof DarknetPeerNode dpn)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.DARKNET_ONLY,
          "ModifyPeer only available for darknet peers",
          requestIdentifier,
          false);
    }
    applyDisableFlag(dpn, fs.get("IsDisabled"));
    applyBooleanFlag(dpn::setListenOnly, fs.get("IsListenOnly"));
    applyBooleanFlag(dpn::setBurstOnly, fs.get("IsBurstOnly"));
    applyBooleanFlag(dpn::setIgnoreSourcePort, fs.get("IgnoreSourcePort"));
    applyBooleanFlag(dpn::setAllowLocalAddresses, fs.get("AllowLocalAddresses"));
    handler.send(new PeerMessage(pn, true, true, requestIdentifier));
  }

  private static void applyDisableFlag(DarknetPeerNode dpn, String disableFlag) {
    if (isNonEmpty(disableFlag)) {
      if (Fields.stringToBool(disableFlag, false)) {
        dpn.disablePeer();
      } else {
        dpn.enablePeer();
      }
    }
  }

  private static void applyBooleanFlag(Consumer<Boolean> setter, String flagValue) {
    if (isNonEmpty(flagValue)) {
      setter.accept(Fields.stringToBool(flagValue, false));
    }
  }

  private static boolean isNonEmpty(String value) {
    return value != null && !value.isEmpty();
  }
}
