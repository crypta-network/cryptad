package network.crypta.node;

import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Seed peer implementation used exclusively by seed-server tests.
 *
 * <p>This test-only variant never initiates the regular connection handshake and is not removed by
 * routine housekeeping tasks. It allows tests to observe how the node reacts to specific connection
 * outcomes without generating additional traffic. The exported reference marks itself with {@code
 * opennet=true} so downstream consumers can recognize test entries.
 *
 * <p>Thread-safety: instances rely on the same concurrency guarantees as {@link
 * SeedServerPeerNode}. The {@link #exportFieldSet()} method remains {@code synchronized} to match
 * the superclass contract.
 *
 * @author nextgens
 */
public class SeedServerTestPeerNode extends SeedServerPeerNode {

  private static final Logger LOG = LoggerFactory.getLogger(SeedServerTestPeerNode.class);

  /**
   * Creates a test seed peer.
   *
   * <p>This constructor mirrors the superclass and forwards the parsed peer reference and wiring to
   * {@link SeedServerPeerNode}. No additional validation is performed here.
   *
   * @param fs parsed reference fields for the peer; must include the required identity keys.
   * @param node2 owning node instance.
   * @param crypto cryptographic utilities for peer verification.
   * @param fromLocal whether the peer reference originates from the local configuration.
   * @param peers peer manager used to register and track this peer.
   * @throws FSParseException if {@code fs} cannot be interpreted as a valid reference.
   * @throws PeerParseException if peer identity or address data is malformed.
   * @throws ReferenceSignatureVerificationException if the reference signature fails verification.
   * @throws PeerTooOldException if the peer is below the supported protocol/version threshold.
   */
  public SeedServerTestPeerNode(
      SimpleFieldSet fs, Node node2, NodeCrypto crypto, boolean fromLocal, PeerManager peers)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    super(fs, node2, crypto, fromLocal, peers);
  }

  /**
   * Exports the peer as a {@link SimpleFieldSet} with a testing hint.
   *
   * <p>Adds {@code opennet=true} to indicate to downstream consumers that this reference is used in
   * seed-server tests. The base export from the superclass is otherwise preserved.
   *
   * @return a field set describing this peer; never {@code null}.
   */
  @Override
  public synchronized SimpleFieldSet exportFieldSet() {
    SimpleFieldSet sfs = super.exportFieldSet();
    sfs.putOverwrite("opennet", "true");
    return sfs;
  }

  /**
   * Keeps test seed peers resident.
   *
   * <p>Returns {@code false} so background cleanup never proactively drops this peer based solely
   * on inactivity. Tests control lifecycle explicitly.
   *
   * @return always {@code false}.
   */
  @Override
  public boolean shouldDisconnectAndRemoveNow() {
    return false;
  }

  /**
   * Suppresses the initial handshake for test peers.
   *
   * <p>Intentionally performs no action to avoid initiating network traffic during tests.
   * Production peers use this hook to send the first messages of the protocol handshake.
   */
  @Override
  protected void sendInitialMessages() {
    // Intentionally empty to avoid starting a handshake during tests.
  }

  /** High-level outcome of this peer's most recent connection attempt or state. */
  public enum FATE {
    /** Never connected to this peer. */
    NEVER_CONNECTED,
    /** Connected, but no packets have been received so far. */
    CONNECTED_NO_PACKETS_RECEIVED,
    /** Connected, but the peer is on an unsupported/older protocol version. */
    CONNECTED_TOO_OLD,
    /** Connected and successfully received packets. */
    CONNECTED_SUCCESS,
    /** Connection established, then timed out without receiving any packets. */
    CONNECTED_TIMEOUT_NO_PACKETS_RECEIVED,
    /** Connected and later disconnected for an unknown reason. */
    CONNECTED_DISCONNECTED_UNKNOWN
  }

  /**
   * Logs a concise removal reason and delegates to the superclass.
   *
   * <p>The reason is derived from the last successful connection timestamp and the last time a data
   * packet was received. A warning is logged for visibility in test output.
   */
  @Override
  public void onRemove() {
    long lastReceivedDataPacketTime = lastReceivedDataPacketTime();
    if (lastReceivedDataPacketTime <= 0 && timeLastConnectionCompleted() > 0) {
      printRemovalReason("TIMEOUT: NO PACKETS RECEIVED AFTER SUCCESSFUL CONNECTION SETUP");
    } else if (timeLastConnectionCompleted() <= 0) {
      printRemovalReason("NEVER CONNECTED");
    } else {
      printRemovalReason("UNKNOWN CAUSE");
    }
    super.onRemove();
  }

  /**
   * Mirrors the removal reason to the structured logger.
   *
   * <p>This class is used exclusively by seed-server tests. Tests assert on the logger output to
   * validate the textual classification.
   */
  private void printRemovalReason(String reason) {
    String msg = this.getIdentityString() + " : REMOVED: " + reason;
    LOG.warn(msg);
  }

  /**
   * Returns a summarized connection outcome for this peer.
   *
   * <p>The result reflects the current connection state and whether any packets have been received
   * since the last connection, including special handling for peers deemed too old to route.
   *
   * @return the most appropriate {@link FATE} for the current/last state.
   */
  public FATE getFate() {
    long lastReceivedDataPacketTime = lastReceivedDataPacketTime();
    if (isConnected()) {
      if (lastReceivedDataPacketTime <= 0) return FATE.CONNECTED_NO_PACKETS_RECEIVED;
      else if (this.isUnroutableOlderVersion()) return FATE.CONNECTED_TOO_OLD;
      else return FATE.CONNECTED_SUCCESS;
    }
    long lastConnectionTime = timeLastConnectionCompleted();
    if (lastConnectionTime <= 0) return FATE.NEVER_CONNECTED;
    if (lastReceivedDataPacketTime <= 0) return FATE.CONNECTED_TIMEOUT_NO_PACKETS_RECEIVED;
    return FATE.CONNECTED_DISCONNECTED_UNKNOWN;
  }
}
