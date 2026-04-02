package network.crypta.node;

import network.crypta.io.AddressTracker.Status;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.IncomingPacketFilter;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.SocketHandler;

/**
 * Abstraction for composing and sending outgoing packets for transport.
 *
 * <p>Implementations provide the mechanics to initiate handshakes, assess connectivity constraints,
 * and emit wire-ready datagrams/frames to a {@link SocketHandler}. A UDP-based transport typically
 * implements both this interface and {@link IncomingPacketFilter} on the same class so that
 * send/receive paths share state and policy.
 *
 * @see IncomingPacketFilter
 * @see FNPPacketMangler
 */
public interface OutgoingPacketMangler {

  /**
   * Sends a transport-layer handshake to a peer when supported.
   *
   * @param pn the target peer node to contact.
   * @param notRegistered {@code true} if the local node is not yet registered with the peer
   *     according to higher-level state; implementations may use this to choose a more permissive
   *     or discovery-oriented handshake form.
   */
  void sendHandshake(PeerNode pn, boolean notRegistered);

  /**
   * Returns whether the peer referenced by the provided context is considered disconnected.
   *
   * <p>The exact policy is transport-specific (e.g., last activity timeout, explicit close, NAT
   * failure). Implementations should avoid expensive work in this method, as callers may probe it
   * frequently.
   *
   * @param context a peer context associated with an existing or pending connection.
   * @return {@code true} if the transport treats the peer as disconnected.
   */
  @SuppressWarnings("unused")
  boolean isDisconnected(PeerContext context);

  /**
   * Returns the supported negotiation types in preference order.
   *
   * <p>The returned array lists negotiation identifiers with the best choice appearing as the last
   * element. Implementations may vary the list based on the {@code forPublic} flag.
   *
   * @param forPublic a hint that the negotiation list is intended for connections exposed to
   *     non-local peers (implementations decide how to interpret this hint).
   * @return non-empty array of negotiation identifiers in ascending preference; best is last.
   */
  int[] supportedNegTypes(boolean forPublic);

  /**
   * Returns the {@link SocketHandler} used to send bytes on the underlying transport.
   *
   * @return the socket handler that owns the transport I/O.
   */
  SocketHandler getSocketHandler();

  /**
   * Returns this node's primary addresses represented as {@link Peer} endpoints.
   *
   * <p>The list may be empty when the transport cannot determine a stable address set.
   *
   * @return array of primary local addresses; may be empty.
   */
  Peer[] getPrimaryIPAddress();

  /**
   * Returns the compressed node reference for the local node.
   *
   * <p>The exact format and compression are transport- or implementation-defined and suitable for
   * exchanging a compact self-description with peers.
   *
   * @return a byte array containing the compressed node reference.
   */
  @SuppressWarnings("unused")
  byte[] getCompressedNoderef();

  /**
   * Indicates whether local/private addresses are always allowed regardless of other policy.
   *
   * @return {@code true} if local addresses are unconditionally permitted.
   */
  boolean alwaysAllowLocalAddresses();

  /**
   * Port forwarding status.
   *
   * @return a status code from {@link network.crypta.io.AddressTracker}. Consider abstracting the
   *     return type away from {@code AddressTracker.Status} to a transport-agnostic connectivity
   *     indicator when multiple transports require it.
   */
  Status getConnectivityStatus();

  /**
   * Is there any reason not to allow this connection? E.g., limits on the number of nodes on a
   * specific IP address?
   *
   * @param node the peer node we intend to connect to.
   * @param addr the remote network address under consideration.
   * @return {@code true} if the connection is permitted by current policy; {@code false} to
   *     suppress establishing or maintaining the connection.
   */
  boolean allowConnection(PeerNode node, FreenetInetAddress addr);

  /**
   * Notifies the implementation that port forwarding appears to be broken.
   *
   * <p>Implementations should update any cached connectivity state and, if applicable, trigger
   * re-probing or backoff to avoid repeated failed attempts.
   */
  @SuppressWarnings("unused")
  void setPortForwardingBroken();
}
