package network.crypta.node;

import network.crypta.io.AddressTracker.Status;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.IncomingPacketFilter;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.SocketHandler;

/**
 * Low-level interface for sending packets. A UDP-based transport will have to implement both this
 * and IncomingPacketFilter, usually on the same class.
 *
 * @see IncomingPacketFilter
 * @see FNPPacketMangler
 */
public interface OutgoingPacketMangler {

  /**
   * Send a handshake, if possible, to the node.
   *
   * @param pn
   */
  void sendHandshake(PeerNode pn, boolean notRegistered);

  /** Is a peer disconnected? */
  boolean isDisconnected(PeerContext context);

  /** List of supported negotiation types in preference order (best last) */
  int[] supportedNegTypes(boolean forPublic);

  /** The SocketHandler we are connected to. */
  SocketHandler getSocketHandler();

  /** Get our addresses, as peers. */
  Peer[] getPrimaryIPAddress();

  /** Get our compressed noderef */
  byte[] getCompressedNoderef();

  /** Always allow local addresses? */
  boolean alwaysAllowLocalAddresses();

  /**
   * Port forwarding status.
   *
   * @return A status code from AddressTracker. FIXME make this more generic when we need to.
   */
  Status getConnectivityStatus();

  /**
   * Is there any reason not to allow this connection? E.g. limits on the number of nodes on a
   * specific IP address?
   */
  boolean allowConnection(PeerNode node, FreenetInetAddress addr);

  /** If the lower level code detects the port forwarding is broken, it will call this method. */
  void setPortForwardingBroken();
}
