package network.crypta.io.comm;

import network.crypta.io.AddressTracker.Status;
import network.crypta.io.comm.Peer.LocalAddressException;

/** Base class for UdpSocketHandler and any other datagram-based transports. */
public interface PacketSocketHandler extends SocketHandler {

  /** The maximum size of a packet, not including transport layer headers */
  int getMaxPacketSize();

  /**
   * Send a block of encoded bytes to a peer. This is called by send, and by
   * IncomingPacketFilter.processOutgoing(..).
   *
   * @param blockToSend The data block to send.
   * @param destination The peer to send it to.
   */
  void sendPacket(byte[] blockToSend, Peer destination, boolean allowLocalAddresses)
      throws LocalAddressException;

  /** Get the size of the transport layer headers, for byte accounting purposes. */
  int getHeadersLength();

  /**
   * Get the size of the transport layer headers, for byte accounting purposes.
   *
   * @param peer used to detect address family.
   */
  int getHeadersLength(Peer peer);

  /** Set the decryption filter to which incoming packets will be fed */
  void setLowLevelFilter(IncomingPacketFilter f);

  /**
   * How big must the pending data be before we send a packet? *Includes* transport layer headers.
   */
  int getPacketSendThreshold();

  /** Does this port appear to be port forwarded? @see AddressTracker */
  Status getDetectedConnectivityStatus();
}
