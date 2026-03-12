package network.crypta.io.comm;

import network.crypta.io.AddressTracker.Status;
import network.crypta.io.comm.Peer.LocalAddressException;

/**
 * Contract for datagram-oriented transports (for example, UDP).
 *
 * <p>Implementations provide packet sizing information, send raw encoded datagrams, and expose
 * header lengths for accurate byte accounting. A {@link IncomingPacketFilter} can be registered to
 * decrypt and dispatch received packets.
 *
 * <p>Threading: Callers may invoke these methods from I/O and worker threads. Implementations
 * should document their own thread-safety guarantees.
 */
public interface PacketSocketHandler extends SocketHandler {

  /**
   * Returns the maximum payload size for a single datagram, excluding transport headers.
   *
   * <p>Units are bytes. The value is suitable for sizing message buffers before adding UDP/IP (or
   * similar) headers.
   *
   * @return maximum bytes allowed for one packet's payload (no transport headers).
   */
  int getMaxPacketSize();

  /**
   * Sends one already-encoded datagram to a peer.
   *
   * <p>This is used by the messaging stack after assembling the on‑wire format. Implementations
   * must route the packet to the network and may update I/O statistics.
   *
   * @param blockToSend the datagram payload to transmit; not modified by the callee.
   * @param destination the target peer (address and port provider).
   * @param allowLocalAddresses when {@code true}, permits sending to local or private addresses;
   *     when {@code false}, such destinations result in an exception.
   * @throws LocalAddressException if {@code allowLocalAddresses} is {@code false} and the
   *     destination resolves to a local/private address.
   */
  void sendPacket(byte[] blockToSend, Peer destination, boolean allowLocalAddresses)
      throws LocalAddressException;

  /**
   * Returns the transport header length used for accounting when the address family is unknown.
   *
   * <p>Units are bytes. Implementations may return a conservative upper bound when the actual
   * family (IPv4 vs IPv6) is not available.
   */
  @SuppressWarnings("unused")
  int getHeadersLength();

  /**
   * Returns the transport header length for the given peer's address family.
   *
   * <p>Units are bytes. Implementations may inspect the peer's resolved address to choose the
   * appropriate header size.
   *
   * @param peer used to detect address family.
   * @return header length in bytes for this peer's address family.
   */
  int getHeadersLength(Peer peer);

  /**
   * Registers the low‑level filter that decrypts and dispatches received datagrams.
   *
   * <p>Subsequent incoming packets are fed to the filter; passing {@code null} removes the filter
   * if supported by the implementation.
   *
   * @param f the incoming packet filter to install, or {@code null} to clear.
   */
  void setLowLevelFilter(IncomingPacketFilter f);

  /**
   * Returns the accumulated byte threshold that triggers sending a datagram.
   *
   * <p>The threshold includes transport headers and represents the minimum buffered size at which
   * the transport prefers to transmit.
   *
   * @return size in bytes, including transport headers, that prompts a sending.
   */
  @SuppressWarnings("unused")
  int getPacketSendThreshold();

  /**
   * Reports whether the local port appears reachable from the Internet.
   *
   * <p>The status originates from the {@link network.crypta.io.AddressTracker} and reflects
   * observations such as successful inbound connectivity (for example, NAT/port‑forwarding
   * detection).
   *
   * @return the last observed connectivity status.
   */
  Status getDetectedConnectivityStatus();
}
