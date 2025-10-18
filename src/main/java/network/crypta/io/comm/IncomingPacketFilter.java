package network.crypta.io.comm;

import network.crypta.node.OutgoingPacketMangler;

/**
 * Filter interface that decrypts and processes incoming UDP packets.
 *
 * <p>Implementations authenticate and decode packets, then dispatch any contained {@link Message}
 * objects to the messaging core (historically "USM"). See {@link #process(byte[], int, int, Peer,
 * long)} for the required behavior and {@link #isDisconnected(PeerContext)} for connection state
 * checks used during processing.
 *
 * @see OutgoingPacketMangler
 */
public interface IncomingPacketFilter {

  /**
   * Result of attempting to decode an incoming packet.
   *
   * <p>These values allow the caller to distinguish between normal non-matches, intentional
   * declines, and shutdown handling.
   */
  enum DECODED {
    /** The packet was recognized and decoded; messages may have been dispatched to USM/filters. */
    DECODED,
    /** No matching context was found; the packet was not decoded. */
    NOT_DECODED,
    /**
     * The packet was not decoded because open‑net acceptance was disabled or not desired at this
     * time. This indicates an intentional skip rather than a failure to match.
     */
    DIDNT_WANT_OPENNET,
    /** The node is shutting down; callers should stop processing further input. */
    SHUTTING_DOWN
  }

  /**
   * Processes one incoming packet.
   *
   * <p>Implementations should authenticate/decrypt the buffer and, if a valid {@link Message} is
   * found, call {@code USM.decodePacket(...)} followed by {@code USM.checkFilters(...)} (historical
   * naming) to dispatch it to waiting filters or the {@link Dispatcher}.
   *
   * @param buf the input buffer; may be reused by the caller after return—copy any data that must
   *     be retained.
   * @param offset start offset into {@code buf} in bytes.
   * @param length number of bytes available from {@code offset}.
   * @param peer the sender as observed by the transport. Because this is inbound, a {@link
   *     PeerContext} may need to be created or located during processing.
   * @param now receive time in milliseconds since the epoch.
   * @return a {@link DECODED} status indicating whether decoding succeeded, was skipped
   *     intentionally, or should be aborted due to shutdown.
   */
  DECODED process(byte[] buf, int offset, int length, Peer peer, long now);

  // Outgoing packets are handled elsewhere...

  /**
   * Reports whether the given connection is no longer usable.
   *
   * <p>Implementations typically consult {@link PeerContext#isConnected()} to decide. The behavior
   * for a {@code null} context is implementation-defined.
   *
   * @param context the peer context to check; may be {@code null}.
   * @return {@code true} if the connection is considered closed; {@code false} otherwise.
   */
  boolean isDisconnected(PeerContext context);
}
