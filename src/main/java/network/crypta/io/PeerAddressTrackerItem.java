package network.crypta.io;

import java.net.UnknownHostException;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.node.FSParseException;
import network.crypta.support.SimpleFieldSet;

/**
 * Tracks send/receive activity for a single {@link network.crypta.io.comm.Peer}.
 *
 * <p>This type extends {@link AddressTrackerItem} with a concrete peer identity. It is used by
 * {@link AddressTracker} to keep recent activity, counters, and derived inactivity gaps per peer.
 * Timestamps are in milliseconds since the Unix epoch.
 *
 * <p>Threading: mutations and state reads inherited from {@code AddressTrackerItem} use its
 * synchronization strategy. The {@link #peer} field is immutable.
 *
 * @see AddressTrackerItem
 * @see AddressTracker
 * @see network.crypta.io.comm.Peer
 */
public final class PeerAddressTrackerItem extends AddressTrackerItem {

  /** The logical remote endpoint this tracker represents; never {@code null}. */
  public final Peer peer;

  /**
   * Creates an item with initial upper bounds and a concrete peer.
   *
   * @param timeDefinitelyNoPacketsReceived the earliest time at which receiving was impossible (for
   *     example, socket startup), in milliseconds since epoch
   * @param timeDefinitelyNoPacketsSent the earliest time at which sending was impossible (for
   *     example, node startup), in milliseconds since epoch
   * @param peer peer identity to track; must not be {@code null}
   */
  public PeerAddressTrackerItem(
      long timeDefinitelyNoPacketsReceived, long timeDefinitelyNoPacketsSent, Peer peer) {
    super(timeDefinitelyNoPacketsReceived, timeDefinitelyNoPacketsSent);
    this.peer = peer;
  }

  /**
   * Reconstructs an item from a serialized field set.
   *
   * <p>In addition to the fields handled by {@link
   * AddressTrackerItem#AddressTrackerItem(SimpleFieldSet)}, the field set must contain {@code
   * Address}, formatted as {@code host-or-ip:port}. When the host part is a domain name, a DNS
   * lookup is performed during construction. Unknown hosts and malformed addresses are reported as
   * {@link FSParseException}.
   *
   * @param fs field set to parse
   * @throws FSParseException if {@code Address} is missing, cannot be parsed, or the host name does
   *     not resolve
   */
  public PeerAddressTrackerItem(SimpleFieldSet fs) throws FSParseException {
    super(fs);
    try {
      // Disallow unknown hosts so invalid DNS names fail fast during the load.
      peer = new Peer(fs.getString("Address"), false);
    } catch (UnknownHostException e) {
      throw new FSParseException("Unknown domain name in Address: " + e, e);
    } catch (PeerParseException e) {
      throw new FSParseException(e);
    }
  }

  /**
   * Serializes this item to a {@link SimpleFieldSet}.
   *
   * <p>The result includes all fields from {@link AddressTrackerItem#toFieldSet()} and adds {@code
   * Address}, written using {@link Peer#toStringPrefNumeric()} so that numeric IPs are preferred
   * over hostnames when persisted.
   *
   * @return field set suitable for persistence and the {@linkplain
   *     #PeerAddressTrackerItem(SimpleFieldSet) matching constructor}
   */
  @Override
  public SimpleFieldSet toFieldSet() {
    SimpleFieldSet fs = super.toFieldSet();
    fs.putOverwrite("Address", peer.toStringPrefNumeric());
    return fs;
  }
}
