package network.crypta.io;

import java.net.InetAddress;
import java.net.UnknownHostException;
import network.crypta.node.FSParseException;
import network.crypta.support.SimpleFieldSet;

/**
 * {@link AddressTrackerItem} specialization that binds the activity tracking state to a concrete
 * {@link InetAddress} (host address, no port).
 *
 * <p>This class adds only the address identity; all timing, counters, and gap logic live in the
 * superclass. Serialization via {@link #toFieldSet()} writes the address under the key {@code
 * Address} using {@link InetAddress#getHostAddress()} so the textual form is the numeric
 * representation. The {@linkplain #InetAddressAddressTrackerItem(SimpleFieldSet) field-set
 * constructor} accepts any string that {@link InetAddress#getByName(String)} resolves.
 *
 * <p>Threading: mutation and access methods are inherited from {@code AddressTrackerItem}; they are
 * synchronized where relevant. This type does not add additional mutable state beyond the final
 * {@link #addr} reference.
 */
public class InetAddressAddressTrackerItem extends AddressTrackerItem {

  /**
   * Create a tracker for the given address with known upper bounds for the initial "no packets"
   * window.
   *
   * @param timeDefinitelyNoPacketsReceived the earliest time (ms since epoch) at which receiving
   *     was definitely impossible for this address
   * @param timeDefinitelyNoPacketsSent the earliest time (ms since epoch) at which sending was
   *     definitely impossible
   * @param addr the {@link InetAddress} to track; the reference is stored as-is and not cloned
   */
  public InetAddressAddressTrackerItem(
      long timeDefinitelyNoPacketsReceived, long timeDefinitelyNoPacketsSent, InetAddress addr) {
    super(timeDefinitelyNoPacketsReceived, timeDefinitelyNoPacketsSent);
    this.addr = addr;
  }

  /** The address whose activity is being tracked. Never reassigned after construction. */
  public final InetAddress addr;

  /**
   * Serialize this tracker to a {@link SimpleFieldSet} and include the numeric textual form of the
   * {@linkplain #addr address} under key {@code Address}.
   *
   * @return a field set suitable for persistence and later reconstruction via {@link
   *     #InetAddressAddressTrackerItem(SimpleFieldSet)}
   */
  @Override
  public SimpleFieldSet toFieldSet() {
    SimpleFieldSet fs = super.toFieldSet();
    fs.putOverwrite("Address", addr.getHostAddress());
    return fs;
  }

  /**
   * Reconstruct a tracker from its serialized {@link SimpleFieldSet} form.
   *
   * <p>Expected keys include those written by {@link AddressTrackerItem#toFieldSet()} and, in
   * addition, {@code Address}. The address value is resolved using {@link
   * InetAddress#getByName(String)}.
   *
   * @param fs field set produced by {@link #toFieldSet()}
   * @throws FSParseException if {@code Address} is missing or cannot be resolved by {@code
   *     InetAddress.getByName}
   */
  public InetAddressAddressTrackerItem(SimpleFieldSet fs) throws FSParseException {
    super(fs);
    try {
      addr = InetAddress.getByName(fs.getString("Address"));
    } catch (UnknownHostException e) {
      throw new FSParseException("Unknown domain name in Address: " + e, e);
    }
  }
}
