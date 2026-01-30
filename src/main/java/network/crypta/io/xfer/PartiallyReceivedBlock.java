package network.crypta.io.xfer;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import network.crypta.support.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Assembles a block from fixed-size packets and tracks which packets have arrived.
 *
 * <p>This class owns the backing byte array for a block that is transmitted as {@code packets}
 * packets, each of size {@code packetSize}. Callers add packets as they arrive and may register
 * listeners that are notified for each received packet and when a transfer is aborted. Listener
 * callbacks are invoked outside the monitor to avoid executing unknown code while holding the lock.
 *
 * <p>The instance can be created either with a pre-populated data array (all packets are marked as
 * received) or with an empty buffer to be filled by incoming packets. When all packets are
 * received, {@link #getBlock()} returns the backing array; callers must treat the returned array as
 * read-only.
 *
 * <p>Thread-safety: Most methods that read or mutate internal state are synchronized on the
 * instance. Simple accessors that do not modify state may not be synchronized and therefore return
 * a moment-in-time view. Listener notifications occur after the corresponding state change and
 * outside the synchronized block.
 */
public class PartiallyReceivedBlock {
  private static final Logger LOG = LoggerFactory.getLogger(PartiallyReceivedBlock.class);

  byte[] data;
  boolean[] received;
  int receivedCount;

  /** Total number of packets that compose the block. Immutable after construction. */
  public final int packets;

  /** Size of each packet in bytes. Immutable after construction. */
  public final int packetSize;

  boolean aborted;
  boolean abortedLocally;
  int abortReason;
  String abortDescription;
  ArrayList<PacketReceivedListener> packetReceivedListeners = new ArrayList<>();

  /**
   * Creates a block with the provided backing data. All packets are considered received.
   *
   * @param packets the number of packets in the block
   * @param packetSize the size of each packet in bytes
   * @param data the backing array; its length must equal {@code packets * packetSize}
   * @throws IllegalArgumentException if {@code data.length != packets * packetSize}
   */
  public PartiallyReceivedBlock(int packets, int packetSize, byte[] data) {
    if (data.length != packets * packetSize) {
      throw new IllegalArgumentException(
          "Length of data (" + data.length + ") doesn't match packet number and size");
    }
    this.data = data;
    received = new boolean[packets];
    Arrays.fill(received, true);
    receivedCount = packets;
    this.packets = packets;
    this.packetSize = packetSize;
  }

  /**
   * Creates an empty block and allocates storage for all packets.
   *
   * @param packets the number of packets in the block
   * @param packetSize the size of each packet in bytes
   */
  public PartiallyReceivedBlock(int packets, int packetSize) {
    data = new byte[packets * packetSize];
    received = new boolean[packets];
    this.packets = packets;
    this.packetSize = packetSize;
  }

  /**
   * Registers a listener and returns the indices of packets that have already been received.
   *
   * <p>The returned deque contains packet numbers in ascending order so the caller can process
   * historical packets immediately. Future packets will trigger callbacks on the provided listener.
   *
   * @param listener the receiver of packet and abort notifications
   * @return a deque of packet indices that were already received at registration time
   * @throws AbortedException if the transfer has been aborted
   */
  public synchronized Deque<Integer> addListener(PacketReceivedListener listener)
      throws AbortedException {
    if (aborted) {
      throw new AbortedException("Adding listener to aborted PRB");
    }
    packetReceivedListeners.add(listener);
    Deque<Integer> ret = new ArrayDeque<>();
    for (int x = 0; x < packets; x++) {
      if (received[x]) {
        ret.addLast(x);
      }
    }
    return ret;
  }

  /**
   * Indicates whether a particular packet has been received.
   *
   * @param packetNo the packet index in the range {@code [0, packets)}
   * @return {@code true} if the packet has been received
   * @throws AbortedException if the transfer has been aborted
   * @throws IndexOutOfBoundsException if {@code packetNo} is outside {@code [0, packets)}
   */
  public synchronized boolean isReceived(int packetNo) throws AbortedException {
    if (aborted) {
      throw new AbortedException("PRB is aborted");
    }
    return received[packetNo];
  }

  /**
   * Returns the total number of packets for this block.
   *
   * @return the number of packets
   * @throws AbortedException if the transfer has been aborted
   */
  public synchronized int getNumPackets() throws AbortedException {
    if (aborted) {
      throw new AbortedException("PRB is aborted");
    }
    return packets;
  }

  /**
   * Returns the fixed size of each packet, in bytes.
   *
   * @return the packet size in bytes
   * @throws AbortedException if the transfer has been aborted
   */
  public synchronized int getPacketSize() throws AbortedException {
    if (aborted) {
      throw new AbortedException("PRB is aborted");
    }
    return packetSize;
  }

  /**
   * Adds a newly received packet at the specified position and notifies listeners.
   *
   * <p>Listener callbacks are invoked after the state is updated and outside the synchronized
   * block. If the packet at {@code position} was already present, the method is a no-op.
   *
   * @param position the packet index in the range {@code [0, packets)}
   * @param packet the packet data; its {@link Buffer#getLength() length} must equal {@link
   *     #packetSize}
   * @throws AbortedException if the transfer has been aborted
   * @throws IllegalArgumentException if the packet length does not equal {@code packetSize}
   * @throws IndexOutOfBoundsException if {@code position} is outside {@code [0, packets)}
   */
  public void addPacket(int position, Buffer packet) throws AbortedException {

    PacketReceivedListener[] prls;

    synchronized (this) {
      if (aborted) {
        throw new AbortedException("PRB is aborted");
      }
      if (packet.getLength() != packetSize) {
        throw new IllegalArgumentException(
            "New packet size "
                + packet.getLength()
                + " but expecting packet of size "
                + packetSize);
      }
      if (received[position]) return;

      receivedCount++;
      packet.copyTo(data, position * packetSize);
      received[position] = true;

      // Copy to an array to minimize allocations and allow notification after releasing the lock.
      // This avoids running arbitrary listener code while holding this monitor.
      prls = packetReceivedListeners.toArray(new PacketReceivedListener[0]);
    }

    for (PacketReceivedListener prl : prls) {
      prl.packetReceived(position);
    }
  }

  /**
   * Returns whether all packets have been received and the transfer has not been aborted.
   *
   * <p>This is a non-throwing convenience that checks both conditions in one call.
   *
   * @return {@code true} if all packets are present and no abort occurred
   */
  public synchronized boolean allReceivedAndNotAborted() {
    return receivedCount == packets && !aborted;
  }

  /**
   * Returns whether all packets have been received.
   *
   * <p>If the transfer has been aborted, this method throws.
   *
   * @return {@code true} if all packets are present
   * @throws AbortedException if the transfer has been aborted
   */
  public synchronized boolean allReceived() throws AbortedException {
    if (receivedCount == packets) {
      if (LOG.isTraceEnabled()) LOG.trace("Received {} of {} on {}", receivedCount, packets, this);
      return true;
    }
    if (aborted) {
      throw new AbortedException(
          "PRB is aborted: "
              + abortReason
              + " : "
              + abortDescription
              + " received "
              + receivedCount
              + " of "
              + packets
              + " on "
              + this);
    }
    return false;
  }

  /**
   * Returns the fully assembled block.
   *
   * <p>This exposes the backing array; callers should treat it as read-only. All packets must be
   * received prior to calling this method.
   *
   * @return the backing array containing the complete block
   * @throws AbortedException if the transfer has been aborted
   * @throws IllegalStateException if not all packets have been received
   */
  public synchronized byte[] getBlock() throws AbortedException {
    if (allReceived()) return data;
    throw new IllegalStateException("Tried to get block before all packets received");
  }

  /**
   * Returns a view of a single received packet.
   *
   * <p>The returned {@link Buffer} references the underlying storage; callers should not modify the
   * contents.
   *
   * @param x the packet index in the range {@code [0, packets)}
   * @return a buffer over the requested packet
   * @throws AbortedException if the transfer has been aborted
   * @throws IllegalStateException if the packet has not been received
   * @throws IndexOutOfBoundsException if {@code x} is outside {@code [0, packets)}
   */
  public synchronized Buffer getPacket(int x) throws AbortedException {
    if (aborted) {
      throw new AbortedException("PRB is aborted");
    }
    if (!received[x]) {
      throw new IllegalStateException("that packet is not received");
    }
    return new Buffer(data, x * packetSize, packetSize);
  }

  /**
   * Unregisters a listener. No effect if the listener was not registered.
   *
   * @param listener the previously registered listener
   */
  public synchronized void removeListener(PacketReceivedListener listener) {
    packetReceivedListeners.remove(listener);
  }

  /**
   * Aborts the transfer and notifies listeners.
   *
   * <p>If already complete, returns the data without changing state. If already aborted, returns
   * {@code null}. Otherwise, marks the instance as aborted, records the reason and description, and
   * notifies listeners via {@link PacketReceivedListener#receiveAborted(int, String)}. After
   * notification the listener list is cleared and no further packet events are delivered.
   *
   * @param reason an application-defined abort reason code
   * @param description human-readable detail about the abort
   * @param cancelledLocally {@code true} if this node initiated the abort rather than a timeout or
   *     remote condition
   * @return {@code null} if the transfer is (now) aborted; the backing data if all packets were
   *     already received
   */
  @SuppressWarnings("java:S1168")
  public byte[] abort(int reason, String description, boolean cancelledLocally) {
    PacketReceivedListener[] listeners;
    synchronized (this) {
      if (aborted) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Already aborted {} : reason={} description={}", this, abortReason, abortDescription);
        return null;
      }
      if (receivedCount == packets) {
        if (LOG.isDebugEnabled()) LOG.debug("Already received");
        return data;
      }
      LOG.info("Aborting PRB: {} : {} on {}", reason, description, this, new Exception("debug"));
      aborted = true;
      abortedLocally = cancelledLocally;
      abortReason = reason;
      abortDescription = description;
      listeners = packetReceivedListeners.toArray(new PacketReceivedListener[0]);
      packetReceivedListeners.clear();
    }
    for (PacketReceivedListener prl : listeners) {
      prl.receiveAborted(reason, description);
    }
    return null;
  }

  /**
   * Returns whether the transfer has been aborted.
   *
   * @return {@code true} if aborted
   */
  public synchronized boolean isAborted() {
    return aborted;
  }

  /**
   * Returns the abort reason code.
   *
   * @return the reason code; meaningful only if {@link #isAborted()} returns {@code true}
   */
  public synchronized int getAbortReason() {
    return abortReason;
  }

  /**
   * Returns the abort description text.
   *
   * @return the description; may be {@code null}; meaningful only if {@link #isAborted()} returns
   *     {@code true}
   */
  public synchronized String getAbortDescription() {
    return abortDescription;
  }

  /**
   * Listener for packet-receipt and abort events.
   *
   * <p>Callbacks are invoked without holding the {@link PartiallyReceivedBlock} monitor.
   */
  public interface PacketReceivedListener {

    /**
     * Called when a packet becomes available.
     *
     * @param packetNo the packet index in the range {@code [0, packets)}
     */
    void packetReceived(int packetNo);

    /**
     * Called when a transfer is aborted.
     *
     * @param reason the abort reason code
     * @param description human-readable detail about the abort
     */
    void receiveAborted(int reason, String description);
  }

  /**
   * Returns whether the abort was initiated locally on this node.
   *
   * <p>This accessor is not synchronized and returns a snapshot that may not reflect a concurrent
   * abort in progress.
   *
   * @return {@code true} if the abort originated locally; {@code false} otherwise
   */
  public boolean abortedLocally() {
    return abortedLocally;
  }
}
