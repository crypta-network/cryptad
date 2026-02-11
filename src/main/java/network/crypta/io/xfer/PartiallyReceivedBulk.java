package network.crypta.io.xfer;

import java.io.IOException;
import java.util.Arrays;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.RetrievalException;
import network.crypta.support.BitArray;
import network.crypta.support.api.RandomAccessBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks and persists a large multi-block transfer.
 *
 * <p>This class is the bulk-file counterpart to {@code PartiallyReceivedBlock}. It maintains an
 * in-memory bitmap of received blocks and commits payloads to a {@link
 * network.crypta.support.api.RandomAccessBuffer}. The current approach keeps one bit per block in
 * RAM, which is adequate for fairly large files (for example, roughly 128&nbsp;KiB of bitmap memory
 * for a 1&nbsp;GiB file at 64&nbsp;KiB blocks). The representation may be compressed in the future
 * without changing the external behavior.
 *
 * <p>Concurrency: the instance synchronizes updates to its internal bitmap and transmitter list.
 * Callers must not rely on finer-grained atomicity than provided by the synchronized methods. I/O
 * is performed outside the synchronized section to avoid long critical sections. On fatal errors,
 * {@link #abort(int, String)} transitions the instance to an aborted state, notifies registered
 * collaborators, and closes the underlying buffer.
 *
 * @author toad
 */
public class PartiallyReceivedBulk {
  private static final Logger LOG = LoggerFactory.getLogger(PartiallyReceivedBulk.class);

  /**
   * Total size of the data being received, in bytes. The value does not need to be a multiple of
   * {@link #blockSize} (the last block may be partial).
   */
  final long size;

  /** Size of each transfer block, in bytes. */
  final int blockSize;

  private final RandomAccessBuffer raf;

  /** Bitmap indicating which blocks have been received and written. */
  private final BitArray blocksReceived;

  final int blocks;
  private BulkTransmitter[] transmitters;
  final MessageCore usm;

  /** The sole {@link BulkReceiver} coordinating inbound packets for this bulk. */
  BulkReceiver recv;

  private int blocksReceivedCount;
  // Abort status (accessed by package classes and getters)
  boolean aborted;
  int abortReason;
  String abortDescription;

  /**
   * Creates a new bulk-transfer accumulator.
   *
   * @param usm Message core used by collaborating components.
   * @param size Total size of the incoming data, in bytes. Does not need to be a multiple of {@code
   *     blockSize}.
   * @param blockSize Size of each block, in bytes.
   * @param raf Random-access buffer used to persist the received data. The buffer must be at least
   *     {@code size} bytes large.
   * @param initialState When {@code true}, marks every block as already present (e.g., whole-file
   *     already cached). When {@code false}, marks all blocks as missing.
   * @throws IllegalArgumentException If {@code size} implies more than {@link Integer#MAX_VALUE}
   *     blocks, or when {@code raf.size() < size}.
   */
  public PartiallyReceivedBulk(
      MessageCore usm, long size, int blockSize, RandomAccessBuffer raf, boolean initialState) {
    this.size = size;
    this.blockSize = blockSize;
    this.raf = raf;
    this.usm = usm;
    long blocksCount = (size + blockSize - 1) / blockSize;
    if (blocksCount > Integer.MAX_VALUE) throw new IllegalArgumentException("Too big");
    this.blocks = (int) blocksCount;
    blocksReceived = new BitArray(this.blocks);
    if (initialState) {
      blocksReceived.setAllOnes();
      blocksReceivedCount = this.blocks;
    }
    if (raf.size() < size) {
      throw new IllegalArgumentException("Backing buffer too small: " + raf.size() + " < " + size);
    }
  }

  /**
   * Returns a snapshot of the received-blocks bitmap.
   *
   * <p>Used by {@link BulkTransmitter} to discover which blocks are already present at construction
   * time. Callers must already hold this instance's monitor.
   *
   * @return a copy of {@link #blocksReceived}.
   */
  synchronized BitArray cloneBlocksReceived() {
    return new BitArray(blocksReceived);
  }

  /**
   * Registers a {@link BulkTransmitter} to receive block-availability notifications.
   *
   * @param bt transmitter to register.
   */
  synchronized void add(BulkTransmitter bt) {
    if (transmitters == null) transmitters = new BulkTransmitter[] {bt};
    else {
      transmitters = Arrays.copyOf(transmitters, transmitters.length + 1);
      transmitters[transmitters.length - 1] = bt;
    }
  }

  /**
   * Commits a received block to storage and updates the state, then notifies transmitters.
   *
   * <p>Validates that {@code length} is at least the expected number of bytes for the addressed
   * block. If validation or storage fails, the transfer is aborted for an appropriate reason.
   * Blocks that are already marked as received are ignored.
   *
   * @param blockNum zero-based block index.
   * @param data source buffer containing the block payload.
   * @param offset offset into {@code data} where the payload starts.
   * @param length number of bytes available from {@code data[offset...]}; must be at least the
   *     expected block length (short final block permitted).
   */
  @SuppressWarnings("java:S1181")
  void received(int blockNum, byte[] data, int offset, int length) {
    if (blockNum >= blocks) {
      LOG.error("Received block {} of {} !", blockNum, blocks);
      return;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Received block {}", blockNum);
    BulkTransmitter[] notifyBTs;
    long fileOffset = (long) blockNum * (long) blockSize;
    int bs = (int) Math.min(blockSize, size - fileOffset);
    if (length < bs) {
      String err = "Data too short! Should be " + bs + " actually " + length;
      LOG.error("{} for {}", err, this);
      abort(RetrievalException.PREMATURE_EOF, err);
      return;
    }
    synchronized (this) {
      if (blocksReceived.bitAt(blockNum)) return; // Ignore duplicates
      // Optimistically mark as received before I/O; abort() will notify on failure.
      blocksReceived.setBit(blockNum, true);
      blocksReceivedCount++;
      notifyBTs = transmitters;
    }
    try {
      raf.pwrite(fileOffset, data, offset, bs);
    } catch (Throwable t) {
      LOG.error("Failed to store received block {} on {} : {}", blockNum, this, t, t);
      abort(RetrievalException.IO_ERROR, t.toString());
    }
    if (notifyBTs == null) return;
    for (BulkTransmitter notifyBT : notifyBTs) {
      // Not a generic callback; allow exceptions to surface during development/tests.
      notifyBT.blockReceived(blockNum);
    }
  }

  /**
   * Aborts the transfer, notifies collaborators, and closes the underlying buffer.
   *
   * <p>After abortion, {@link #isAborted()} returns {@code true}. Registered transmitters and the
   * current receiver (if any) are notified via their respective callbacks. The {@link
   * RandomAccessBuffer} is closed.
   *
   * @param errCode a {@link RetrievalException} error code that explains the reason.
   * @param why human-readable description of the failure; may be {@code null}.
   */
  public void abort(int errCode, String why) {
    if (LOG.isDebugEnabled())
      LOG.info(
          "Aborting {}: {} : {} first missing is {}",
          this,
          errCode,
          why,
          blocksReceived.firstZero(0),
          new Exception("debug"));
    BulkTransmitter[] notifyBTs;
    BulkReceiver notifyBR;
    synchronized (this) {
      aborted = true;
      abortReason = errCode;
      abortDescription = why;
      notifyBTs = transmitters;
      notifyBR = recv;
    }
    if (notifyBTs != null) {
      for (BulkTransmitter notifyBT : notifyBTs) {
        notifyBT.onAborted();
      }
    }
    if (notifyBR != null) notifyBR.onAborted();
    raf.close();
  }

  /**
   * Returns whether the transfer has been aborted.
   *
   * @return {@code true} if {@link #abort(int, String)} has been called; otherwise {@code false}.
   */
  public synchronized boolean isAborted() {
    return aborted;
  }

  /**
   * Returns whether all blocks have been received and written.
   *
   * @return {@code true} when every block is present; otherwise {@code false}.
   */
  public synchronized boolean hasWholeFile() {
    return blocksReceivedCount >= blocks;
  }

  /**
   * Reads and returns the bytes for a stored block.
   *
   * <p>On I/O failure, the method logs, aborts the transfer with {@link
   * RetrievalException#IO_ERROR}, and returns {@code null} to preserve historical behavior.
   *
   * @param blockNum zero-based block index.
   * @return the block contents, or {@code null} on failure.
   */
  public byte[] getBlockData(int blockNum) {
    long fileOffset = (long) blockNum * (long) blockSize;
    int bs = (int) Math.min(blockSize, size - fileOffset);
    byte[] data = new byte[bs];
    try {
      raf.pread(fileOffset, data, 0, bs);
    } catch (IOException e) {
      LOG.error("Failed to read stored block {} on {} : {}", blockNum, this, e, e);
      abort(RetrievalException.IO_ERROR, e.toString());
      data = null; // Preserve existing contract: return null on failure
    }
    return data;
  }

  /**
   * Unregisters a {@link BulkTransmitter}. No-op when the transmitter is not currently registered.
   *
   * @param remove transmitter to remove.
   */
  public synchronized void remove(BulkTransmitter remove) {
    boolean found = false;
    for (BulkTransmitter t : transmitters) {
      if (t == remove) {
        found = true;
        break;
      }
    }
    if (!found) return;
    BulkTransmitter[] newTrans = new BulkTransmitter[transmitters.length - 1];
    int j = 0;
    for (BulkTransmitter t : transmitters) {
      if (t == remove) continue;
      newTrans[j++] = t;
    }
    transmitters = newTrans;
  }

  /**
   * Returns the numeric abort reason associated with the last {@link #abort(int, String)} call.
   *
   * @return a {@link RetrievalException} reason code.
   */
  public int getAbortReason() {
    return abortReason;
  }

  /**
   * Returns the descriptive abort message associated with the last {@link #abort(int, String)}
   * call.
   *
   * @return a human-readable description; may be {@code null}.
   */
  public String getAbortDescription() {
    return abortDescription;
  }
}
