package com.onionnetworks.fec;

import com.onionnetworks.util.Buffer;

/**
 * Main API/SPI for forward error correction codes created by {@link FECCodeFactory}.
 *
 * <p>An {@code FECCode} instance encapsulates the immutable parameters {@code k} (source packet
 * count) and {@code n} (total packets) and exposes symmetrical encode/decode operations. Instances
 * are obtained from a factory because concrete implementations may wrap native libraries or
 * algorithm-specific state that requires controlled construction. Typical call flow creates a code
 * once per data block, encodes a set of repair packets, transports them, and later decodes when a
 * sufficient subset arrives. All implementations are systematic: the first {@code k} encoded
 * packets match the original sources so unencoded data can be forwarded directly when present.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Mapping source buffers into encoded repair buffers without altering payload ownership.
 *   <li>Decoding shuffled or partially received packets into ordered source buffers.
 *   <li>Cooperating with {@link Buffer} wrappers to minimize copying in Java
 * </ul>
 *
 * <p>Thread-safety is implementation-defined; most implementations expect single-threaded use per
 * instance because internal scratch buffers are reused. Prefer creating independent instances per
 * concurrent stream. This class implements {@link AutoCloseable}; implementations that hold native
 * handles should release them in {@link #close()}.
 *
 * <p>(c) Copyright 2001 Onion Networks (c) Copyright 2000 OpenCola
 *
 * @author Justin F. Chapweske (justin@chapweske.com)
 */
public abstract class FECCode implements AutoCloseable {

  /**
   * Number of original source packets, fixed for the life of the code instance; used when
   * determining systematic packet positions and decode viability. Must be positive and not greater
   * than {@link #n}.
   */
  protected int k;

  /**
   * Total number of packets in the FEC block, including systematic and repair packets. Values
   * beyond {@link #k} represent repair indexes and bound the valid range for {@code index}
   * arguments passed to encoding and decoding operations.
   */
  protected int n;

  /**
   * Construct a new FECCode given {@code k} and {@code n} values describing a single codeword. The
   * parameters are stored verbatim and drive later encode/decode bounds checking; subclasses may
   * allocate internal lookup tables sized to these values, so callers should avoid reusing an
   * instance for mismatched blocks.
   *
   * @param k The number of source packets to be encoded or decoded; must be greater than zero.
   * @param n The total number of packets produced by the code, including repair packets; must be at
   *     least {@code k}.
   */
  protected FECCode(int k, int n) {
    this.k = k;
    this.n = n;
  }

  /**
   * Close and release any underlying native or I/O resources while leaving previously supplied
   * buffers untouched. The default implementation is a no-op, but subclasses that allocate native
   * encoder state or file descriptors should override to free them deterministically. Instances are
   * typically short-lived and used within a try-with-resources block when they manage scarce
   * handles.
   *
   * <p>Implementations should remain idempotent and thread-confined; concurrent calls are not
   * guaranteed to be safe unless documented otherwise by the subclass.
   */
  @Override
  public void close() {}

  /**
   * This method takes an array of source packets and generates a number of repair packets from
   * them. This method could have taken in only one repair packet to be generated, but in many cases
   * it is more efficient (and convenient) to encode multiple packets at once. This is especially
   * true of the NativeCode implementation where data must be copied and the Java->Native->Java
   * transition is expensive.
   *
   * @param src An array of {@code k} byte arrays holding the source packets in order; elements may
   *     share an underlying backing array provided offsets are honored.
   * @param srcOff Offsets in bytes into each {@code src} element indicating the first payload byte;
   *     each offset must be non-negative and less than or equal to the array length minus {@code
   *     packetLength}.
   * @param repair Target buffers that receive encoded repair packets; length must match {@code
   *     repairOff} and {@code index}, and each buffer must provide at least {@code packetLength}
   *     bytes from its corresponding offset.
   * @param repairOff Offsets in bytes into each {@code repair} buffer where encoded data will be
   *     written; values must align with {@code packetLength} constraints.
   * @param index Index values for the repair packets being produced; entries must lie between
   *     {@code 0} and {@code n} inclusive, and values below {@code k} represent systematic packets
   *     where encoding is effectively a copy.
   * @param packetLength The packet length in bytes; all buffers in {@code src} and {@code repair}
   *     are assumed to expose at least this many readable or writable bytes from the given offset.
   */
  protected abstract void encode(
      byte[][] src, int[] srcOff, byte[][] repair, int[] repairOff, int[] index, int packetLength);

  /**
   * This method takes an array of encoded packets and decodes them. Before the packets are decoded,
   * they are shuffled so that packets that are original source packets ({@code index < k}) are
   * positioned so that their index within the byte[][] is the same as their packet index. If the
   * <code>
   * shuffled</code> flag is set to true then it is assumed that the packets are already in the
   * proper order. If not then they will have the references of the byte[]'s shuffled within the
   * byte[][]. No data will be copied, only references swapped. This means that if the byte[][] is
   * wrapping an underlying byte[] then the shuffling procedure may bring the byte[][] out of sync
   * with the underlying data structure. From an SPI perspective this means that the implementation
   * is expected to follow the exact same behavior as the shuffle() method in this class which means
   * that you should simply call shuffle() if the flag is false.
   *
   * @param pkts An array of {@code k} byte arrays holding encoded packets, possibly shuffled; the
   *     decoder writes recovered source data back into these buffers.
   * @param pktsOff Byte offsets for each entry in {@code pkts}; values must point to the start of
   *     the packet data and stay within array bounds for {@code packetLength} bytes.
   * @param index Indexes of the supplied packets; every value must lie between {@code 0} and {@code
   *     n}. Values below {@code k} indicate systematic packets already equal to the source payload.
   * @param packetLength Length in bytes of each packet slice contained in {@code pkts}; must match
   *     the length used during encoding.
   * @param shuffled {@code true} if {@code pkts} is already arranged so that entries with {@code
   *     index < k} occupy their matching positions; {@code false} to request in-place reference
   *     shuffling before decode logic runs.
   */
  protected abstract void decode(
      byte[][] pkts, int[] pktsOff, int[] index, int packetLength, boolean shuffled);

  /**
   * This method takes an array of source packets and generates a number of repair packets from
   * them. This method could have taken in only one repair packet to be generated, but in many cases
   * it is more efficient (and convenient) to encode multiple packets at once. This is especially
   * true of the NativeCode implementation where data must be copied and the Java->Native->Java
   * transition is expensive.
   *
   * @param src Ordered {@link Buffer} instances containing {@code k} source packets; the backing
   *     byte arrays may overlap when offsets delineate distinct slices.
   * @param repair Destination {@link Buffer} instances that receive encoded packets; length must
   *     equal {@code index.length}, and each buffer must expose writable capacity for one packet.
   * @param index Packet indexes corresponding to entries in {@code repair}; values from {@code 0}
   *     to {@code n} are accepted, and values below {@code k} represent systematic copies rather
   *     than parity data.
   */
  public void encode(Buffer[] src, Buffer[] repair, int[] index) {
    byte[][] srcBufs = new byte[src.length][];
    int[] srcOffs = new int[src.length];
    byte[][] repairBufs = new byte[repair.length][];
    int[] repairOffs = new int[repair.length];
    for (int i = 0; i < srcBufs.length; i++) {
      srcBufs[i] = src[i].b;
      srcOffs[i] = src[i].off;
    }
    for (int i = 0; i < repairBufs.length; i++) {
      repairBufs[i] = repair[i].b;
      repairOffs[i] = repair[i].off;
    }

    encode(srcBufs, srcOffs, repairBufs, repairOffs, index, src[0].len);
  }

  /**
   * This method takes an array of encoded packets and decodes them. Before the packets are decoded,
   * they are shuffled so that packets that are original source packets ({@code index < k}) are so
   * that their index within the byte[][] is the same as their packet index.
   *
   * <p>We shuffle the packets using the copy mechanism to allow API users to be guaranteed that the
   * Buffer[] references will not be shuffled around. This allows the Buffer[] to wrap an underlying
   * byte[], and once decoding is complete the entire block will be in the proper order in the
   * underlying byte[]. If the packets are already in the proper position then no copying will take
   * place.
   *
   * @param pkts {@link Buffer} array containing encoded packets; on return it holds the recovered
   *     source data arranged so that entries with {@code index < k} align to their ordinal
   *     positions.
   * @param index Index values for each packet in {@code pkts}; every entry must be within {@code
   *     0..n}. Values already in the correct position avoid additional copying during the shuffle
   *     stage.
   */
  public void decode(Buffer[] pkts, int[] index) {
    // Must pre-shuffle so that no future shuffles bring the byte[]'s
    // out of sync with the Buffer[]'s.  We use copyShuffle so that
    // the Buffer[]'s don't have their references shuffled around, and
    // therefore we can have the Buffer[]'s wrapping one large byte[]
    // that will be decoded with all the data in order in that block.
    copyShuffle(pkts, index, k);

    byte[][] bufs = new byte[pkts.length][];
    int[] offs = new int[pkts.length];
    for (int i = 0; i < bufs.length; i++) {
      bufs[i] = pkts[i].b;
      offs[i] = pkts[i].off;
    }
    decode(bufs, offs, index, pkts[0].len, true);
  }

  /**
   * Copy-based shuffle that repositions all packets with {@code index < k} into their canonical
   * slots, preserving the external {@link Buffer} array ordering. Unlike {@link #shuffle(byte[][],
   * int[], int[], int)}, this variant swaps payload bytes with {@link System#arraycopy(Object, int,
   * Object, int, int)} so callers that wrap a contiguous {@code byte[]} with multiple {@link
   * Buffer} views keep their Buffer references stable after decoding completes.
   *
   * @param pkts Buffer views of encoded packets; contents are rearranged by copying but reference
   *     order remains intact for callers.
   * @param index Current packet indexes aligned with {@code pkts}; values below {@code k} are
   *     placed at matching offsets, and duplicates trigger {@link IllegalArgumentException}.
   * @param k Number of systematic packets expected at the start of {@code pkts}; must be less than
   *     or equal to {@code pkts.length}.
   */
  protected static void copyShuffle(Buffer[] pkts, int[] index, int k) {
    byte[] b = null;
    int i = 0;
    while (i < k) {
      if (index[i] >= k || index[i] == i) {
        i++;
      } else {
        // put pkts in the right position (first check for conflicts).
        int c = index[i];

        if (index[c] == c) {
          throw new IllegalArgumentException("Shuffle Error: Duplicate indexes at " + i);
        }
        // swap(index[c],index[i])
        int tmp = index[i];
        index[i] = index[c];
        index[c] = tmp;

        // swap(pkts[c],pkts[i])
        if (b == null) {
          b = new byte[pkts[0].len];
        }
        System.arraycopy(pkts[i].b, pkts[i].off, b, 0, b.length);
        System.arraycopy(pkts[c].b, pkts[c].off, pkts[i].b, pkts[i].off, b.length);
        System.arraycopy(b, 0, pkts[c].b, pkts[c].off, b.length);
      }
    }
  }

  /**
   * Shuffle an array of packet buffers by swapping references until all entries with {@code index <
   * k} occupy positions equal to their index. Offsets and index metadata are swapped alongside
   * buffers to preserve alignment; the operation is performed in-place and does not copy payload
   * data.
   *
   * @param pkts Packet byte arrays to reorder in-place; entries are swapped rather than copied.
   * @param pktsOff Offsets that accompany each packet array; swapped in lockstep with {@code pkts}
   *     to keep packet slices aligned.
   * @param index Index values describing the current position of each packet; values below {@code
   *     k} are considered systematic and must end up at their matching offset after the shuffle
   *     completes.
   * @param k Number of systematic packets expected at the front of the array; must not exceed the
   *     array length.
   */
  protected static void shuffle(byte[][] pkts, int[] pktsOff, int[] index, int k) {
    int i = 0;
    while (i < k) {
      if (index[i] >= k || index[i] == i) {
        i++;
      } else {
        // put pkts in the right position (first check for conflicts).
        int c = index[i];

        if (index[c] == c) {
          throw new IllegalArgumentException("Shuffle error at " + i);
        }
        // swap(pkts[c],pkts[i])
        byte[] tmp = pkts[i];
        pkts[i] = pkts[c];
        pkts[c] = tmp;

        // swap(pktsOff[c],pktsOff[i])
        int tmp2 = pktsOff[i];
        pktsOff[i] = pktsOff[c];
        pktsOff[c] = tmp2;

        // swap(index[c],index[i])
        tmp2 = index[i];
        index[i] = index[c];
        index[c] = tmp2;
      }
    }
  }
}
