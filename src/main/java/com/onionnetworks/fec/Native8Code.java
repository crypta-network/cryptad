package com.onionnetworks.fec;

import com.onionnetworks.util.NativeDeployer;
import java.util.logging.Logger;

/**
 * JNI-backed implementation of the 8-bit forward error correction code used by the Onion Networks
 * encoder.
 *
 * <p>This class delegates encode and decode operations to the {@code fec8} native library and
 * stores its opaque handle in {@link #code}. It follows the {@link FECCode} SPI without extra Java
 * buffering, so callers usually build one instance per {@code k}/{@code n} combination and discard
 * it once that block is processed.
 *
 * <p>Typical usage creates the code, generates repair packets, and later decodes when enough
 * packets arrive. {@link #close()} frees the native state; use try-with-resources as shown below.
 *
 * <pre>{@code
 * try (Native8Code code = new Native8Code(k, n)) {
 *   code.encode(src, srcOff, repair, repairOff, repairIndex, packetLength);
 * }
 * }</pre>
 *
 * <p>Thread-safety is limited to construction and teardown; concurrent encode/decode calls on the
 * same instance are not synchronized. The static initializer loads the shared library once per
 * class loader and logs discovery failures.
 *
 * @author Justin F. Chapweske (justin@chapweske.com)
 * @see FECCode
 */
public class Native8Code extends FECCode {

  private static final Logger LOGGER = Logger.getLogger(Native8Code.class.getName());

  // One must be very, very careful not to let code escape, it stores the
  // memory address of a fec_parms struct and if modified could give an
  // attacker the ability to point to anything in memory.
  private final long code;

  static {
    String path = NativeDeployer.getLibraryPath(Native8Code.class.getClassLoader(), "fec8");
    if (path != null) {
      System.load(path);
      initFEC();
    } else {
      LOGGER.info(
          () -> "Unable to find native library for fec8 for platform " + NativeDeployer.OS_ARCH);
      LOGGER.info(() -> String.valueOf((Object) null));
    }
  }

  /**
   * Create a new native-backed code instance for the given systematic and total packet counts.
   *
   * <p>The constructor immediately allocates the underlying native structures via {@link
   * #nativeNewFEC(int, int)} and logs the resulting handle for trace-level diagnostics. The {@code
   * k} and {@code n} values are immutable for the life of the instance; callers should instantiate
   * separate objects when working with differently sized FEC blocks to avoid mismatched buffers
   * during later encode or decode calls.
   *
   * @param k Number of original source packets in the block; must be positive and not exceed {@code
   *     n}.
   * @param n Total packet count for the codeword, including parity packets; must be at least {@code
   *     k}.
   */
  public Native8Code(int k, int n) {
    super(k, n);
    code = nativeNewFEC(k, n);
    LOGGER.finest(() -> "Initialized native fec8 handle " + code);
  }

  /**
   * Encode one or more repair packets from the provided source payloads using the native
   * implementation.
   *
   * <p>This override forwards directly to {@link #nativeEncode(byte[][], int[], int[], byte[][],
   * int[], int, int)}. The method expects aligned buffer arrays sized to the {@code k} and {@code
   * n} values declared at construction and does not perform deep validation beyond the base class
   * guarantees. Callers should ensure that offsets and packet lengths remain within array bounds to
   * prevent undefined native behavior.
   *
   * @param src Ordered source packet buffers; length should equal {@code k} for systematic data.
   * @param srcOff Offsets in bytes for each source packet; values must leave {@code packetLength}
   *     readable bytes in every buffer.
   * @param repair Destination buffers that receive parity packets; indexes correspond one-to-one
   *     with {@code index} entries.
   * @param repairOff Offsets in bytes into each repair buffer where encoded bytes are written; each
   *     value must leave {@code packetLength} writable bytes.
   * @param index Packet indexes to generate, typically values {@code >= k}; systematic indexes are
   *     treated as direct copies by the native code.
   * @param packetLength Number of bytes per packet slice shared by all buffers in this operation.
   */
  @Override
  protected void encode(
      byte[][] src, int[] srcOff, byte[][] repair, int[] repairOff, int[] index, int packetLength) {

    nativeEncode(src, srcOff, index, repair, repairOff, k, packetLength);
  }

  /**
   * Decode received packets into their original order, invoking the native decoder after optional
   * shuffling.
   *
   * <p>If {@code inOrder} is {@code false}, this method reorders the provided packet references so
   * that systematic packets occupy their canonical positions prior to delegating to the native
   * routine. No copying occurs during this shuffle; only array references are swapped, keeping the
   * caller-owned buffers intact. The native decoder expects exactly {@code k} systematic positions
   * to be satisfied by the combination of provided data and computed repairs.
   *
   * @param pkts Packet buffers containing systematic and repair data; contents may be rearranged in
   *     place when {@code inOrder} is {@code false}.
   * @param pktsOff Offsets into each packet buffer pointing to the packet start; values must leave
   *     {@code packetLength} readable bytes.
   * @param index Packet index for each entry in {@code pkts}; values below {@code k} denote source
   *     packets, while values above represent repairs.
   * @param packetLength Size in bytes of every packet handled by this decode call; must match the
   *     length used during encoding.
   * @param inOrder {@code true} if {@code pkts} is already arranged so {@code index < k} entries
   *     occupy matching positions; {@code false} to request an in-place shuffle first.
   */
  @Override
  protected void decode(
      byte[][] pkts, int[] pktsOff, int[] index, int packetLength, boolean inOrder) {
    // We need to shuffle at this point so that the Java byte[][] stays
    // in sync with what happens in native land.
    if (!inOrder) {
      shuffle(pkts, pktsOff, index, k);
    }
    nativeDecode(pkts, pktsOff, index, k, packetLength);
  }

  /**
   * Native bridge that encodes a batch of packets without additional Java-side checks.
   *
   * <p>All arrays must be non-null and sized consistently with {@code k} and {@code n}. The native
   * library interprets indexes below {@code k} as systematic packets and copies source payloads to
   * the corresponding repair slots. Offsets and lengths are trusted verbatim; callers must guard
   * against out-of-bounds access before invoking this method.
   *
   * @param src Source packet buffers presented in systematic order; elements may share backing
   *     arrays when offsets isolate distinct regions.
   * @param srcOff Byte offsets into each source buffer where packet data begins; every value must
   *     be within bounds for {@code packetLength} bytes.
   * @param index Packet indexes to generate; values from {@code 0} to {@code n - 1} are expected
   *     and usually increase monotonically for parity generation.
   * @param repair Destination buffers for parity output; length must match {@code index.length}.
   * @param repairOff Offsets into each repair buffer identifying the first writable byte for the
   *     encoded packet.
   * @param k Systematic packet count configured for this code; forwarded for native bounds
   *     checking.
   * @param packetLength Length in bytes of each packet slice written during this call.
   */
  protected native void nativeEncode(
      byte[][] src,
      int[] srcOff,
      int[] index,
      byte[][] repair,
      int[] repairOff,
      int k,
      int packetLength);

  /**
   * Native bridge that reconstructs source packets from a mixture of systematic and repair data.
   *
   * <p>Buffers and offsets are trusted exactly as provided. The native implementation consumes the
   * packet indexes to decide which packets are already present and which must be synthesized. The
   * method mutates {@code pkts} in place, writing recovered source data into the supplied buffers
   * beginning at each offset.
   *
   * @param pkts Packet buffers that will be updated with decoded payloads; entries may already hold
   *     systematic data.
   * @param pktsOff Offsets in bytes to the start of each packet within {@code pkts}; must allow
   *     {@code packetLength} readable and writable bytes.
   * @param index Packet identifiers parallel to {@code pkts}; duplicates or out-of-range values may
   *     cause native errors.
   * @param k Systematic packet count configured for this code instance; defines the boundary
   *     between source and repair indexes.
   * @param packetLength Number of bytes per packet the decoder should consume and emit.
   */
  protected native void nativeDecode(
      byte[][] pkts, int[] pktsOff, int[] index, int k, int packetLength);

  /**
   * Allocate a new native FEC context configured for the supplied packet counts.
   *
   * <p>The returned handle is an opaque pointer into the native library and must later be released
   * via {@link #nativeFreeFEC()}. Calls are synchronized to ensure a single allocation occurs when
   * multiple threads race to build instances during class loading or dependency injection.
   *
   * @param k Systematic packet count to embed in the native context; must mirror the constructor
   *     argument.
   * @param n Total packet count ({@code k} plus repair packets) that bounds valid indexes for this
   *     context.
   * @return Opaque native handle identifying the allocated context; never {@code 0} on success.
   */
  protected synchronized native long nativeNewFEC(int k, int n);

  /**
   * Release the native FEC context previously allocated for this instance.
   *
   * <p>This method is idempotent on the native side and synchronized to avoid double frees when
   * concurrent threads attempt closure. Callers should pair it with {@link #nativeNewFEC(int, int)}
   * and rely on {@link #close()} for higher-level lifecycle management.
   */
  protected synchronized native void nativeFreeFEC();

  /**
   * Perform any required one-time native initialization for the fec8 library.
   *
   * <p>The static initializer invokes this method after successfully loading the shared library.
   * Implementations typically populate lookup tables or perform architecture-specific setup. The
   * synchronization ensures only one thread runs the initialization sequence per class loader.
   */
  protected static synchronized native void initFEC();

  private volatile boolean closed;

  /**
   * Release native resources associated with this code instance in an idempotent manner.
   *
   * <p>If the instance is already closed, the method returns immediately. Otherwise, it
   * synchronizes to guard the native handle and invokes {@link #nativeFreeFEC()} once, marking the
   * instance as closed even if native teardown throws. Callers should prefer try-with-resources to
   * ensure this cleanup runs when encode/decode operations are scoped to a single block.
   */
  @Override
  public void close() {
    if (closed) return;
    synchronized (this) {
      if (closed) return;
      try {
        nativeFreeFEC();
      } finally {
        closed = true;
      }
    }
  }

  /**
   * Describe the code instance using its configured packet counts.
   *
   * <p>The returned string is intended for debugging and logging and does not expose the native
   * handle. Format is {@code Native8Code[k=<k>,n=<n>]} to mirror the {@code k}/{@code n}
   * constructor values.
   *
   * @return Human-readable description containing the configured {@code k} and {@code n} values.
   */
  @Override
  public String toString() {
    return "Native8Code[k=" + k + ",n=" + n + "]";
  }
}
