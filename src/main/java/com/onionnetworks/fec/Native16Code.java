package com.onionnetworks.fec;

import com.onionnetworks.util.NativeDeployer;
import java.util.logging.Logger;

/**
 * JNI-backed forward error correction code that processes 16-bit wide symbols.
 *
 * <p>This implementation delegates parity generation and repair to the native {@code fec16} library
 * while exposing a compact API that mirrors {@link FECCode}. Typical use is to construct one
 * instance per coding scheme (with {@code k} source blocks and {@code n} total blocks), feed it
 * contiguous packet buffers across repeated encode/decode cycles, and invoke {@link #close()} when
 * finished.
 *
 * <p>Instances are lightweight but not documented as thread-safe; coordinate access if the native
 * layer requires serialization. Packet buffers must be 16-bit aligned because the native routines
 * interpret arrays as unsigned short sequences. Encoding is order-sensitive, whereas decoding can
 * reshuffle inputs when necessary.
 *
 * <p>(c) Copyright 2001 Onion Networks (c) Copyright 2000 OpenCola
 *
 * @author Justin F. Chapweske (justin@chapweske.com)
 * @see FECCode
 */
public class Native16Code extends FECCode {

  private static final Logger LOGGER = Logger.getLogger(Native16Code.class.getName());

  // One must be very, very careful not to let code escape, it stores the
  // memory address of a fec_parms struct and if modified could give an
  // attacker the ability to point to anything in memory.
  private final long code;

  /**
   * Exposes the native handle for test harnesses and closely coupled JNI peers.
   *
   * <p>The returned value is the opaque pointer to the underlying {@code fec_parms} structure
   * allocated by {@link #nativeNewFEC(int, int)}. Callers must treat it as read-only metadata and
   * must never attempt to free or reinterpret the address. The handle remains valid until {@link
   * #close()} completes, after which callers should discard cached references.
   *
   * @return native {@code fec_parms} pointer associated with this instance; undefined after close
   */
  @SuppressWarnings("unused")
  protected final long getNativeHandle() {
    return code;
  }

  static {
    String path = NativeDeployer.getLibraryPath(Native8Code.class.getClassLoader(), "fec16");
    if (path != null) {
      System.load(path);
      initFEC();
    } else {
      LOGGER.warning(
          () -> "Unable to find native library for fec16 for platform " + NativeDeployer.OS_ARCH);
      LOGGER.warning(() -> String.valueOf((Object) null));
    }
  }

  /**
   * Creates a native FEC encoder/decoder configured for 16-bit symbols.
   *
   * <p>Construction allocates the native {@code fec_parms} structure using {@link
   * #nativeNewFEC(int, int)} and keeps the returned pointer for subsequent encode/decode calls.
   * Callers should choose {@code k} to reflect the number of original data fragments and {@code n}
   * to include both data and repair fragments. The instance can be reused across many invocations
   * and must be closed when no longer required.
   *
   * @param k number of data fragments to protect; must match encode/decode inputs
   * @param n total fragments including repair; must be greater than or equal to {@code k}
   */
  public Native16Code(int k, int n) {
    super(k, n);
    code = nativeNewFEC(k, n);
  }

  /**
   * Generates repair symbols for the supplied source packets using the native encoder.
   *
   * <p>The method expects all packet buffers to be 16-bit aligned; an {@link
   * IllegalArgumentException} is thrown when {@code packetLength} is odd. Source and repair arrays
   * are passed directly to JNI without copying, so callers must ensure offsets and indices are
   * valid for the requested packet length. This operation is not synchronized; coordinate
   * concurrent use externally if the native library is single-threaded.
   *
   * @param src source packet buffers containing the original data fragments
   * @param srcOff offsets into each source buffer where valid data begins, in bytes
   * @param repair destination buffers that will be filled with computed repair symbols
   * @param repairOff offsets into each repair buffer where writing should start, in bytes
   * @param index indices of repair symbols to generate, aligned with {@code repair}
   * @param packetLength length in bytes of each packet; must be an even value
   * @throws IllegalArgumentException if {@code packetLength} is not 16-bit aligned
   */
  protected void encode(
      byte[][] src, int[] srcOff, byte[][] repair, int[] repairOff, int[] index, int packetLength) {

    if (packetLength % 2 != 0) {
      throw new IllegalArgumentException("For 16 bit codes, buffers " + "must be 16 bit aligned.");
    }
    nativeEncode(src, srcOff, index, repair, repairOff, k, packetLength);
  }

  /**
   * Reconstructs missing data packets from a mix of data and repair fragments.
   *
   * <p>The method accepts packets in arbitrary order. When {@code inOrder} is {@code false} it
   * shuffles the arrays in place so the native decoder receives contiguous data, preserving caller
   * offsets. Packet lengths must remain even to satisfy the 16-bit alignment requirement enforced
   * by the native library.
   *
   * @param pkts packet buffers containing data and repair fragments to decode
   * @param pktsOff offsets within each packet buffer where valid data starts, in bytes
   * @param index indices describing which fragments are present in {@code pkts}
   * @param packetLength length in bytes for each packet; must be an even value
   * @param inOrder whether packets are already ordered by index and need no shuffling
   * @throws IllegalArgumentException if {@code packetLength} is not 16-bit aligned
   */
  protected void decode(
      byte[][] pkts, int[] pktsOff, int[] index, int packetLength, boolean inOrder) {
    if (packetLength % 2 != 0) {
      throw new IllegalArgumentException("For 16 bit codes, buffers " + "must be 16 bit aligned.");
    }
    if (!inOrder) {
      shuffle(pkts, pktsOff, index, k);
    }
    nativeDecode(pkts, pktsOff, index, k, packetLength);
  }

  /**
   * JNI entry point that encodes repair symbols for 16-bit packets.
   *
   * <p>Implementations must honor the alignment guarantees documented on {@link #encode(byte[][],
   * int[], byte[][], int[], int[], int)} and should operate without modifying the provided input
   * buffers. The {@code k} parameter mirrors the constructor value and is supplied to simplify
   * native verification.
   *
   * @param src source packet buffers containing the original data fragments
   * @param srcOff offsets into each source buffer where valid data begins, in bytes
   * @param index indices of repair symbols to generate, aligned with {@code repair}
   * @param repair destination buffers that will receive generated repair symbols
   * @param repairOff offsets into each repair buffer where writing should start, in bytes
   * @param k number of data fragments expected by the native encoder
   * @param packetLength length in bytes of each packet; must be an even value
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
   * JNI entry point that decodes mixed data and repair packets back into ordered fragments.
   *
   * <p>Callers arrange packet ordering and alignment before invoking this method. Implementations
   * must read from the supplied buffers starting at {@code pktsOff} and write corrected data in
   * place. The {@code k} parameter is provided for native validation and mirrors the constructor
   * argument.
   *
   * @param pkts packet buffers containing data and repair fragments to decode
   * @param pktsOff offsets within each packet buffer where valid data starts, in bytes
   * @param index indices describing which fragments are present in {@code pkts}
   * @param k number of data fragments expected by the native decoder
   * @param packetLength length in bytes for each packet; must be an even value
   */
  protected native void nativeDecode(
      byte[][] pkts, int[] pktsOff, int[] index, int k, int packetLength);

  /**
   * Allocates a native {@code fec_parms} structure for the requested code dimensions.
   *
   * <p>The returned pointer is stored as the immutable {@code code} field and later exposed via
   * {@link #getNativeHandle()}. Implementations must allocate any auxiliary native state required
   * by encode/decode operations and should validate that {@code n} is at least {@code k}.
   *
   * @param k number of data fragments the code protects
   * @param n total number of fragments, including repair symbols
   * @return opaque pointer to allocated native state for this code instance
   */
  protected synchronized native long nativeNewFEC(int k, int n);

  /**
   * Releases the native {@code fec_parms} structure associated with this instance.
   *
   * <p>Invoked from {@link #close()} exactly once; implementations must tolerate redundant calls to
   * support idempotent shutdown paths. After this invocation completes, the pointer returned by
   * {@link #getNativeHandle()} is no longer valid.
   */
  protected synchronized native void nativeFreeFEC();

  /**
   * Initializes native library state required before creating any {@code Native16Code} instances.
   *
   * <p>Called during static initialization immediately after the JNI library is loaded.
   * Implementing code should set up any global tables or caches needed by {@link #nativeNewFEC(int,
   * int)}.
   */
  protected static synchronized native void initFEC();

  private volatile boolean closed;

  /**
   * Releases native resources associated with this code instance.
   *
   * <p>This method calls {@link #nativeFreeFEC()} once to dispose of the underlying {@code
   * fec_parms} structure and marks the instance as closed using a volatile flag. The method is
   * idempotent and safe to invoke from multiple threads; redundant calls return immediately without
   * reentering JNI. Callers should invoke this method promptly after finishing encode/decode work
   * to prevent native memory from leaking and should avoid further operations once closure
   * completes.
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
   * Returns a diagnostic description containing the configured code dimensions.
   *
   * <p>The string mirrors the simple {@code ClassName[k=...,n=...]} pattern used by other {@link
   * FECCode} implementations, making it suitable for logs and troubleshooting output. The values
   * reflect the constructor parameters and do not change during the lifetime of the instance. The
   * method performs no native calls and therefore cannot fail.
   *
   * @return human-readable summary of the code dimensions for debugging purposes
   */
  public String toString() {
    return "Native16Code[k=" + k + ",n=" + n + "]";
  }
}
