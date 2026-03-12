/* (PD) 2006 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: KzTreeHandler.java,v 1.2 2006/07/14 04:58:39 gojomo Exp $
 */
package org.bitpedia.collider.core;

/**
 * Computes Kazaa-style hash trees over streaming content using MD5 digests.
 *
 * <p>The handler accumulates input in {@value #KZTREE_BLOCKSIZE}-byte leaves, hashes each leaf with
 * MD5, and progressively composes parent nodes until a single root digest remains. Callers
 * typically create an instance, invoke {@link #analyzeInit()}, feed data through {@link
 * #analyzeUpdate(byte[], int, int)}, and finish with {@link #analyzeFinal()}. The instance is
 * stateful and not thread-safe; reuse requires a fresh initialization before processing another
 * payload. Zero-length inputs are handled by hashing an empty block, and single-block inputs are
 * rehashed to align with the KZ tree specification.
 *
 * <p><strong>Responsibilities</strong>
 *
 * <ul>
 *   <li>Maintain in-progress leaf and node stacks while streaming bytes.
 *   <li>Produce deterministic MD5-based tree roots for content integrity checks.
 *   <li>Ensure edge cases (partial leaves, odd generations, empty input) match legacy behavior.
 * </ul>
 *
 * <p>Mutating operations update internal buffers; no defensive copies are kept aside from the final
 * digest returned to the caller. Callers should synchronize externally when sharing an instance
 * across threads.
 */
public class KzTreeHandler {

  /* MD5 hash result size, in bytes */
  private static final int MD5_SIZE = 16;

  /* size of each block independently tiger-hashed, not counting leaf 0x00 prefix */
  private static final int KZTREE_BLOCKSIZE = 1024 * 32;

  /* size of input to each non-leaf hash-tree node, not counting node 0x01 prefix */
  private static final int KZTREE_NODESIZE = MD5_SIZE * 2;

  /* default size of interim values stack, in MD5SIZE
   * blocks. If this overflows (as it will for input
   * longer than 2^128 in size), havoc may ensue. */
  private static final int KZTREE_STACKSIZE = MD5_SIZE * 113;

  private int count; /* total blocks processed */
  private byte[] leaf; /* leaf in progress */
  private int blockIndex; /* leaf data */
  private int index; /* index into block */
  private int topIndex; /* top (next empty) stack slot */
  private byte[] nodes; /* stack of interim node values */
  private int gen;

  /** Creates a handler with empty state; invoke {@link #analyzeInit()} before supplying data. */
  public KzTreeHandler() {
    // Constructor intentionally empty; actual buffer allocation is deferred to analyzeInit to allow
    // repeated reuse of the same instance without reallocating when callers prefer explicit reset.
  }

  /**
   * Resets the handler so a new stream can be processed.
   *
   * <p>This method allocates fresh leaf and node buffers sized for the configured block and stack
   * dimensions, and clears all counters used to track partially filled blocks and composed nodes.
   * It must be invoked exactly once before feeding any bytes to {@link #analyzeUpdate(byte[], int,
   * int)}, and should be called again before reusing the instance for a subsequent payload. The
   * method performs no I/O and does not release prior buffers; repeated calls overwrite existing
   * state in place.
   */
  public void analyzeInit() {

    leaf = new byte[KZTREE_BLOCKSIZE];
    nodes = new byte[KZTREE_STACKSIZE];

    count = 0;
    blockIndex = 0; // working area for blocks
    index = 0; // partial block pointer/block length
    topIndex = 0;
  }

  /**
   * Feeds a segment of the source data into the tree builder.
   *
   * <p>The supplied {@code buffer} slice is appended to the current leaf until it reaches {@value
   * #KZTREE_BLOCKSIZE} bytes, at which point the block is hashed and folded into the node stack.
   * Larger segments are processed iteratively to avoid excessive copying. Callers may provide
   * successive slices of any length; partial blocks are retained between calls. Input is treated as
   * opaque bytes and is not modified.
   *
   * @param buffer contiguous array containing the next bytes to analyze; must not be {@code null}.
   * @param ofs zero-based offset within {@code buffer} where consumption begins; must be within the
   *     array bounds.
   * @param len number of bytes from {@code buffer} to read starting at {@code ofs}; may be zero to
   *     advance nothing.
   */
  public void analyzeUpdate(byte[] buffer, int ofs, int len) {

    if (0 != index) {
      /* Try to fill partial block */
      int left = KZTREE_BLOCKSIZE - index;
      if (len < left) {
        System.arraycopy(buffer, ofs, leaf, blockIndex + index, len);
        index += len;
        return; /* Finished */
      } else {
        System.arraycopy(buffer, ofs, leaf, blockIndex + index, left);
        index = KZTREE_BLOCKSIZE;
        kztreeBlock();
        ofs += left;
        len -= left;
      }
    }

    while (KZTREE_BLOCKSIZE <= len) {
      System.arraycopy(buffer, ofs, leaf, blockIndex, KZTREE_BLOCKSIZE);
      index = KZTREE_BLOCKSIZE;
      kztreeBlock();
      ofs += KZTREE_BLOCKSIZE;
      len -= KZTREE_BLOCKSIZE;
    }

    if (0 != (index = len)) {
      /* This assignment is intended */
      /* Buffer leftovers */
      System.arraycopy(buffer, ofs, leaf, blockIndex, len);
    }
  }

  /**
   * A full {@code KZTREE_BLOCKSIZE} bytes have become available; hash them and compose siblings.
   */
  private void kztreeBlock() {

    byte[] md5 = Md5Handler.md5(leaf, index);
    System.arraycopy(md5, 0, nodes, topIndex, md5.length);
    topIndex += MD5_SIZE;

    ++count;
    gen = count;
    while (gen == ((gen >> 1) << 1)) { // while evenly divisible by 2...
      kztreeCompose();
      gen = gen >> 1;
    }
  }

  private void kztreeCompose() {

    if (gen != ((gen >> 1) << 1)) { // compose of generation with odd population
      // Hash the only child in place to advance the tree level.
      byte[] childMd5 = Md5Handler.md5(nodes, topIndex - MD5_SIZE, MD5_SIZE);
      System.arraycopy(childMd5, 0, nodes, topIndex - MD5_SIZE, MD5_SIZE);

      return;
    }
    int nodeIndex = topIndex - KZTREE_NODESIZE;
    byte[] md5 = Md5Handler.md5(nodes, nodeIndex, KZTREE_NODESIZE);
    System.arraycopy(md5, 0, nodes, nodeIndex, MD5_SIZE);
    topIndex -= MD5_SIZE; // update top ptr
  }

  /**
   * Completes hashing and returns the tree root digest.
   *
   * <p>This method finalizes any partially filled block, injects a synthetic empty block when the
   * total length is zero, and composes remaining node generations until a single root remains. It
   * also rehashes the lone block case to preserve legacy KZ tree semantics. The returned byte array
   * is a new {@code MD5_SIZE}-length instance owned by the caller; internal buffers are left
   * intact, allowing optional inspection after completion.
   *
   * @return 16-byte MD5 digest representing the root of the constructed hash tree; never {@code
   *     null}.
   */
  public byte[] analyzeFinal() {

    // do last partial block, if any
    if (0 < index) {
      kztreeBlock();
    }

    if (0 == count) {
      // for the zero-length input case, hash nothing.
      kztreeBlock();
    }

    while (1 < gen) {
      kztreeCompose();
      gen = (gen + 1) / 2;
    }

    if (1 == count) {
      // for the single block case, hash again
      kztreeCompose();
    }

    byte[] digest = new byte[MD5_SIZE];
    System.arraycopy(nodes, 0, digest, 0, MD5_SIZE);

    return digest;
  }
}
