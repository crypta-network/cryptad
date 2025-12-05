/* TigerTree.java
 *
 * (PD) 2003-2006 The Bitzi Corporation Please see http://bitzi.com/publicdomain for
 * more info.
 *
 * $Id: TigerTree.java,v 1.1 2006/04/14 07:40:12 gojomo Exp $
 */
package org.bitpedia.util;

import java.nio.ByteBuffer;
import java.security.DigestException;
import java.util.LinkedList;
import org.bitpedia.util.hash.StreamingHash;

/**
 * Streaming implementation of the Tiger Tree Hash (TTH/THEX) algorithm that layers a balanced
 * binary Merkle tree on top of the Tiger digest. Leaf blocks are hashed with a distinct prefix and
 * merged upward using an internal-node prefix so clients can authenticate partial content while
 * still deriving a stable root hash.
 *
 * <p>The instance accumulates data in 1024-byte leaves, keeps a compact stack of pending subtree
 * hashes, and incrementally composes parent nodes as soon as sibling hashes become available. This
 * reduces memory overhead for large inputs and allows callers to stream data without knowing the
 * total size in advance. The class is intentionally stateful and not thread-safe; use a separate
 * instance per concurrent computation. Typical usage creates an instance, feeds input through
 * {@link #update(byte[], int, int)} or {@link #update(ByteBuffer)}, calls {@link #digest()} to
 * obtain the 24-byte root, and optionally reuses the same instance after {@link #reset()}.
 *
 * <ul>
 *   <li>Leaf prefix {@code 0x00} distinguishes raw block hashing.
 *   <li>Internal prefix {@code 0x01} guards against structural collisions.
 *   <li>Block size is fixed at 1024 bytes; partial final blocks are permitted.
 * </ul>
 *
 * @see StreamingHash
 * @see Tiger
 */
public class TigerTree implements StreamingHash {
  private static final int BLOCKSIZE = 1024;
  private static final int HASHSIZE = 24;

  /** 1024 byte buffer */
  private final byte[] buffer;

  /** Buffer offset */
  private int bufferOffset;

  /** Internal Tiger MD instance */
  private final Tiger tiger;

  /** Interim tree node hash values */
  private LinkedList<byte[]> nodes;

  /** Blocks handled until now */
  long blockCount;

  /**
   * Creates a fresh Tiger tree accumulator with an empty buffer, clear node stack, and a reset
   * Tiger digest. The instance is ready to accept streamed input immediately after construction and
   * may be reused for multiple computations by invoking {@link #reset()} between runs.
   */
  public TigerTree() {
    buffer = new byte[BLOCKSIZE];
    bufferOffset = 0;
    blockCount = 0;
    nodes = new LinkedList<>();
    tiger = new Tiger();
  }

  /**
   * Returns the fixed length of Tiger Tree Hash outputs in bytes.
   *
   * <p>The digest produced by this implementation is always 24 bytes (192 bits) because it uses the
   * standard Tiger-192 variant and does not truncate or extend the underlying hash.
   *
   * @return digest length in bytes; always {@value #HASHSIZE} for this implementation.
   */
  @Override
  public int getDigestLength() {
    return HASHSIZE;
  }

  /**
   * Appends a single byte to the running hash computation.
   *
   * <p>The byte is staged in the internal 1024-byte buffer; once the buffer fills, a leaf hash is
   * produced and merged into the node stack automatically. Callers should prefer the array or
   * {@link ByteBuffer} overloads for bulk updates, as this method performs per-byte buffer boundary
   * checks.
   *
   * @param in next input byte to incorporate; all possible byte values are accepted.
   */
  @Override
  public void update(byte in) {
    buffer[bufferOffset++] = in;
    if (bufferOffset == BLOCKSIZE) {
      blockUpdate();
      bufferOffset = 0;
    }
  }

  /**
   * Appends a slice of the provided byte array to the running hash computation.
   *
   * <p>Data is copied into an internal 1024-byte buffer; each time the buffer fills, a leaf hash is
   * emitted and combined into the pending node stack. The method processes as many complete blocks
   * as possible without additional allocations and retains any trailing partial block for future
   * updates. The supplied array is not retained.
   *
   * @param in source array containing input bytes; must not be {@code null}.
   * @param offset starting index within {@code in}; must be within the array bounds.
   * @param length number of bytes to read from {@code in}; must be non-negative and fit within the
   *     array starting at {@code offset}.
   */
  @Override
  public void update(byte[] in, int offset, int length) {
    int remaining;
    while (length >= (remaining = BLOCKSIZE - bufferOffset)) {
      System.arraycopy(in, offset, buffer, bufferOffset, remaining);
      bufferOffset += remaining;
      blockUpdate();
      length -= remaining;
      offset += remaining;
      bufferOffset = 0;
    }

    System.arraycopy(in, offset, buffer, bufferOffset, length);
    bufferOffset += length;
  }

  /**
   * Appends bytes from the given {@link ByteBuffer} to the running hash computation.
   *
   * <p>If the buffer exposes an accessible backing array, the data is ingested without extra copies
   * by delegating to {@link #update(byte[], int, int)}; otherwise a small scratch buffer is reused
   * to stream the contents. The method advances the buffer position to its limit to reflect the
   * consumed input.
   *
   * @param input source buffer; must not be {@code null}. Both direct and heap buffers are
   *     accepted.
   * @throws NullPointerException if {@code input} is {@code null}.
   */
  @Override
  public void update(ByteBuffer input) {
    if (input == null) {
      throw new NullPointerException("input");
    }
    int remaining = input.remaining();
    if (remaining == 0) {
      return;
    }
    if (input.hasArray()) {
      int position = input.position();
      update(input.array(), input.arrayOffset() + position, remaining);
      input.position(position + remaining);
      return;
    }
    byte[] scratch = new byte[Math.min(remaining, BLOCKSIZE)];
    while (input.hasRemaining()) {
      int chunk = Math.min(scratch.length, input.remaining());
      input.get(scratch, 0, chunk);
      update(scratch, 0, chunk);
    }
  }

  /**
   * Finalizes the computation and returns a newly allocated Tiger Tree digest.
   *
   * <p>Any buffered bytes are hashed, the tree is collapsed to a single root node, and the instance
   * is reset for reuse. The returned array is exactly {@value #HASHSIZE} bytes long and is safe for
   * the caller to modify. Subsequent updates begin a new computation.
   *
   * @return a fresh array containing the 24-byte Tiger Tree Hash of all supplied input.
   */
  @Override
  public byte[] digest() {
    byte[] hash = new byte[HASHSIZE];
    try {
      digest(hash, 0, HASHSIZE);
    } catch (DigestException e) {
      return new byte[0];
    }
    return hash;
  }

  /**
   * Finalizes the computation and writes the Tiger Tree digest into the caller-provided buffer.
   *
   * <p>Any remaining buffered bytes are hashed, pending nodes are composed until a single root
   * remains, and the internal state is cleared. The output buffer is not reused by this class after
   * the call returns. This method is suitable for callers that wish to avoid intermediate
   * allocations.
   *
   * @param buf destination array that will receive the digest bytes.
   * @param offset starting index within {@code buf} where the 24-byte digest is written.
   * @param len available space from {@code offset}; must be at least {@value #HASHSIZE}.
   * @return number of bytes written (always {@value #HASHSIZE}).
   * @throws DigestException if {@code len} is smaller than the required digest size or if
   *     structural errors arise while composing nodes.
   */
  @Override
  public int digest(byte[] buf, int offset, int len) throws DigestException {
    if (len < HASHSIZE) throw new DigestException();

    // hash any remaining fragments
    blockUpdate();

    while (nodes.size() > 1) {
      composeNodes();
    }
    System.arraycopy(nodes.getFirst(), 0, buf, offset, HASHSIZE);
    reset();
    return HASHSIZE;
  }

  /**
   * Resets the accumulator to its initial empty state.
   *
   * <p>Pending buffered data, intermediate node hashes, and the internal Tiger digest are cleared.
   * Call this method to reuse the instance for another computation after a successful or aborted
   * digest operation. The method is idempotent and safe to call multiple times in succession.
   */
  @Override
  public void reset() {
    bufferOffset = 0;
    blockCount = 0;
    nodes = new LinkedList<>();
    tiger.reset();
  }

  /**
   * Hashes the currently buffered bytes as a leaf and updates the node stack as needed.
   *
   * <p>The method prefixes the buffered block with {@code 0x00} to distinguish leaf hashing, stores
   * the resulting digest, and increments the block counter. When two sibling nodes become available
   * (an even block count), it eagerly composes parent nodes to keep the stack depth minimal. An
   * empty buffer is ignored unless the tree is empty, preventing spurious zero-length leaves.
   */
  protected void blockUpdate() {
    tiger.reset();
    tiger.update((byte) 0); // leaf prefix
    tiger.update(buffer, 0, bufferOffset);
    if (bufferOffset == 0 && !nodes.isEmpty())
      return; // don't remember a zero-size hash except at very beginning
    nodes.add(tiger.digest());
    blockCount++;
    long interimNode = blockCount;
    while ((interimNode % 2) == 0) { // even
      composeNodes();
      interimNode >>= 1;
    }
  }

  /**
   * Combines the two most recent node hashes into their parent node.
   *
   * <p>The method removes the rightmost pair of pending nodes, prefixes the concatenated hash with
   * {@code 0x01} to mark an internal edge, and appends the resulting digest back onto the stack. It
   * is invoked automatically by {@link #blockUpdate()} whenever two siblings are present, keeping
   * the tree balanced without additional allocations.
   */
  protected void composeNodes() {
    byte[] right = nodes.removeLast();
    byte[] left = nodes.removeLast();
    tiger.reset();
    tiger.update((byte) 1); // internal node prefix
    tiger.update(left);
    tiger.update(right);
    nodes.add(tiger.digest());
  }
}
