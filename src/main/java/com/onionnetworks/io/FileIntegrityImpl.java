package com.onionnetworks.io;

import com.onionnetworks.util.Buffer;
import com.onionnetworks.util.Util;

/**
 * Immutable container for integrity metadata associated with a file.
 *
 * <p>This implementation stores the digest algorithm name, the overall file hash, and a hash for
 * each fixed-size block of the file. It performs basic validation in the constructor to ensure the
 * supplied hashes align with the expected block layout and size. Callers typically obtain an
 * instance from code that already computed the hashes, then pass it to verification routines that
 * compare hashes against bytes read from disk or the network. Because the internal arrays are not
 * defensively copied, callers should treat the provided {@code Buffer} instances as read-only after
 * construction to preserve integrity guarantees.
 *
 * <p>The class is thread-safe for concurrent reads after construction: all fields are {@code final}
 * and no mutation occurs. It does not perform any I/O itself; it simply exposes the precomputed
 * values needed by {@link FileIntegrity} consumers. Typical usage patterns include: reading the
 * algorithm name to initialize a message digest, requesting individual block hashes during
 * streaming verification, and comparing {@link #getFileHash()} when all blocks have been processed.
 *
 * <ul>
 *   <li>Validates non-null inputs and non-negative sizes during construction.
 *   <li>Computes the expected block count using ceiling division to cover partial tails.
 *   <li>Assumes callers manage the lifecycle of the supplied buffers.
 * </ul>
 *
 * @author Justin F. Chapweske
 */
public final class FileIntegrityImpl implements FileIntegrity {

  private final String algo;
  private final Buffer fileHash;
  private final Buffer[] blockHashes;
  private final int blockSize;
  private final int blockCount;
  private final long fileSize;

  /**
   * Creates an immutable snapshot of file-integrity data for a single file instance.
   *
   * <p>All inputs must already reflect the same digest algorithm. The constructor checks for null
   * references, enforces non-negative sizes, and verifies the number of provided block hashes
   * matches the ceiling of {@code fileSize / blockSize}. The supplied arrays are stored by
   * reference; callers should avoid mutating them after construction to prevent divergence between
   * stored hashes and the represented file.
   *
   * @param algorithm message-digest algorithm name (e.g., {@code "SHA-256"}); must not be null.
   * @param fileHash hash of the complete file content using {@code algorithm}; must not be null.
   * @param blockHashes ordered hashes for each block from offset 0 upward; array must not be null.
   * @param fileSize total file length in bytes; must be zero or positive.
   * @param blockSize configured block size in bytes; must be positive for non-empty files.
   * @throws NullPointerException if {@code algorithm}, {@code fileHash}, or {@code blockHashes} is
   *     {@code null}.
   * @throws IllegalArgumentException if {@code fileSize} or {@code blockSize} is negative, or if
   *     {@code blockHashes.length} does not equal the computed block count.
   */
  public FileIntegrityImpl(
      String algorithm, Buffer fileHash, Buffer[] blockHashes, long fileSize, int blockSize) {
    if (algorithm == null) {
      throw new NullPointerException("algorithm is null");
    } else if (fileHash == null) {
      throw new NullPointerException("fileHash is null");
    } else if (blockHashes == null) {
      throw new NullPointerException("blockHashes are null");
    } else if (fileSize < 0) {
      throw new IllegalArgumentException("fileSize < 0");
    } else if (blockSize < 0) {
      throw new IllegalArgumentException("blockSize < 0");
    }
    this.algo = algorithm;
    this.fileHash = fileHash;
    this.blockHashes = blockHashes;
    this.fileSize = fileSize;
    this.blockSize = blockSize;
    this.blockCount = Util.divideCeil(fileSize, blockSize);
    if (blockHashes.length != blockCount) {
      throw new IllegalArgumentException("Incorrect block hash count");
    }
  }

  /**
   * Returns the message-digest algorithm name used to create every hash in this instance.
   *
   * <p>The algorithm is the exact string provided at construction time and should be compatible
   * with {@link java.security.MessageDigest#getInstance(String)} when initializing verifiers.
   *
   * @return algorithm identifier; callers must not assume normalization beyond the provided value.
   */
  @Override
  public String getAlgorithm() {
    return algo;
  }

  /**
   * Reports the configured block size, in bytes, used when computing per-block hashes.
   *
   * <p>All blocks except the tail share this size; the final block may be shorter when {@code
   * fileSize} is not an exact multiple. The value is identical to the constructor argument and
   * should typically be a power of two for efficient alignment, although no enforcement occurs
   * here.
   *
   * @return positive integer size in bytes; unchanged from construction input.
   */
  @Override
  public int getBlockSize() {
    return blockSize;
  }

  /**
   * Returns the total file size, in bytes, that the stored hashes describe.
   *
   * <p>The value represents the original length supplied to the constructor. Verification routines
   * can use it to detect truncated data or to compute stream boundaries when iterating blocks.
   *
   * @return non-negative length in bytes for the represented file.
   */
  @Override
  public long getFileSize() {
    return fileSize;
  }

  /**
   * Returns the number of logical blocks whose hashes are stored in this instance.
   *
   * <p>The count equals {@code ceil(fileSize / blockSize)} and therefore includes a final partial
   * block when the file length is not evenly divisible by the block size. It is precomputed during
   * construction to support fast bounds checking when retrieving block hashes.
   *
   * @return positive count when {@code fileSize > 0}; otherwise zero for an empty file.
   */
  @Override
  public int getBlockCount() {
    return blockCount;
  }

  /**
   * Returns the hash of the specified block index.
   *
   * <p>The returned {@link Buffer} is the same object provided at construction time; callers should
   * treat it as immutable to preserve integrity. Block numbering starts at zero and increases
   * sequentially toward the end of the file.
   *
   * @param blockNum zero-based block index to retrieve; must be within stored bounds.
   * @return block hash buffer representing the requested block's digest bytes.
   * @throws IllegalArgumentException if {@code blockNum} is negative or greater than or equal to
   *     {@link #getBlockCount()}.
   */
  @Override
  public Buffer getBlockHash(int blockNum) {
    if (blockNum < 0 || blockNum >= blockCount) {
      throw new IllegalArgumentException("Invalid block #" + blockNum);
    }
    return blockHashes[blockNum];
  }

  /**
   * Returns the digest of the entire file content using {@link #getAlgorithm()}.
   *
   * <p>The buffer reference is shared with the constructor input; callers should avoid modification
   * to keep the stored metadata consistent with the underlying file.
   *
   * @return hash buffer for the whole file, covering every byte from start to end.
   */
  @Override
  public Buffer getFileHash() {
    return fileHash;
  }
}
