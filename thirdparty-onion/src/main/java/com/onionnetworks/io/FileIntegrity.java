package com.onionnetworks.io;

import com.onionnetworks.util.Buffer;

/**
 * Exposes a read-only view of cryptographic hashes calculated over a file and its constituent
 * fixed-size blocks.
 *
 * <p>Implementations typically wrap precomputed digest material so callers can verify large files
 * without re-hashing the entire contents. The interface is intentionally minimal: it reports the
 * digest algorithm, the uniform block size, the original file length, and both per-block and whole
 * file hashes. The final block may be shorter than the declared block size but is still hashed with
 * the same algorithm to maintain deterministic coverage across the file.
 *
 * <p>Callers commonly pair this interface with a streaming reader that replays file data and
 * compares the supplied hashes on-the-fly. Implementations should document their thread-safety and
 * lifetime guarantees; a typical implementation is immutable once constructed, enabling reuse
 * across validation passes or parallel download segments. All lengths are expressed in bytes and
 * block indexes are expected to follow zero-based semantics unless otherwise specified by the
 * implementation.
 *
 * <ul>
 *   <li>Provides block-level verification to localize corruption quickly.
 *   <li>Supplies a whole-file hash for coarse integrity checks or catalog metadata.
 *   <li>Relies on a consistent message-digest algorithm across all reported hashes.
 * </ul>
 *
 * @see FileIntegrityImpl
 */
public interface FileIntegrity {

  /**
   * Returns the canonical name of the message-digest algorithm that produced all reported hashes.
   *
   * <p>The algorithm identifier is suitable for {@link
   * java.security.MessageDigest#getInstance(String)} and should match both the per-block hashes and
   * the overall file hash. Implementations must return a non-null, non-empty string so callers can
   * create compatible digest instances when revalidating data. The algorithm choice determines
   * digest size, collision properties, and the level of interoperability with other tools that may
   * consume the integrity metadata.
   *
   * @return algorithm name understood by {@code MessageDigest}, stable for this integrity record.
   */
  String getAlgorithm();

  /**
   * Reports the nominal size, in bytes, of each uniformly hashed block within the file.
   *
   * <p>Implementations typically choose a power-of-two value to align with storage boundaries and
   * simplify segment arithmetic. Every block except the final one must match this size exactly; the
   * last block may be shorter but never zero bytes. The reported size remains constant for the life
   * of this integrity descriptor so clients can calculate offsets deterministically when mapping
   * block numbers back to absolute file positions.
   *
   * @return positive block size in bytes used for all but the final partial block.
   */
  int getBlockSize();

  /**
   * Returns the total file length, in bytes, that the integrity data describes.
   *
   * <p>The size represents the original payload length at the time the hashes were computed. It
   * combines with {@link #getBlockSize()} to derive the block count and to verify that readers do
   * not truncate or pad the content when reassembling distributed segments. Callers should treat
   * this value as authoritative metadata for range validation and consistency checks.
   *
   * @return non-negative file length in bytes covered by the recorded hashes.
   */
  long getFileSize();

  /**
   * Returns the number of hashed blocks that together span the described file.
   *
   * <p>The count equals {@code ceil(fileSize / blockSize)}; when the file size is an exact multiple
   * of the block size, the final block is full length. This value helps callers preallocate data
   * structures for per-block verification or progress reporting. Implementations should ensure
   * consistency with {@link #getFileSize()} and {@link #getBlockSize()} so that iterating through
   * block indices from zero to {@code count - 1} covers the entire file without gaps.
   *
   * @return total number of sequential blocks implied by the file size and block size.
   */
  @SuppressWarnings("unused")
  int getBlockCount();

  /**
   * Retrieves the cryptographic hash for an individual block identified by its index.
   *
   * <p>Block numbering is expected to start at zero and increase sequentially. Callers should pass
   * values within the range {@code 0 <= blockNum < getBlockCount()}; behavior for out-of-range
   * values is implementation-specific and may result in runtime exceptions. The returned buffer is
   * typically immutable; callers must not modify it unless the implementation explicitly allows
   * mutation. Hashes correspond to the algorithm reported by {@link #getAlgorithm()} and reflect
   * the exact bytes contained in the referenced block.
   *
   * <pre>{@code
   * // Example: verify a freshly read block against known integrity data
   * Buffer expected = integrity.getBlockHash(blockIndex);
   * }</pre>
   *
   * @param blockNum zero-based index of the block to verify; must exist within the file span.
   * @return hash bytes for the requested block, using the shared digest algorithm.
   */
  @SuppressWarnings("unused")
  Buffer getBlockHash(int blockNum);

  /**
   * Provides the cryptographic digest computed over the entire file contents in order.
   *
   * <p>The whole-file hash complements per-block hashes by allowing a fast coarse-grained integrity
   * check. It uses the same algorithm as {@link #getAlgorithm()} and is calculated over the
   * original file length returned by {@link #getFileSize()}. Callers can compare this value before
   * attempting block-by-block validation or after reconstruction from independent segments. The
   * returned buffer is typically read-only and should be treated as immutable checksum metadata.
   *
   * @return digest of the full file data, consistent with the configured message-digest algorithm.
   */
  @SuppressWarnings("unused")
  Buffer getFileHash();
}
