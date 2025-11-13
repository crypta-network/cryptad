package network.crypta.client;

import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.Metadata.SplitfileAlgorithm;

/**
 * Simple in-memory-only API for forward error correction (FEC) encoding and decoding.
 *
 * <p>This abstraction exposes a minimal, allocation-conscious surface over concrete codec engines.
 * Implementations operate entirely in memory and do not perform queuing, throttling, or any kind of
 * asynchronous scheduling. If you need back‑pressure or job orchestration, integrate with a higher
 * level component such as {@code MemoryLimitedJobRunner} or an equivalent executor that mediates
 * concurrency and memory usage.
 *
 * <p>Typical usage is to prepare contiguous arrays for data and check blocks and then invoke {@link
 * #encode(byte[][], byte[][], boolean[], int)} to materialize parity blocks, or {@link
 * #decode(byte[][], byte[][], boolean[], boolean[], int)} to reconstruct missing data blocks.
 * Callers are responsible for padding the last block of a segment to {@code blockLength} bytes and
 * for tracking which blocks are present. Implementations may cache internal state between calls in
 * order to reduce per‑operation allocations, but they are not required to be thread‑safe unless
 * documented otherwise.
 *
 * <ul>
 *   <li>Mutability: the provided arrays are filled in place; no copies are guaranteed.
 *   <li>Thread‑safety: unless stated by an implementation, instances are not thread‑safe.
 *   <li>Limits: {@link #MAX_TOTAL_BLOCKS_PER_SEGMENT} bounds data+check blocks per segment.
 * </ul>
 *
 * @see #getInstance(SplitfileAlgorithm)
 * @see #getCheckBlocks(int, InsertContext.CompatibilityMode)
 */
public abstract class FECCodec {

  /**
   * Default constructor for subclasses and factory methods.
   *
   * <p>The class is abstract and cannot be instantiated directly by callers. This explicit
   * constructor exists to document the otherwise implicit default constructor so that Javadoc
   * doclint can analyze it. Implementations may perform no initialization beyond standard field
   * defaults.
   */
  protected FECCodec() {}

  /**
   * Minimum extra memory (in bytes) an implementation should assume for internal working buffers.
   *
   * <p>This value serves as a conservative baseline when estimating transient allocations required
   * by the codec beyond the storage of the blocks themselves. Callers that plan job concurrency can
   * use this constant together with {@link #maxMemoryOverheadEncode(int, int)} and {@link
   * #maxMemoryOverheadDecode(int, int)} to ensure a safe upper bound on in‑flight memory. The
   * actual usage may be lower depending on the concrete engine and JVM.
   */
  public static final long MIN_MEMORY_ALLOCATION = 8L * 1024 * 1024 + 256L * 1024;

  /**
   * Maximum number of total blocks per segment supported by all implementations.
   *
   * <p>The value caps the sum of data blocks and check/parity blocks that may be processed as a
   * single segment. Callers should ensure {@code dataBlocks + checkBlocks <=
   * MAX_TOTAL_BLOCKS_PER_SEGMENT} when selecting parameters. Exceeding the limit is undefined for a
   * particular engine and may result in allocation failures or validation errors.
   */
  public static final int MAX_TOTAL_BLOCKS_PER_SEGMENT = 256;

  /**
   * Maximum memory usage with the given number of data blocks and check blocks, not including the
   * blocks themselves.
   *
   * <p>The returned figure is a best‑effort upper bound for decode operations performed by a
   * concrete implementation. It counts temporary buffers, tables, and state the codec may allocate,
   * but it deliberately excludes the memory occupied by the caller‑supplied data and check block
   * arrays. The value is suitable for coarse admission control when running multiple decodes
   * concurrently.
   *
   * @param dataBlocks number of data blocks in the segment; must be non‑negative and typically
   *     greater than zero for useful work. Extremely large values may be rejected by
   *     implementations.
   * @param checkBlocks number of parity/check blocks; must be non‑negative. The sum of data and
   *     check blocks should not exceed {@link #MAX_TOTAL_BLOCKS_PER_SEGMENT}.
   * @return an upper bound, in bytes, of additional memory that a decode may allocate besides the
   *     storage of the block arrays themselves; callers should treat it as advisory, not exact.
   */
  public abstract long maxMemoryOverheadDecode(int dataBlocks, int checkBlocks);

  /**
   * Maximum memory usage with the given number of data blocks and check blocks, not including the
   * blocks themselves.
   *
   * <p>The figure estimates temporary memory needed to produce parity blocks during an encode. It
   * excludes the storage for the provided data and check block arrays, focusing on transient
   * structures such as generator matrices and scratch buffers. Use together with {@link
   * #MIN_MEMORY_ALLOCATION} to budget headroom for bursts or scheduler concurrency.
   *
   * @param dataBlocks number of data blocks in the segment; must be non‑negative and within engine
   *     limits. Implementations may impose additional constraints on the range.
   * @param checkBlocks number of parity/check blocks to generate; must be non‑negative. The sum of
   *     data and check blocks should not exceed {@link #MAX_TOTAL_BLOCKS_PER_SEGMENT}.
   * @return an upper bound, in bytes, of additional memory that an encode may allocate besides the
   *     storage of the block arrays themselves; intended for planning rather than precise sizing.
   */
  public abstract long maxMemoryOverheadEncode(int dataBlocks, int checkBlocks);

  /**
   * Execute a FEC decode. On exiting the function we will have all the data blocks.
   *
   * @param dataBlocks The byte[]'s for storing the data blocks. Must all be non-null. Which have
   *     valid contents is indicated by dataBlocksPresent. When exit this function, they will be
   *     filled with the data blocks in the correct order.
   * @param checkBlocks The byte[]'s for storing the check blocks. Which have valid contents is
   *     indicated by checkBlocksPresent.
   * @param dataBlocksPresent Indicates which data blocks were present before decoding. (Will not be
   *     changed by this function).
   * @param checkBlocksPresent Indicates which check blocks are present before decoding. (Will not
   *     be changed by this function).
   * @param blockLength The length of any and all blocks. Padding must be handled by the caller if
   *     it is necessary.
   *     <p>The method reconstructs any missing data blocks in place using the provided parity.
   *     Arrays must be correctly sized for the number of data and check blocks for the segment, and
   *     every non‑missing slot must reference a non‑{@code null} buffer of length exactly {@code
   *     blockLength} bytes. This operation is not guaranteed to be idempotent for malformed inputs;
   *     provide accurate presence bitmaps to avoid undefined behavior. Callers should zero or reuse
   *     temporary buffers as appropriate for their privacy or performance goals.
   */
  public abstract void decode(
      byte[][] dataBlocks,
      byte[][] checkBlocks,
      boolean[] dataBlocksPresent,
      boolean[] checkBlocksPresent,
      int blockLength);

  /**
   * Execute a FEC encode. On entering, we must have all the data blocks. On exiting, we will have
   * all the check blocks as well.
   *
   * @param dataBlocks All the data blocks, which all have valid contents.
   * @param checkBlocks The byte[]'s for storing the encoded check blocks. Must all be non-null.
   * @param checkBlocksPresent Indicates which check blocks have already been encoded.
   * @param blockLength Length of each data and check block in bytes. The caller is responsible for
   *     padding the last data block to this fixed size before encoding; implementations assume
   *     uniform block sizes throughout the segment.
   *     <p>This method fills missing parity/check blocks in place without modifying any provided
   *     data blocks. Repeated invocations may skip already present parity according to {@code
   *     checkBlocksPresent}. The caller owns the arrays and can decide whether to retain or discard
   *     the generated parity afterward.
   */
  public abstract void encode(
      byte[][] dataBlocks, byte[][] checkBlocks, boolean[] checkBlocksPresent, int blockLength);

  /**
   * Create a codec instance suitable for the requested splitfile algorithm.
   *
   * <p>The mapping aligns with the splitfile metadata used by the client: standard onion routing
   * splitfiles obtain a parity‑capable codec, while non‑redundant splitfiles yield {@code null}
   * because no FEC is required. Callers typically branch on {@code null} to skip parity work when
   * reinserting or verifying segments that historically carried no redundancy.
   *
   * @param splitfileType the desired splitfile algorithm as recorded in metadata; the value
   *     determines whether redundancy is expected and which engine to select.
   * @return a codec implementation for the given algorithm, or {@code null} when the algorithm
   *     specifies no redundancy ({@link SplitfileAlgorithm#NONREDUNDANT}).
   */
  public static FECCodec getInstance(SplitfileAlgorithm splitfileType) {
    return switch (splitfileType) {
      case NONREDUNDANT -> null;
      case ONION_STANDARD -> new OnionFECCodec();
    };
  }

  /**
   * Get the recommended number of check blocks per segment for a given number of data blocks for a
   * given compatibility mode.
   *
   * @param dataBlocks The number of data blocks per segment.
   * @param cmode The compatibility mode (so we can exactly mimic the behaviour of older builds when
   *     reinserting files).
   * @return the suggested count of parity/check blocks to pair with {@code dataBlocks} under the
   *     supplied compatibility rules; callers may clamp to {@link #MAX_TOTAL_BLOCKS_PER_SEGMENT} as
   *     needed.
   */
  public abstract int getCheckBlocks(int dataBlocks, CompatibilityMode cmode);
}
