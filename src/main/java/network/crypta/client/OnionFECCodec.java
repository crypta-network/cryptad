package network.crypta.client;

import com.onionnetworks.fec.PureCode;
import com.onionnetworks.util.Buffer;
import java.lang.ref.SoftReference;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.support.LRUMap;

/**
 * Forward error correction (FEC) codec backed by the Onion Networks {@code PureCode}
 * implementation.
 *
 * <p>This class provides encode/decode operations used by the splitfile layer to add redundancy to
 * segments and to reconstruct missing data from available parity. It is a concrete implementation
 * of {@link FECCodec} that delegates the heavy lifting to {@code PureCode} while handling buffer
 * preparation and a small, memory‑sensitive cache of initialized codec instances keyed by the pair
 * {@code (k, n)}.
 *
 * <p>Typical usage is write‑once per segment: callers prepare arrays for data and parity blocks of
 * a uniform {@code blockLength}, mark which blocks are present, and invoke {@link #decode(byte[][],
 * byte[][], boolean[], boolean[], int)} or {@link #encode(byte[][], byte[][], boolean[], int)}.
 * Instances are stateless with respect to the content being processed; internal caching exists only
 * to amortize setup costs of {@code PureCode}. The cache uses {@link SoftReference} entries and an
 * LRU policy so it sheds memory under pressure. Methods are thread‑safe with respect to the cache
 * access but do not synchronize on caller‑provided arrays.
 *
 * <ul>
 *   <li>Encodes only the parity blocks that are currently missing.
 *   <li>Decodes in place; recovered data are written back into {@code dataBlocks} slots.
 *   <li>Exposes coarse memory overhead estimates to help schedule FEC jobs.
 *   <li>Provides a heuristically chosen number of parity blocks per segment.
 * </ul>
 *
 * @see FECCodec
 * @see HighLevelSimpleClientImpl
 * @see CompatibilityMode
 */
public class OnionFECCodec extends FECCodec {

  /**
   * Creates a new codec instance.
   *
   * <p>The codec is stateless with respect to inputs; construction performs no I/O and allocates no
   * large data structures. Internal {@code PureCode} instances are cached separately and reused
   * across calls, so callers may create {@code OnionFECCodec} instances cheaply and share them
   * across operations if desired.
   */
  public OnionFECCodec() {
    // Intentionally empty: the codec is stateless and construction performs no initialization.
    // PureCode instances are cached separately and acquired on demand per (k, n) pair.
  }

  /**
   * Decodes a set of splitfile blocks using available parity, reconstructing any missing data
   * blocks in place.
   *
   * <p>The method expects {@code dataBlocks.length == k} source blocks and {@code
   * checkBlocks.length} parity blocks with a uniform {@code blockLength} in bytes. Presence arrays
   * indicate which positions are currently filled. Missing data positions are backed by writable
   * {@code byte[]} slots in {@code dataBlocks}; when enough inputs are present, the codec writes
   * the recovered content into those slots. All arrays are indexed from zero, and the operation
   * completes synchronously before the method returns.
   *
   * @param dataBlocks the {@code k} data block buffers; each element must reference a non-null
   *     array of exactly {@code blockLength} bytes. Slots for missing data must still be allocated
   *     and will receive reconstructed bytes when possible.
   * @param checkBlocks the parity block buffers; each present element must reference a non-null
   *     array of exactly {@code blockLength} bytes. Only positions flagged present are read.
   * @param dataBlocksPresent flags where {@code true} marks that the corresponding entry in {@code
   *     dataBlocks} already contains valid data; {@code false} marks a missing data block that may
   *     be reconstructed.
   * @param checkBlocksPresent flags where {@code true} marks that the corresponding entry in {@code
   *     checkBlocks} contains a valid parity block; other entries are ignored for input.
   * @param blockLength the size, in bytes, of every data and parity block; all arrays must use the
   *     same fixed length and callers should ensure the buffers match this value exactly.
   * @throws IllegalArgumentException if any present data or parity buffer length differs from
   *     {@code blockLength}; this guard prevents partial or oversized blocks from being processed.
   */
  @Override
  public void decode(
      byte[][] dataBlocks,
      byte[][] checkBlocks,
      boolean[] dataBlocksPresent,
      boolean[] checkBlocksPresent,
      int blockLength) {
    int k = dataBlocks.length;
    int n = dataBlocks.length + checkBlocks.length;
    PureCode codec = getCodec(k, n);
    int[] blockNumbers = new int[k];
    Buffer[] buffers = new Buffer[k];
    initDataBuffers(dataBlocks, dataBlocksPresent, blockLength, buffers, blockNumbers);
    fillDataBuffersWithCheckBlocks(
        dataBlocks, checkBlocks, checkBlocksPresent, blockLength, buffers, blockNumbers);

    // Now do the decoding.
    try (PureCode ignored =
        codec) { // PureCode close() is a no-op; enables try-with-resources usage
      codec.decode(buffers, blockNumbers);
    }
    // The data blocks are now decoded and in the correct locations.
  }

  private static void initDataBuffers(
      byte[][] dataBlocks,
      boolean[] dataBlocksPresent,
      int blockLength,
      Buffer[] buffers,
      int[] blockNumbers) {
    // The data blocks are already in the correct positions in dataBlocks.
    for (int i = 0; i < dataBlocks.length; i++) {
      if (dataBlocks[i].length != blockLength) throw new IllegalArgumentException();
      if (!dataBlocksPresent[i]) continue;
      buffers[i] = new Buffer(dataBlocks[i], 0, blockLength);
      blockNumbers[i] = i;
    }
  }

  private static void fillDataBuffersWithCheckBlocks(
      byte[][] dataBlocks,
      byte[][] checkBlocks,
      boolean[] checkBlocksPresent,
      int blockLength,
      Buffer[] buffers,
      int[] blockNumbers) {
    int target = 0;
    // Fill in the gaps with the check blocks.
    for (int i = 0; i < checkBlocks.length; i++) {
      if (checkBlocksPresent[i]) {
        if (checkBlocks[i].length != blockLength) throw new IllegalArgumentException();
        while (target < dataBlocks.length && buffers[target] != null) target++; // Scan for slot.
        if (target >= dataBlocks.length) break;
        // Decode into the slot for the relevant data block.
        buffers[target] = new Buffer(dataBlocks[target]);
        // Provide the data from the check block.
        blockNumbers[target] = i + dataBlocks.length;
        System.arraycopy(checkBlocks[i], 0, dataBlocks[target], 0, blockLength);
      }
    }
  }

  /**
   * Cache of PureCode by {k,n}. The memory usage is relatively small so we account for it in the
   * FEC jobs, see maxMemoryOverheadDecode() etc.
   */
  private static synchronized PureCode getCodec(int k, int n) {
    CodecKey key = new CodecKey(k, n);
    SoftReference<PureCode> codeRef;
    while ((codeRef = recentlyUsedCodecs.peekValue()) != null) {
      // Remove the oldest codecs if they have been GC'ed.
      if (codeRef.get() == null) {
        recentlyUsedCodecs.popKey();
      } else {
        break;
      }
    }
    codeRef = recentlyUsedCodecs.get(key);
    if (codeRef != null) {
      PureCode code = codeRef.get();
      if (code != null) {
        recentlyUsedCodecs.push(key, codeRef);
        return code;
      }
    }
    PureCode code = new PureCode(k, n);
    recentlyUsedCodecs.push(key, new SoftReference<>(code));
    return code;
  }

  private static final LRUMap<CodecKey, SoftReference<PureCode>> recentlyUsedCodecs =
      LRUMap.createSafeMap();

  private static class CodecKey implements Comparable<CodecKey> {
    /** Number of input blocks */
    int k;

    /** Number of output blocks, including input blocks */
    int n;

    public CodecKey(int k, int n) {
      this.n = n;
      this.k = k;
    }

    @Override
    public boolean equals(Object o) {
      if (o instanceof CodecKey key) {
        return (key.n == n) && (key.k == k);
      } else {
        return false;
      }
    }

    @Override
    public int hashCode() {
      return (n << 16) + k;
    }

    @Override
    public int compareTo(CodecKey o) {
      if (n > o.n) return 1;
      if (n < o.n) return -1;
      return Integer.compare(k, o.k);
    }
  }

  /**
   * Generates the missing parity blocks for a segment.
   *
   * <p>The method considers the {@code checkBlocksPresent} mask and encodes only positions
   * currently marked {@code false}. All buffers must be preallocated and sized to {@code
   * blockLength}; the codec writes the new parity bytes into the corresponding {@code
   * checkBlocks[i]} entries. Data block inputs are treated as read‑only; parity buffers for already
   * present positions are not modified. The call is synchronous and does not retain references to
   * the supplied arrays.
   *
   * <pre>{@code
   * // Example: encode two missing parity blocks
   * codec.encode(data, parity, new boolean[] { false, false }, blockLen);
   * }</pre>
   *
   * @param dataBlocks the {@code k} data block buffers; every element must be non-null and exactly
   *     {@code blockLength} bytes long; content is read but never mutated.
   * @param checkBlocks the parity block buffers; every element must be non-null and exactly {@code
   *     blockLength} bytes long; missing positions will be filled by the encoder.
   * @param checkBlocksPresent presence mask for {@code checkBlocks}; {@code false} entries select
   *     the parity indices to compute and write; {@code true} entries are left untouched.
   * @param blockLength the size, in bytes, required for each data and parity buffer; mis-sized
   *     buffers trigger argument validation failures.
   * @throws IllegalArgumentException if any data or parity buffer length does not equal {@code
   *     blockLength}; callers must allocate uniformly sized arrays before invoking.
   */
  @Override
  public void encode(
      byte[][] dataBlocks, byte[][] checkBlocks, boolean[] checkBlocksPresent, int blockLength) {
    int k = dataBlocks.length;
    int n = dataBlocks.length + checkBlocks.length;
    PureCode codec = getCodec(k, n);
    Buffer[] data = new Buffer[dataBlocks.length];
    for (int i = 0; i < data.length; i++) {
      if (dataBlocks[i] == null || dataBlocks[i].length != blockLength)
        throw new IllegalArgumentException();
      data[i] = new Buffer(dataBlocks[i]);
    }
    int mustEncode = 0;
    for (int i = 0; i < checkBlocks.length; i++) {
      if (checkBlocks[i] == null || checkBlocks[i].length != blockLength)
        throw new IllegalArgumentException();
      if (!checkBlocksPresent[i]) mustEncode++;
    }
    Buffer[] check = new Buffer[mustEncode];
    if (mustEncode == 0) return; // Done already.
    int[] toEncode = new int[mustEncode];
    int x = 0;
    for (int i = 0; i < checkBlocks.length; i++) {
      if (checkBlocksPresent[i]) continue;
      check[x] = new Buffer(checkBlocks[i]);
      toEncode[x++] = i + dataBlocks.length;
    }
    try (PureCode ignored =
        codec) { // PureCode close() is a no-op; enables try-with-resources usage
      codec.encode(data, check, toEncode);
    }
  }

  /**
   * Returns an approximate upper bound, in bytes, for the transient heap used during decoding for a
   * given {@code (dataBlocks, checkBlocks)} configuration.
   *
   * <p>The estimate is intentionally coarse. It reflects the dominant term of the decoding matrix
   * representation and a small constant factor to cover intermediate structures. Use this value to
   * budget concurrent jobs or to gate work submission in schedulers; it is not a strict cap, but in
   * practice it closely tracks the cost of the underlying {@code PureCode} operations.
   *
   * @param dataBlocks number of data blocks {@code k} that make up the segment to decode; must be
   *     positive and match the size of the {@code dataBlocks} array passed to {@link #decode}.
   * @param checkBlocks number of parity blocks available {@code n - k}; corresponds to the size of
   *     the {@code checkBlocks} array passed to {@link #decode}.
   * @return a non-negative byte count that approximates temporary memory required to decode;
   *     callers should treat this as guidance for scheduling rather than a hard limit.
   */
  @Override
  public long maxMemoryOverheadDecode(int dataBlocks, int checkBlocks) {
    int n = dataBlocks + checkBlocks;
    int matrixSize = n * dataBlocks * 2; // char[] of n*k
    return matrixSize
        * 3L; // Very approximately, the last one absorbing some columns and fixed overhead.
  }

  /**
   * Returns an approximate upper bound, in bytes, for the transient heap used during encoding for a
   * given {@code (dataBlocks, checkBlocks)} configuration.
   *
   * <p>Encoding has the same dominant memory term as decoding in this implementation; therefore
   * this method delegates to {@link #maxMemoryOverheadDecode(int, int)} to keep the estimate
   * consistent. The returned value should be used as a scheduling hint rather than a strict
   * guarantee.
   *
   * @param dataBlocks number of data blocks {@code k} to encode into parity; must be positive.
   * @param checkBlocks number of parity blocks {@code n - k} considered by the encoder; must be
   *     non-negative.
   * @return a non-negative byte count that approximates temporary memory required to encode; use
   *     this for coarse capacity planning of FEC jobs.
   */
  @Override
  public long maxMemoryOverheadEncode(int dataBlocks, int checkBlocks) {
    // Same computation as decode; delegate to avoid duplication.
    return maxMemoryOverheadDecode(dataBlocks, checkBlocks);
  }

  /**
   * Computes a heuristic number of parity (check) blocks for a segment of {@code dataBlocks}.
   *
   * <p>The policy balances end‑to‑end redundancy between network‑level replication and FEC. For
   * larger segments the ratio approaches a fixed ceiling; for smaller segments an extra block is
   * added to avoid under‑protection. To preserve backward compatibility for older nodes,
   * {@linkplain CompatibilityMode certain modes} cap parity at {@code dataBlocks} to keep
   * redundancy ≤ 100% for peers that cannot handle higher ratios. The computation also ensures the
   * combined number of blocks does not exceed 256 for operational reasons.
   *
   * @param dataBlocks number of data blocks in the segment; this is {@code k} in coding terms and
   *     directly influences the base parity ratio.
   * @param compatibilityMode compatibility setting that constrains parity when communicating with
   *     older peers; use {@link CompatibilityMode#COMPAT_1250} or {@link
   *     CompatibilityMode#COMPAT_1250_EXACT} to cap redundancy at 100%.
   * @return the recommended count of parity blocks to allocate; callers should respect the returned
   *     value to achieve the intended durability across a heterogeneous network.
   */
  @Override
  public int getCheckBlocks(int dataBlocks, CompatibilityMode compatibilityMode) {
    /*
     * ALCHEMY: What we do know is that redundancy by FEC is much more efficient than redundancy by
     * simply duplicating blocks, for obvious reasons (see e.g. Wuala). But we have to have some
     * redundancy at the duplicating blocks level because we do use some keys directly etc.: we store
     * an insert in 3 nodes. We also cache it on 20 nodes, but generally the key will fall out of
     * the caches within days. So long term, it's 3. Multiplied by 2 here, makes 6. Used to be 1.5 *
     * 3 = 4.5. Wuala uses 5, but that's all FEC.
     */
    int checkBlocks =
        dataBlocks
            * HighLevelSimpleClientImpl.SPLITFILE_CHECK_BLOCKS_PER_SEGMENT
            / HighLevelSimpleClientImpl.SPLITFILE_SCALING_BLOCKS_PER_SEGMENT;
    if (dataBlocks >= HighLevelSimpleClientImpl.SPLITFILE_CHECK_BLOCKS_PER_SEGMENT)
      checkBlocks = HighLevelSimpleClientImpl.SPLITFILE_CHECK_BLOCKS_PER_SEGMENT;
    // An extra block for anything below the limit.
    checkBlocks++;
    // Keep it within 256 blocks.
    if (dataBlocks < 256 && dataBlocks + checkBlocks > 256) checkBlocks = 256 - dataBlocks;
    if ((compatibilityMode == InsertContext.CompatibilityMode.COMPAT_1250
            || compatibilityMode == InsertContext.CompatibilityMode.COMPAT_1250_EXACT)
        && checkBlocks > dataBlocks) {
      // Pre-1250, redundancy was always 100% or less.
      // Builds of that period using the native FEC (ext #26) will segfault sometimes on >100%
      // redundancy.
      // So limit check blocks to data blocks.
      checkBlocks = dataBlocks;
    }
    return checkBlocks;
  }
}
