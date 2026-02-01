package network.crypta.client.async;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.NodeCHK;
import network.crypta.support.Fields;

/**
 * Contains the keys for a splitfile segment in a compact, stream‑friendly representation. Instances
 * capture routing keys and the cryptographic material needed to construct both {@link ClientCHK}
 * and {@link NodeCHK} views for each block (data and check). Depending on the splitfile format, the
 * cryptographic keying material may be shared for all blocks ("common" key) or stored per block.
 *
 * <p>This type is typically populated during metadata parsing and then consulted repeatedly while
 * fetching blocks. It separates the immutable segment layout (counts and keys) from per‑request
 * state such as which blocks were already fetched. Callers usually build an instance, fill it from
 * a binary stream, and then query by key ({@code getBlockNumber(...)}) or by index ({@code
 * getKey(...)}, {@code getNodeKey(...)}). The optional copy parameters on getters let callers
 * control aliasing of underlying arrays when reusing the instance across threads.
 *
 * <p>Thread safety: the object is not strictly immutable. After construction, callers may write
 * keys via {@link #readKeys(DataInputStream, boolean)} or {@link #setKey(int, ClientCHK)}. Once
 * fully populated it is commonly treated as read‑most. For cross‑thread use, either publish after
 * construction and population, or request defensive copies via the {@code copy} parameters.
 *
 * <ul>
 *   <li>Supports both common and per‑block crypto keys and extra bytes.
 *   <li>Provides constant‑time matching on routing keys to find block indices.
 *   <li>Can serialize/deserialize keys for data vs. check blocks independently.
 * </ul>
 *
 * @see ClientCHK
 * @see NodeCHK
 */
public class SplitFileSegmentKeys implements Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Number of data blocks in this segment. Data blocks contribute to the original payload and do
   * not include parity/check blocks. The value is fixed at construction and used to compute offsets
   * into internal arrays when reading and writing keys.
   */
  public final int dataBlocks;

  /**
   * Number of parity/check blocks in this segment. Check blocks are used for redundancy and error
   * correction. The value is fixed at construction and combined with {@link #dataBlocks} to derive
   * the total number of keys managed by this instance.
   */
  public final int checkBlocks;

  /**
   * When present, a single decryption key shared by all blocks in the segment. If {@code null},
   * per‑block decryption keys are stored in {@link #decryptKeys}. The array may be exposed by
   * getters when {@code copy == false}, so callers should not modify its contents.
   */
  public final byte[] commonDecryptKey;

  /**
   * Optional extra bytes that are common to all blocks, typically encoding the crypto algorithm and
   * related parameters expected by {@link ClientCHK}. If {@code null}, extra bytes are stored per
   * block in {@link #extraBytesForKeys}. Treat as read‑only when obtained through getters.
   */
  public final byte[] commonExtraBytes;

  /**
   * Concatenation of {@link NodeCHK#KEY_LENGTH}-byte routing keys for all blocks in the segment,
   * ordered by block index: first {@link #dataBlocks} entries, then {@link #checkBlocks}. Offsets
   * are computed as {@code index * NodeCHK.KEY_LENGTH}.
   */
  public final byte[] routingKeys;

  /**
   * Concatenation of per‑block decryption keys. Used only when {@link #commonDecryptKey} is {@code
   * null}. The array is sized {@code (dataBlocks + checkBlocks) * ClientCHK.CRYPTO_KEY_LENGTH} and
   * indexed by block number.
   */
  public final byte[] decryptKeys;

  /**
   * Concatenation of per‑block extra bytes accompanying each key. Present only when {@link
   * #commonExtraBytes} is {@code null}. Entries are {@code EXTRA_BYTES_LENGTH} bytes long and
   * indexed by block number.
   */
  public final byte[] extraBytesForKeys;

  static final int EXTRA_BYTES_LENGTH = ClientCHK.EXTRA_LENGTH;

  /**
   * Bare constructor for metadata. Allocates internal storage for keys based on the segment sizes
   * and whether a shared crypto key is used. Actual key bytes can be populated later with {@link
   * #readKeys(DataInputStream, boolean)} or {@link #setKey(int, ClientCHK)}.
   *
   * @param blocksPerSegment number of data blocks in the segment; must be non‑negative.
   * @param checkBlocksPerSegment number of check/parity blocks; must be non‑negative.
   * @param splitfileSingleCryptoKey optional common decryption key applied to all blocks; when
   *     {@code null}, space is allocated for per‑block decryption keys instead.
   * @param splitfileSingleCryptoAlgorithm crypto algorithm identifier associated with the common
   *     key; ignored when {@code splitfileSingleCryptoKey} is {@code null}.
   */
  public SplitFileSegmentKeys(
      int blocksPerSegment,
      int checkBlocksPerSegment,
      byte[] splitfileSingleCryptoKey,
      byte splitfileSingleCryptoAlgorithm) {
    this.dataBlocks = blocksPerSegment;
    this.checkBlocks = checkBlocksPerSegment;
    routingKeys = new byte[NodeCHK.KEY_LENGTH * (dataBlocks + checkBlocks)];
    if (splitfileSingleCryptoKey != null) {
      commonDecryptKey = splitfileSingleCryptoKey;
      commonExtraBytes = ClientCHK.getExtra(splitfileSingleCryptoAlgorithm, (short) -1, false);
      decryptKeys = null;
      extraBytesForKeys = null;
    } else {
      commonDecryptKey = null;
      commonExtraBytes = null;
      decryptKeys = new byte[ClientCHK.CRYPTO_KEY_LENGTH * (dataBlocks + checkBlocks)];
      extraBytesForKeys = new byte[EXTRA_BYTES_LENGTH * (dataBlocks + checkBlocks)];
    }
  }

  /**
   * No‑arg constructor for serialization frameworks. Creates an empty shell with default values;
   * fields are set to zero or {@code null}. Not intended for direct use by application code.
   */
  protected SplitFileSegmentKeys() {
    // For serialization.
    dataBlocks = 0;
    checkBlocks = 0;
    commonDecryptKey = null;
    commonExtraBytes = null;
    routingKeys = null;
    decryptKeys = null;
    extraBytesForKeys = null;
  }

  /**
   * Copy constructor performing a deep copy of internal arrays.
   *
   * <p>Behavior remains identical to the source instance; arrays are copied to avoid accidental
   * sharing. Reference fields that are {@code null} in the source remain {@code null}.
   *
   * @param other the instance to copy; its arrays are cloned so subsequent changes do not leak.
   */
  public SplitFileSegmentKeys(SplitFileSegmentKeys other) {
    this.dataBlocks = other.dataBlocks;
    this.checkBlocks = other.checkBlocks;
    this.routingKeys = other.routingKeys != null ? other.routingKeys.clone() : null;
    if (other.commonDecryptKey != null) {
      this.commonDecryptKey = other.commonDecryptKey.clone();
      this.commonExtraBytes =
          other.commonExtraBytes != null ? other.commonExtraBytes.clone() : null;
      this.decryptKeys = null;
      this.extraBytesForKeys = null;
    } else {
      this.commonDecryptKey = null;
      this.commonExtraBytes = null;
      this.decryptKeys = other.decryptKeys != null ? other.decryptKeys.clone() : null;
      this.extraBytesForKeys =
          other.extraBytesForKeys != null ? other.extraBytesForKeys.clone() : null;
    }
  }

  /**
   * Returns the block index for the given {@link ClientCHK} if present in this segment.
   *
   * <p>Matches on routing key and on the decryption key and extra bytes (either common or
   * per‑block). Entries corresponding to {@code true} values in {@code ignoreSlots} are skipped.
   * When not found, {@code -1} is returned.
   *
   * @param key the complete client key to resolve; routing, crypto, and extra must match stored
   *     values exactly; must not be {@code null}.
   * @param ignoreSlots optional mask of indices to ignore; when {@code null}, all indices are
   *     considered; when provided, {@code true} skips the corresponding position.
   * @return the zero‑based block index if a match is found, or {@code -1} when no match exists or
   *     the only matches occur at ignored positions.
   */
  public int getBlockNumber(ClientCHK key, boolean[] ignoreSlots) {
    byte[] rkey = key.getRoutingKey();
    byte[] ckey = null;
    byte[] extra = null;
    int rkOffset = 0;
    final int total = dataBlocks + checkBlocks;
    for (int i = 0; i < total; i++) {
      boolean notIgnored = !(ignoreSlots != null && ignoreSlots[i]);
      if (notIgnored) {
        if (ckey == null) ckey = key.getCryptoKey();
        if (extra == null) extra = key.getExtra();
        if (matchesClientKeyAt(i, rkOffset, rkey, ckey, extra)) return i;
      }
      rkOffset += NodeCHK.KEY_LENGTH;
    }
    return -1;
  }

  private boolean matchesClientKeyAt(
      int index, int rkOffset, byte[] rkey, byte[] ckey, byte[] extra) {
    if (!Fields.byteArrayEqual(routingKeys, rkey, rkOffset, 0, NodeCHK.KEY_LENGTH)) return false;
    boolean cryptoMatch;
    if (commonDecryptKey != null) {
      cryptoMatch = Arrays.equals(commonDecryptKey, ckey);
    } else {
      int dkOffset = index * ClientCHK.CRYPTO_KEY_LENGTH;
      cryptoMatch =
          Fields.byteArrayEqual(decryptKeys, ckey, dkOffset, 0, ClientCHK.CRYPTO_KEY_LENGTH);
    }
    if (!cryptoMatch) return false;
    if (commonExtraBytes != null) {
      return Arrays.equals(commonExtraBytes, extra);
    } else {
      int exOffset = index * EXTRA_BYTES_LENGTH;
      return Fields.byteArrayEqual(extraBytesForKeys, extra, exOffset, 0, EXTRA_BYTES_LENGTH);
    }
  }

  /**
   * Returns the block index whose routing key equals the supplied {@link NodeCHK}'s routing key.
   *
   * <p>This method compares routing keys only and does not consider crypto keys or extra bytes.
   * Indices masked by {@code ignoreSlots} are skipped. If multiple positions share the same routing
   * key, the first non‑ignored index is returned.
   *
   * @param key the node key supplying the routing key to look up; must not be {@code null}.
   * @param ignoreSlots optional mask of indices to ignore; when {@code null}, searches all
   *     positions; {@code true} marks an index as ignored.
   * @return the zero‑based index of the first matching routing key, or {@code -1} if none match or
   *     all matches are ignored.
   */
  public int getBlockNumber(NodeCHK key, boolean[] ignoreSlots) {
    byte[] rkey = key.getRoutingKey();
    int rkOffset = 0;
    final int total = dataBlocks + checkBlocks;
    for (int i = 0; i < total; i++) {
      boolean notIgnored = !(ignoreSlots != null && ignoreSlots[i]);
      boolean routingMatch =
          notIgnored && Fields.byteArrayEqual(routingKeys, rkey, rkOffset, 0, NodeCHK.KEY_LENGTH);
      if (routingMatch) return i;
      rkOffset += NodeCHK.KEY_LENGTH;
    }
    return -1;
  }

  /**
   * Returns all block indices whose routing key equals the supplied {@link NodeCHK}'s routing key.
   *
   * <p>Only routing keys are compared; crypto keys and extra bytes are not considered. Indices
   * masked by {@code ignoreSlots} are skipped. The returned array is a newly allocated, possibly
   * empty array in ascending index order.
   *
   * @param key the node key providing the routing key to match; must not be {@code null}.
   * @param ignoreSlots optional mask of indices to skip; when {@code null}, examines all indices.
   * @return a new array of zero‑based indices that matched; the array is owned by the caller and
   *     can be freely modified.
   */
  public int[] getBlockNumbers(NodeCHK key, boolean[] ignoreSlots) {
    ArrayList<Integer> results = null;
    byte[] rkey = key.getRoutingKey();
    int rkOffset = 0;
    final int total = dataBlocks + checkBlocks;
    for (int i = 0; i < total; i++) {
      boolean notIgnored = !(ignoreSlots != null && ignoreSlots[i]);
      boolean routingMatch =
          notIgnored && Fields.byteArrayEqual(routingKeys, rkey, rkOffset, 0, NodeCHK.KEY_LENGTH);
      if (routingMatch) {
        if (results == null) results = new ArrayList<>();
        results.add(i);
      }
      rkOffset += NodeCHK.KEY_LENGTH;
    }
    if (results == null) return new int[0];
    int[] ret = new int[results.size()];
    for (int i = 0; i < ret.length; i++) ret[i] = results.get(i);
    return ret;
  }

  /**
   * Returns a {@link NodeCHK} view for the block at {@code x}, or {@code null} if ignored.
   *
   * <p>When {@code copy} is {@code true}, returns a logically equivalent key with defensive copies
   * of underlying arrays; otherwise, the returned key may share backing arrays with this instance.
   * If {@code ignoreSlots} is provided and {@code ignoreSlots[x]} is {@code true}, {@code null} is
   * returned.
   *
   * @param x zero‑based block index within {@code dataBlocks + checkBlocks}; out‑of‑range values
   *     will cause an {@link ArrayIndexOutOfBoundsException} at access time.
   * @param ignoreSlots optional mask that marks indices to ignore; {@code null} means do not ignore
   *     any index.
   * @param copy whether to defensively copy internal arrays to avoid aliasing the instance state.
   * @return a node‑level key for routing and fetching, or {@code null} when the index is marked as
   *     ignored via {@code ignoreSlots}.
   */
  public NodeCHK getNodeKey(int x, boolean[] ignoreSlots, boolean copy) {
    if (ignoreSlots != null && ignoreSlots[x]) return null;
    NodeCHK node = getNodeKey(x);
    return copy ? (NodeCHK) node.cloneKey() : node;
  }

  /**
   * Returns a {@link ClientCHK} for the block at {@code x}, or {@code null} if ignored.
   *
   * <p>Honors {@code copy} in the same way as {@link #getNodeKey(int, boolean[], boolean)}. When a
   * common crypto key/extra are configured, those arrays are reused unless {@code copy} is
   * requested. Otherwise, per‑block slices are returned.
   *
   * @param x zero‑based block index within the segment; must be less than {@code dataBlocks +
   *     checkBlocks}.
   * @param ignoreSlots optional mask to skip indices; when {@code null}, no indices are skipped.
   * @param copy whether to clone backing arrays to avoid sharing with this instance.
   * @return a client‑level key containing routing, crypto key, and extra bytes, or {@code null}
   *     when the block is marked as ignored.
   */
  public ClientCHK getKey(int x, boolean[] ignoreSlots, boolean copy) {
    if (ignoreSlots != null && ignoreSlots[x]) return null;
    return getKey(x, copy);
  }

  private ClientCHK getKey(int x, boolean copy) {
    byte[] routingKey = new byte[NodeCHK.KEY_LENGTH];
    System.arraycopy(routingKeys, x * NodeCHK.KEY_LENGTH, routingKey, 0, NodeCHK.KEY_LENGTH);
    byte[] decryptKey;
    if (commonDecryptKey != null) {
      if (copy) {
        decryptKey = commonDecryptKey.clone();
      } else {
        decryptKey = commonDecryptKey;
      }
    } else {
      int offset = x * ClientCHK.CRYPTO_KEY_LENGTH;
      decryptKey = Arrays.copyOfRange(decryptKeys, offset, offset + ClientCHK.CRYPTO_KEY_LENGTH);
    }
    byte[] extra;
    if (commonExtraBytes != null) {
      if (copy) {
        extra = commonExtraBytes.clone();
      } else {
        extra = commonExtraBytes;
      }
    } else {
      int offset = x * EXTRA_BYTES_LENGTH;
      extra = Arrays.copyOfRange(extraBytesForKeys, offset, offset + EXTRA_BYTES_LENGTH);
    }
    try {
      return new ClientCHK(routingKey, decryptKey, extra);
    } catch (MalformedURLException e) {
      throw new IllegalStateException("Failed to construct ClientCHK from routing/crypto/extra", e);
    }
  }

  private NodeCHK getNodeKey(int x) {
    int xr = x * NodeCHK.KEY_LENGTH;
    byte[] routingKey = Arrays.copyOfRange(routingKeys, xr, xr + NodeCHK.KEY_LENGTH);
    byte[] extra;
    if (commonExtraBytes != null) {
      extra = commonExtraBytes;
    } else {
      int xe = x * EXTRA_BYTES_LENGTH;
      extra = Arrays.copyOfRange(extraBytesForKeys, xe, xe + EXTRA_BYTES_LENGTH);
    }

    byte cryptoAlgorithm = ClientCHK.getCryptoAlgorithmFromExtra(extra);

    return new NodeCHK(routingKey, cryptoAlgorithm);
  }

  /**
   * Reads keys for either data or check blocks from the supplied stream into this instance.
   *
   * <p>When using common crypto material, only routing keys are read. Otherwise, each entry
   * contains extra bytes, routing key, and crypto key as expected by {@link
   * ClientCHK#readRawBinaryKey}.
   *
   * @param dis source stream positioned at the first key for the requested block kind; the method
   *     reads exactly the number of entries implied by the segment sizes.
   * @param check when {@code true}, reads {@link #checkBlocks} keys; otherwise reads {@link
   *     #dataBlocks} keys.
   * @throws IOException if the stream cannot supply the required number of bytes or an I/O error
   *     occurs while reading.
   */
  public void readKeys(DataInputStream dis, boolean check) throws IOException {
    int count = check ? checkBlocks : dataBlocks;
    int offset = check ? dataBlocks : 0;
    int rkOffset = offset * NodeCHK.KEY_LENGTH;
    if (commonDecryptKey != null) {
      for (int i = 0; i < count; i++) {
        dis.readFully(routingKeys, rkOffset, NodeCHK.KEY_LENGTH);
        rkOffset += NodeCHK.KEY_LENGTH;
      }
    } else {
      int extraOffset = offset * EXTRA_BYTES_LENGTH;
      int dkOffset = offset * ClientCHK.CRYPTO_KEY_LENGTH;
      for (int i = 0; i < count; i++) {
        ClientCHK key = ClientCHK.readRawBinaryKey(dis);
        byte[] r = key.getRoutingKey();
        System.arraycopy(r, 0, routingKeys, rkOffset, NodeCHK.KEY_LENGTH);
        byte[] c = key.getCryptoKey();
        System.arraycopy(c, 0, decryptKeys, dkOffset, ClientCHK.CRYPTO_KEY_LENGTH);
        rkOffset += NodeCHK.KEY_LENGTH;
        byte[] e = key.getExtra();
        System.arraycopy(e, 0, extraBytesForKeys, extraOffset, EXTRA_BYTES_LENGTH);
        extraOffset += EXTRA_BYTES_LENGTH;
        dkOffset += ClientCHK.CRYPTO_KEY_LENGTH;
      }
    }
  }

  /**
   * Writes keys for either data or check blocks to the supplied stream from this instance.
   *
   * <p>When using common crypto material, only routing keys are written. Otherwise, for each entry
   * the method writes extra bytes, routing key, then crypto key. The order matches the on‑disk
   * format consumed by {@link #readKeys(DataInputStream, boolean)}.
   *
   * @param dos destination stream to receive the binary key representation; the caller owns the
   *     stream and is responsible for closing it.
   * @param check when {@code true}, writes {@link #checkBlocks} keys; otherwise writes {@link
   *     #dataBlocks} keys.
   * @throws IOException if the stream rejects bytes or another I/O error occurs while writing.
   */
  public void writeKeys(DataOutputStream dos, boolean check) throws IOException {
    int count = check ? checkBlocks : dataBlocks;
    int offset = check ? dataBlocks : 0;
    int rkOffset = offset * NodeCHK.KEY_LENGTH;
    if (commonDecryptKey != null) {
      for (int i = 0; i < count; i++) {
        dos.write(routingKeys, rkOffset, NodeCHK.KEY_LENGTH);
        rkOffset += NodeCHK.KEY_LENGTH;
      }
    } else {
      int extraOffset = offset * EXTRA_BYTES_LENGTH;
      int dkOffset = offset * ClientCHK.CRYPTO_KEY_LENGTH;
      for (int i = 0; i < count; i++) {
        dos.write(extraBytesForKeys, extraOffset, EXTRA_BYTES_LENGTH);
        extraOffset += EXTRA_BYTES_LENGTH;
        dos.write(routingKeys, rkOffset, NodeCHK.KEY_LENGTH);
        dos.write(decryptKeys, dkOffset, ClientCHK.CRYPTO_KEY_LENGTH);
        rkOffset += NodeCHK.KEY_LENGTH;
        dkOffset += ClientCHK.CRYPTO_KEY_LENGTH;
      }
    }
  }

  /**
   * Computes the number of bytes required to store keys for a segment.
   *
   * <p>The result depends on whether a common crypto key is used. With a common key, only routing
   * keys are stored per block. Otherwise, each block stores extra bytes, routing key, and crypto
   * key.
   *
   * @param dataBlocks number of data blocks; must be non‑negative.
   * @param checkBlocks number of check/parity blocks; must be non‑negative.
   * @param commonDecryptKey whether a common decryption key is used for all blocks, reducing the
   *     per‑block storage to routing keys only.
   * @return the total byte length required to persist keys for {@code dataBlocks + checkBlocks}
   *     blocks under the given assumptions.
   */
  public static int storedKeysLength(int dataBlocks, int checkBlocks, boolean commonDecryptKey) {
    int blocks = dataBlocks + checkBlocks;
    if (commonDecryptKey) {
      return blocks * NodeCHK.KEY_LENGTH;
    } else {
      return blocks * (EXTRA_BYTES_LENGTH + NodeCHK.KEY_LENGTH * 2);
    }
  }

  /**
   * Returns the number of data blocks in this segment.
   *
   * @return the count of data (non‑parity) blocks configured at construction time.
   */
  public int getDataBlocks() {
    return dataBlocks;
  }

  /**
   * Returns the number of check/parity blocks in this segment.
   *
   * @return the count of parity blocks configured at construction time.
   */
  public int getCheckBlocks() {
    return checkBlocks;
  }

  /**
   * Sets the key material for a specific block index using a {@link ClientCHK} instance.
   *
   * <p>Writes the routing key unconditionally. When per‑block crypto material is in use, also
   * copies the crypto key and extra bytes into their respective arrays.
   *
   * @param i zero‑based block index to update; must be within the segment range.
   * @param key source of routing key, crypto key, and extra bytes to persist into this instance.
   */
  public void setKey(int i, ClientCHK key) {
    byte[] r = key.getRoutingKey();
    System.arraycopy(r, 0, routingKeys, i * NodeCHK.KEY_LENGTH, NodeCHK.KEY_LENGTH);
    if (decryptKeys != null) {
      byte[] c = key.getCryptoKey();
      System.arraycopy(
          c, 0, decryptKeys, i * ClientCHK.CRYPTO_KEY_LENGTH, ClientCHK.CRYPTO_KEY_LENGTH);
    }
    if (extraBytesForKeys != null) {
      byte[] e = key.getExtra();
      System.arraycopy(e, 0, extraBytesForKeys, i * EXTRA_BYTES_LENGTH, EXTRA_BYTES_LENGTH);
    }
  }

  /**
   * Returns an array of {@link NodeCHK} for all non‑ignored indices in the segment.
   *
   * <p>Indices with {@code true} in {@code foundKeys} are skipped. The {@code copy} parameter has
   * the same meaning as in {@link #getNodeKey(int, boolean[], boolean)}. The returned array is
   * newly allocated and sized to the number of included keys.
   *
   * @param foundKeys optional mask of indices to exclude from the result; {@code null} includes all
   *     indices.
   * @param copy whether to defensively copy internal arrays when constructing each {@link NodeCHK}.
   * @return a new array containing node‑level keys for all included indices, in ascending order.
   */
  public NodeCHK[] listNodeKeys(boolean[] foundKeys, boolean copy) {
    ArrayList<NodeCHK> list = new ArrayList<>();
    for (int i = 0; i < dataBlocks + checkBlocks; i++) {
      NodeCHK k = getNodeKey(i, foundKeys, copy);
      if (k == null) continue;
      list.add(k);
    }
    return list.toArray(new NodeCHK[0]);
  }

  // Clone is intentionally not implemented; prefer explicit copy patterns if needed.

  // Not often used, not very efficient, but overriding equals() requires overriding hashCode().
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + checkBlocks;
    result = prime * result + Arrays.hashCode(commonDecryptKey);
    result = prime * result + Arrays.hashCode(commonExtraBytes);
    result = prime * result + dataBlocks;
    result = prime * result + Arrays.hashCode(decryptKeys);
    result = prime * result + Arrays.hashCode(extraBytesForKeys);
    result = prime * result + Arrays.hashCode(routingKeys);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj instanceof SplitFileSegmentKeys other)) return false;
    if (checkBlocks != other.checkBlocks) return false;
    if (!Arrays.equals(commonDecryptKey, other.commonDecryptKey)) return false;
    if (!Arrays.equals(commonExtraBytes, other.commonExtraBytes)) return false;
    if (dataBlocks != other.dataBlocks) return false;
    if (!Arrays.equals(decryptKeys, other.decryptKeys)) return false;
    if (!Arrays.equals(extraBytesForKeys, other.extraBytesForKeys)) return false;
    return Arrays.equals(routingKeys, other.routingKeys);
  }

  /**
   * Returns the total number of keys managed by this instance.
   *
   * @return the sum of {@link #dataBlocks} and {@link #checkBlocks} representing all block slots.
   */
  public int totalKeys() {
    return checkBlocks + dataBlocks;
  }
}
