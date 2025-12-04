package org.sevenzip.compression.lz;

import java.io.IOException;

/**
 * Binary-tree based match finder used by the LZMA encoder to discover repeated byte sequences
 * efficiently. The structure extends {@link InWindow} to reuse buffered sliding-window semantics
 * and augments it with hash buckets and a binary tree that tracks recent positions. Clients
 * typically configure the finder with {@link #setType(int)} and {@link #createMatchFinder(int, int,
 * int, int)}, attach an input stream through the {@link InWindow} API, and then alternate calls to
 * {@link #getMatches(int[])} and {@link #skip(int)} while the encoder advances. Instances are
 * mutable, not thread-safe, and should be confined to a single compression pipeline.
 *
 * <p>Responsibilities include maintaining cyclic buffers that hold left/right child links,
 * computing rolling hashes for fast candidate retrieval, and normalizing stored offsets when
 * indexes grow large. The finder limits traversal depth via {@code cutValue} to bound worst-case
 * cost even on adversarial data. Invariants: {@code pos} always reflects the current window index,
 * {@code cyclicBufferPos} remains within {@code [0, cyclicBufferSize)}, and hash tables never store
 * negative values.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Supports two hash configurations: short direct matches (2 bytes) or full hash arrays (3–4
 *       bytes) for longer lookups.
 *   <li>Automatically normalizes stored positions near {@link #K_MAX_VAL_FOR_NORMALIZE} to prevent
 *       integer overflow while preserving relative distances.
 *   <li>Separates match discovery ({@link #getMatches(int[])}) from state advancement ({@link
 *       #skip(int)}) so encoders can probe or fast-forward selectively.
 * </ul>
 *
 * @see InWindow
 */
public class BinTree extends InWindow {

  /**
   * Creates a new, uninitialized match finder with default hash configuration. Callers must choose
   * a hash type via {@link #setType(int)}, size buffers through {@link #createMatchFinder(int, int,
   * int, int)}, and attach a stream on the {@link InWindow} API before collecting matches. This
   * constructor performs no allocation beyond the superclass and is intentionally lightweight so
   * the encoder can instantiate multiple finders when experimenting with settings.
   *
   * <p>This body is intentionally empty because all configuration happens through subsequent
   * setters and the inherited window wiring; construction itself must stay side effect free for
   * reuse by different encoder setups.
   */
  public BinTree() {
    // Intentionally empty: setup is deferred to setter-style methods to keep construction side
    // effect free.
  }

  int cyclicBufferPos;
  int cyclicBufferSize = 0;
  int matchMaxLen;

  int[] son;
  int[] hash;

  int cutValue = 0xFF;
  int hashMask;
  int hashSizeSum = 0;

  boolean hashArray = true;

  static final int K_HASH2_SIZE = 1 << 10;
  static final int K_HASH3_SIZE = 1 << 16;
  static final int K_BT2_HASH_SIZE = 1 << 16;
  static final int K_START_MAX_LEN = 1;
  static final int K_HASH3_OFFSET = K_HASH2_SIZE;
  static final int K_EMPTY_HASH_VALUE = 0;
  static final int K_MAX_VAL_FOR_NORMALIZE = (1 << 30) - 1;

  int kNumHashDirectBytes = 0;
  int kMinMatchCheck = 4;
  int kFixHashSize = K_HASH2_SIZE + K_HASH3_SIZE;

  /**
   * Configures the hash strategy based on the number of bytes to hash for initial candidate
   * selection.
   *
   * <p>Values greater than two enable full hash arrays with three- and four-byte signatures,
   * favoring accuracy at the cost of memory. Values of two or less switch to a lightweight mode
   * that relies on direct-byte comparisons with minimal hash tables, suitable for tiny dictionaries
   * or constrained environments. Must be invoked before {@link #createMatchFinder(int, int, int,
   * int)} so that buffer sizing matches the chosen strategy.
   *
   * @param numHashBytes number of leading bytes used to build hash keys; must be positive and
   *     typically 2–4 depending on match finder variant.
   */
  public void setType(int numHashBytes) {
    hashArray = (numHashBytes > 2);
    if (hashArray) {
      kNumHashDirectBytes = 0;
      kMinMatchCheck = 4;
      kFixHashSize = K_HASH2_SIZE + K_HASH3_SIZE;
    } else {
      kNumHashDirectBytes = 2;
      kMinMatchCheck = 2 + 1;
      kFixHashSize = 0;
    }
  }

  /**
   * Resets internal buffers and hash tables, then primes the window by delegating to {@link
   * InWindow#init()}.
   *
   * <p>After initialization the current position is zero, all hash and tree links are cleared to
   * {@link #K_EMPTY_HASH_VALUE}, and offsets are adjusted via {@link #reduceOffsets(int)} to keep
   * indices aligned. Callers must set the input stream on the inherited API before invoking this
   * method. Subsequent calls to {@link #getMatches(int[])} or {@link #skip(int)} assume this setup
   * has completed successfully.
   *
   * @throws IOException if the underlying stream cannot be read while priming the window buffer.
   */
  @Override
  public void init() throws IOException {
    super.init();
    for (int i = 0; i < hashSizeSum; i++) hash[i] = K_EMPTY_HASH_VALUE;
    cyclicBufferPos = 0;
    reduceOffsets(-1);
  }

  /**
   * Advances the current position by one byte, updating the cyclic buffer pointer and normalizing
   * offsets when necessary.
   *
   * <p>This method increments {@code pos}, slides the cyclic pointer with wrap-around, and
   * delegates to {@link InWindow#movePos()} to shift or refill the underlying window. When the
   * absolute position reaches {@link #K_MAX_VAL_FOR_NORMALIZE}, stored offsets are compacted
   * through {@link #normalize()} to avoid integer overflow while preserving match distances.
   * Callers should use this in lockstep with match collection or skipping to keep the tree
   * consistent.
   *
   * @throws IOException if additional data must be read from the stream during the move and the
   *     read fails.
   */
  @Override
  public void movePos() throws IOException {
    if (++cyclicBufferPos >= cyclicBufferSize) cyclicBufferPos = 0;
    super.movePos();
    if (pos == K_MAX_VAL_FOR_NORMALIZE) normalize();
  }

  /**
   * Allocates and wires all buffers required for binary-tree match finding given the chosen
   * dictionary and lookahead sizes.
   *
   * <p>The method sizes the cyclic buffer, hash arrays, and window reservation based on the history
   * size and match length limits. It also derives {@code cutValue}, which caps tree traversal depth
   * to balance speed and match quality. Call this exactly once after {@link #setType(int)} and
   * before {@link #init()} so the inherited window knows its keep-before/after sizes.
   *
   * @param historySize maximum backward distance (dictionary size) in bytes that matches may span;
   *     must be positive and not exceed {@link #K_MAX_VAL_FOR_NORMALIZE} minus a small margin.
   * @param keepAddBufferBefore extra bytes kept before the current position to tolerate backward
   *     lookups beyond {@code historySize}; often zero in typical LZMA usage.
   * @param matchMaxLen maximum match length to report; governs buffer sizing and traversal cut-off;
   *     must be at least the encoder's fast-bytes setting.
   * @param keepAddBufferAfter additional lookahead bytes preserved after the current position to
   *     reduce refills during long matches; non-negative.
   */
  public void createMatchFinder(
      int historySize, int keepAddBufferBefore, int matchMaxLen, int keepAddBufferAfter) {
    if (historySize > K_MAX_VAL_FOR_NORMALIZE - 256) return;
    cutValue = 16 + (matchMaxLen >> 1);

    int windowReservSize =
        (historySize + keepAddBufferBefore + matchMaxLen + keepAddBufferAfter) / 2 + 256;

    super.create(
        historySize + keepAddBufferBefore, matchMaxLen + keepAddBufferAfter, windowReservSize);

    this.matchMaxLen = matchMaxLen;

    int cyclicBufferSizeLocal = historySize + 1;
    if (cyclicBufferSize != cyclicBufferSizeLocal) {
      cyclicBufferSize = cyclicBufferSizeLocal;
      son = new int[cyclicBufferSize * 2];
    }

    int hs = K_BT2_HASH_SIZE;

    if (hashArray) {
      hs = historySize - 1;
      hs |= (hs >> 1);
      hs |= (hs >> 2);
      hs |= (hs >> 4);
      hs |= (hs >> 8);
      hs >>= 1;
      hs |= 0xFFFF;
      if (hs > (1 << 24)) hs >>= 1;
      hashMask = hs;
      hs++;
      hs += kFixHashSize;
    }
    if (hs != hashSizeSum) {
      hashSizeSum = hs;
      hash = new int[hashSizeSum];
    }
  }

  /**
   * Collects match candidates at the current position and writes alternating length/distance pairs
   * into the supplied buffer.
   *
   * <p>The method hashes the current prefix, probes recent positions via the binary tree, and
   * returns the number of integers written (twice the number of matches). Each even index contains
   * a match length, and the subsequent odd index holds the backward distance minus one. When
   * lookahead is insufficient the method advances the position and returns zero. Tree traversal is
   * bounded by {@code cutValue} to prevent excessive scanning. The caller owns the {@code
   * distances} array and must size it to at least {@code 2 * matchMaxLen}.
   *
   * @param distances target array that receives length and distance pairs; must be non-null and
   *     large enough for all potential matches.
   * @return count of integers stored in {@code distances}; zero when no match is recorded due to
   *     insufficient lookahead or empty history.
   * @throws IOException if advancing the position triggers a window refill that fails.
   */
  public int getMatches(int[] distances) throws IOException {
    int lenLimit;
    if (pos + matchMaxLen <= streamPos) lenLimit = matchMaxLen;
    else {
      lenLimit = streamPos - pos;
      if (lenLimit < kMinMatchCheck) {
        movePos();
        return 0;
      }
    }

    int offset = 0;
    int matchMinPos = (pos > cyclicBufferSize) ? (pos - cyclicBufferSize) : 0;
    int cur = bufferOffset + pos;
    int maxLen = K_START_MAX_LEN;

    InitHashResult init = prepareInitHash(cur, matchMinPos, maxLen, distances, offset);
    int curMatch = init.curMatch;
    offset = init.offset;
    maxLen = init.maxLen;

    int ptr0 = (cyclicBufferPos << 1) + 1;
    int ptr1 = (cyclicBufferPos << 1);

    int len0;
    int len1;
    len0 = len1 = kNumHashDirectBytes;

    if (kNumHashDirectBytes != 0
        && curMatch > matchMinPos
        && bufferBase[bufferOffset + curMatch + kNumHashDirectBytes]
            != bufferBase[cur + kNumHashDirectBytes]) {
      distances[offset++] = maxLen = kNumHashDirectBytes;
      distances[offset++] = pos - curMatch - 1;
    }

    int count = cutValue;
    CollectState cs = new CollectState();
    cs.curMatch = curMatch;
    cs.matchMinPos = matchMinPos;
    cs.cur = cur;
    cs.lenLimit = lenLimit;
    cs.maxLen = maxLen;
    cs.ptr0 = ptr0;
    cs.ptr1 = ptr1;
    cs.len0 = len0;
    cs.len1 = len1;
    cs.distances = distances;
    cs.offset = offset;
    cs.count = count;
    traverseAndCollect(cs);
    offset = cs.offset;
    movePos();
    return offset;
  }

  /**
   * Advances the match finder state by the requested number of positions without emitting matches.
   *
   * <p>Useful when the encoder selects a literal or already knows the distance to use. The method
   * repeats internal hashing and tree maintenance for each skipped byte to keep structures in sync,
   * but discards any collected matches. Traversal depth obeys {@code cutValue} to maintain bounded
   * complexity. Negative values are not allowed; zero is a no-op aside from boundary checks.
   *
   * @param num number of positions to advance; must be non-negative and typically small relative to
   *     the dictionary size.
   * @throws IOException if window movement while skipping requires reading from the stream and the
   *     read fails.
   */
  public void skip(int num) throws IOException {
    do {
      int lenLimit;
      if (pos + matchMaxLen <= streamPos) lenLimit = matchMaxLen;
      else {
        lenLimit = streamPos - pos;
        if (lenLimit < kMinMatchCheck) {
          movePos();
          continue;
        }
      }

      int matchMinPos = (pos > cyclicBufferSize) ? (pos - cyclicBufferSize) : 0;
      int cur = bufferOffset + pos;

      int curMatch = prepareInitHashForSkip(cur);

      int ptr0 = (cyclicBufferPos << 1) + 1;
      int ptr1 = (cyclicBufferPos << 1);

      int len0;
      int len1;
      len0 = len1 = kNumHashDirectBytes;

      SkipState ss = new SkipState();
      ss.curMatch = curMatch;
      ss.matchMinPos = matchMinPos;
      ss.cur = cur;
      ss.lenLimit = lenLimit;
      ss.ptr0 = ptr0;
      ss.ptr1 = ptr1;
      ss.len0 = len0;
      ss.len1 = len1;
      ss.count = cutValue;
      traverseAndSkip(ss);
      movePos();
    } while (--num != 0);
  }

  private static final class CollectState {
    int curMatch;
    int matchMinPos;
    int cur;
    int lenLimit;
    int maxLen;
    int ptr0;
    int ptr1;
    int len0;
    int len1;
    int offset;
    int count;
    int[] distances;
  }

  private static final class SkipState {
    int curMatch;
    int matchMinPos;
    int cur;
    int lenLimit;
    int ptr0;
    int ptr1;
    int len0;
    int len1;
    int count;
  }

  private void traverseAndCollect(CollectState s) {
    while (true) {
      boolean exitLoop = false;
      if (shouldExitAndClear(s)) {
        exitLoop = true;
      } else {
        int delta = pos - s.curMatch;
        int cyclicPos = cyclicPosFromDelta(delta);
        int pby1 = bufferOffset + s.curMatch;
        int len = Math.min(s.len0, s.len1);
        len = extendIfEqual(len, pby1, s.cur, s.lenLimit);
        if (recordIfBetterAndMaybeLinkCollect(s, len, delta, cyclicPos)) {
          exitLoop = true;
        } else {
          branchNextCollect(s, len, cyclicPos, pby1);
        }
      }
      if (exitLoop) break;
    }
  }

  private void traverseAndSkip(SkipState s) {
    while (true) {
      boolean exitLoop = false;
      if (shouldExitAndClear(s)) {
        exitLoop = true;
      } else {
        int delta = pos - s.curMatch;
        int cyclicPos = cyclicPosFromDelta(delta);
        int pby1 = bufferOffset + s.curMatch;
        int len = Math.min(s.len0, s.len1);
        len = extendIfEqual(len, pby1, s.cur, s.lenLimit);
        if (len == s.lenLimit) {
          son[s.ptr1] = son[cyclicPos];
          son[s.ptr0] = son[cyclicPos + 1];
          exitLoop = true;
        } else {
          branchNextSkip(s, len, cyclicPos, pby1);
        }
      }
      if (exitLoop) break;
    }
  }

  private boolean shouldExitAndClear(CollectState s) {
    if (s.curMatch <= s.matchMinPos || s.count-- == 0) {
      son[s.ptr0] = son[s.ptr1] = K_EMPTY_HASH_VALUE;
      return true;
    }
    return false;
  }

  private boolean shouldExitAndClear(SkipState s) {
    if (s.curMatch <= s.matchMinPos || s.count-- == 0) {
      son[s.ptr0] = son[s.ptr1] = K_EMPTY_HASH_VALUE;
      return true;
    }
    return false;
  }

  private int cyclicPosFromDelta(int delta) {
    return ((delta <= cyclicBufferPos)
            ? (cyclicBufferPos - delta)
            : (cyclicBufferPos - delta + cyclicBufferSize))
        << 1;
  }

  private int extendIfEqual(int len, int pby1, int cur, int lenLimit) {
    if (bufferBase[pby1 + len] == bufferBase[cur + len]) {
      while (++len != lenLimit) if (bufferBase[pby1 + len] != bufferBase[cur + len]) break;
    }
    return len;
  }

  private boolean recordIfBetterAndMaybeLinkCollect(
      CollectState s, int len, int delta, int cyclicPos) {
    if (s.maxLen < len) {
      s.distances[s.offset++] = s.maxLen = len;
      s.distances[s.offset++] = delta - 1;
      if (len == s.lenLimit) {
        son[s.ptr1] = son[cyclicPos];
        son[s.ptr0] = son[cyclicPos + 1];
        return true;
      }
    }
    return false;
  }

  private void branchNextCollect(CollectState s, int len, int cyclicPos, int pby1) {
    if ((bufferBase[pby1 + len] & 0xFF) < (bufferBase[s.cur + len] & 0xFF)) {
      son[s.ptr1] = s.curMatch;
      s.ptr1 = cyclicPos + 1;
      s.curMatch = son[s.ptr1];
      s.len1 = len;
    } else {
      son[s.ptr0] = s.curMatch;
      s.ptr0 = cyclicPos;
      s.curMatch = son[s.ptr0];
      s.len0 = len;
    }
  }

  private void branchNextSkip(SkipState s, int len, int cyclicPos, int pby1) {
    if ((bufferBase[pby1 + len] & 0xFF) < (bufferBase[s.cur + len] & 0xFF)) {
      son[s.ptr1] = s.curMatch;
      s.ptr1 = cyclicPos + 1;
      s.curMatch = son[s.ptr1];
      s.len1 = len;
    } else {
      son[s.ptr0] = s.curMatch;
      s.ptr0 = cyclicPos;
      s.curMatch = son[s.ptr0];
      s.len0 = len;
    }
  }

  void normalizeLinks(int[] items, int numItems, int subValue) {
    for (int i = 0; i < numItems; i++) {
      int value = items[i];
      if (value <= subValue) value = K_EMPTY_HASH_VALUE;
      else value -= subValue;
      items[i] = value;
    }
  }

  void normalize() {
    int subValue = pos - cyclicBufferSize;
    normalizeLinks(son, cyclicBufferSize * 2, subValue);
    normalizeLinks(hash, hashSizeSum, subValue);
    reduceOffsets(subValue);
  }

  private static final class InitHashResult {
    int curMatch;
    int offset;
    int maxLen;
  }

  private InitHashResult prepareInitHash(
      int cur, int matchMinPos, int maxLen, int[] distances, int offset) {
    int hashValue;
    int hash2Value = 0;
    int hash3Value = 0;
    if (hashArray) {
      int temp = CrcTable[bufferBase[cur] & 0xFF] ^ (bufferBase[cur + 1] & 0xFF);
      hash2Value = temp & (K_HASH2_SIZE - 1);
      temp ^= ((bufferBase[cur + 2] & 0xFF) << 8);
      hash3Value = temp & (K_HASH3_SIZE - 1);
      hashValue = (temp ^ (CrcTable[bufferBase[cur + 3] & 0xFF] << 5)) & hashMask;
    } else {
      hashValue = ((bufferBase[cur] & 0xFF) ^ ((bufferBase[cur + 1] & 0xFF) << 8));
    }

    int curMatch = hash[kFixHashSize + hashValue];
    if (hashArray) {
      int curMatch2 = hash[hash2Value];
      int curMatch3 = hash[K_HASH3_OFFSET + hash3Value];
      hash[hash2Value] = pos;
      hash[K_HASH3_OFFSET + hash3Value] = pos;
      if (curMatch2 > matchMinPos && bufferBase[bufferOffset + curMatch2] == bufferBase[cur]) {
        distances[offset++] = maxLen = 2;
        distances[offset++] = pos - curMatch2 - 1;
      }
      if (curMatch3 > matchMinPos && bufferBase[bufferOffset + curMatch3] == bufferBase[cur]) {
        if (curMatch3 == curMatch2) offset -= 2;
        distances[offset++] = maxLen = 3;
        distances[offset++] = pos - curMatch3 - 1;
        curMatch2 = curMatch3;
      }
      if (offset != 0 && curMatch2 == curMatch) {
        offset -= 2;
        maxLen = K_START_MAX_LEN;
      }
    }
    hash[kFixHashSize + hashValue] = pos;
    InitHashResult r = new InitHashResult();
    r.curMatch = curMatch;
    r.offset = offset;
    r.maxLen = maxLen;
    return r;
  }

  private int prepareInitHashForSkip(int cur) {
    int hashValue;
    if (hashArray) {
      int temp = CrcTable[bufferBase[cur] & 0xFF] ^ (bufferBase[cur + 1] & 0xFF);
      int hash2Value = temp & (K_HASH2_SIZE - 1);
      hash[hash2Value] = pos;
      temp ^= ((bufferBase[cur + 2] & 0xFF) << 8);
      int hash3Value = temp & (K_HASH3_SIZE - 1);
      hash[K_HASH3_OFFSET + hash3Value] = pos;
      hashValue = (temp ^ (CrcTable[bufferBase[cur + 3] & 0xFF] << 5)) & hashMask;
    } else {
      hashValue = ((bufferBase[cur] & 0xFF) ^ ((bufferBase[cur + 1] & 0xFF) << 8));
    }
    int curMatch = hash[kFixHashSize + hashValue];
    hash[kFixHashSize + hashValue] = pos;
    return curMatch;
  }

  private static final int[] CrcTable = new int[256];

  static {
    for (int i = 0; i < 256; i++) {
      int r = i;
      for (int j = 0; j < 8; j++)
        if ((r & 1) != 0) r = (r >>> 1) ^ 0xEDB88320;
        else r >>>= 1;
      CrcTable[i] = r;
    }
  }
}
