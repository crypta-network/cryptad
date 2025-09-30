// LZ.BinTree

package SevenZip.Compression.LZ;

import java.io.IOException;

public class BinTree extends InWindow {
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

  @Override
  public void Init() throws IOException {
    super.Init();
    for (int i = 0; i < hashSizeSum; i++) hash[i] = K_EMPTY_HASH_VALUE;
    cyclicBufferPos = 0;
    ReduceOffsets(-1);
  }

  @Override
  public void MovePos() throws IOException {
    if (++cyclicBufferPos >= cyclicBufferSize) cyclicBufferPos = 0;
    super.MovePos();
    if (_pos == K_MAX_VAL_FOR_NORMALIZE) normalize();
  }

  public void createMatchFinder(
      int historySize, int keepAddBufferBefore, int matchMaxLen, int keepAddBufferAfter) {
    if (historySize > K_MAX_VAL_FOR_NORMALIZE - 256) return;
    cutValue = 16 + (matchMaxLen >> 1);

    int windowReservSize =
        (historySize + keepAddBufferBefore + matchMaxLen + keepAddBufferAfter) / 2 + 256;

    super.Create(
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

  public int getMatches(int[] distances) throws IOException {
    int lenLimit;
    if (_pos + matchMaxLen <= _streamPos) lenLimit = matchMaxLen;
    else {
      lenLimit = _streamPos - _pos;
      if (lenLimit < kMinMatchCheck) {
        MovePos();
        return 0;
      }
    }

    int offset = 0;
    int matchMinPos = (_pos > cyclicBufferSize) ? (_pos - cyclicBufferSize) : 0;
    int cur = _bufferOffset + _pos;
    int maxLen = K_START_MAX_LEN;
    int hashValue;
    int hash2Value = 0;
    int hash3Value = 0;

    if (hashArray) {
      int temp = CrcTable[_bufferBase[cur] & 0xFF] ^ (_bufferBase[cur + 1] & 0xFF);
      hash2Value = temp & (K_HASH2_SIZE - 1);
      temp ^= ((_bufferBase[cur + 2] & 0xFF) << 8);
      hash3Value = temp & (K_HASH3_SIZE - 1);
      hashValue = (temp ^ (CrcTable[_bufferBase[cur + 3] & 0xFF] << 5)) & hashMask;
    } else hashValue = ((_bufferBase[cur] & 0xFF) ^ ((_bufferBase[cur + 1] & 0xFF) << 8));

    int curMatch = hash[kFixHashSize + hashValue];
    if (hashArray) {
      int curMatch2 = hash[hash2Value];
      int curMatch3 = hash[K_HASH3_OFFSET + hash3Value];
      hash[hash2Value] = _pos;
      hash[K_HASH3_OFFSET + hash3Value] = _pos;
      if (curMatch2 > matchMinPos && _bufferBase[_bufferOffset + curMatch2] == _bufferBase[cur]) {
        distances[offset++] = maxLen = 2;
        distances[offset++] = _pos - curMatch2 - 1;
      }
      if (curMatch3 > matchMinPos && _bufferBase[_bufferOffset + curMatch3] == _bufferBase[cur]) {
        if (curMatch3 == curMatch2) offset -= 2;
        distances[offset++] = maxLen = 3;
        distances[offset++] = _pos - curMatch3 - 1;
        curMatch2 = curMatch3;
      }
      if (offset != 0 && curMatch2 == curMatch) {
        offset -= 2;
        maxLen = K_START_MAX_LEN;
      }
    }

    hash[kFixHashSize + hashValue] = _pos;

    int ptr0 = (cyclicBufferPos << 1) + 1;
    int ptr1 = (cyclicBufferPos << 1);

    int len0;
    int len1;
    len0 = len1 = kNumHashDirectBytes;

    if (kNumHashDirectBytes != 0
        && curMatch > matchMinPos
        && _bufferBase[_bufferOffset + curMatch + kNumHashDirectBytes]
            != _bufferBase[cur + kNumHashDirectBytes]) {
      distances[offset++] = maxLen = kNumHashDirectBytes;
      distances[offset++] = _pos - curMatch - 1;
    }

    int count = cutValue;

    while (true) {
      boolean exitLoop = false;
      if (curMatch <= matchMinPos || count-- == 0) {
        son[ptr0] = son[ptr1] = K_EMPTY_HASH_VALUE;
        exitLoop = true;
      } else {
        int delta = _pos - curMatch;
        int cyclicPos =
            ((delta <= cyclicBufferPos)
                    ? (cyclicBufferPos - delta)
                    : (cyclicBufferPos - delta + cyclicBufferSize))
                << 1;

        int pby1 = _bufferOffset + curMatch;
        int len = Math.min(len0, len1);
        if (_bufferBase[pby1 + len] == _bufferBase[cur + len]) {
          while (++len != lenLimit) if (_bufferBase[pby1 + len] != _bufferBase[cur + len]) break;
          if (maxLen < len) {
            distances[offset++] = maxLen = len;
            distances[offset++] = delta - 1;
            if (len == lenLimit) {
              son[ptr1] = son[cyclicPos];
              son[ptr0] = son[cyclicPos + 1];
              exitLoop = true;
            }
          }
        }
        if (!exitLoop) {
          if ((_bufferBase[pby1 + len] & 0xFF) < (_bufferBase[cur + len] & 0xFF)) {
            son[ptr1] = curMatch;
            ptr1 = cyclicPos + 1;
            curMatch = son[ptr1];
            len1 = len;
          } else {
            son[ptr0] = curMatch;
            ptr0 = cyclicPos;
            curMatch = son[ptr0];
            len0 = len;
          }
        }
      }
      if (exitLoop) break;
    }
    MovePos();
    return offset;
  }

  public void skip(int num) throws IOException {
    do {
      int lenLimit;
      if (_pos + matchMaxLen <= _streamPos) lenLimit = matchMaxLen;
      else {
        lenLimit = _streamPos - _pos;
        if (lenLimit < kMinMatchCheck) {
          MovePos();
          continue;
        }
      }

      int matchMinPos = (_pos > cyclicBufferSize) ? (_pos - cyclicBufferSize) : 0;
      int cur = _bufferOffset + _pos;

      int hashValue;

      if (hashArray) {
        int temp = CrcTable[_bufferBase[cur] & 0xFF] ^ (_bufferBase[cur + 1] & 0xFF);
        int hash2Value = temp & (K_HASH2_SIZE - 1);
        hash[hash2Value] = _pos;
        temp ^= ((_bufferBase[cur + 2] & 0xFF) << 8);
        int hash3Value = temp & (K_HASH3_SIZE - 1);
        hash[K_HASH3_OFFSET + hash3Value] = _pos;
        hashValue = (temp ^ (CrcTable[_bufferBase[cur + 3] & 0xFF] << 5)) & hashMask;
      } else hashValue = ((_bufferBase[cur] & 0xFF) ^ ((_bufferBase[cur + 1] & 0xFF) << 8));

      int curMatch = hash[kFixHashSize + hashValue];
      hash[kFixHashSize + hashValue] = _pos;

      int ptr0 = (cyclicBufferPos << 1) + 1;
      int ptr1 = (cyclicBufferPos << 1);

      int len0;
      int len1;
      len0 = len1 = kNumHashDirectBytes;

      int count = cutValue;
      while (true) {
        boolean exitLoop = false;
        if (curMatch <= matchMinPos || count-- == 0) {
          son[ptr0] = son[ptr1] = K_EMPTY_HASH_VALUE;
          exitLoop = true;
        } else {
          int delta = _pos - curMatch;
          int cyclicPos =
              ((delta <= cyclicBufferPos)
                      ? (cyclicBufferPos - delta)
                      : (cyclicBufferPos - delta + cyclicBufferSize))
                  << 1;

          int pby1 = _bufferOffset + curMatch;
          int len = Math.min(len0, len1);
          if (_bufferBase[pby1 + len] == _bufferBase[cur + len]) {
            while (++len != lenLimit) if (_bufferBase[pby1 + len] != _bufferBase[cur + len]) break;
            if (len == lenLimit) {
              son[ptr1] = son[cyclicPos];
              son[ptr0] = son[cyclicPos + 1];
              exitLoop = true;
            }
          }
          if (!exitLoop) {
            if ((_bufferBase[pby1 + len] & 0xFF) < (_bufferBase[cur + len] & 0xFF)) {
              son[ptr1] = curMatch;
              ptr1 = cyclicPos + 1;
              curMatch = son[ptr1];
              len1 = len;
            } else {
              son[ptr0] = curMatch;
              ptr0 = cyclicPos;
              curMatch = son[ptr0];
              len0 = len;
            }
          }
        }
        if (exitLoop) break;
      }
      MovePos();
    } while (--num != 0);
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
    int subValue = _pos - cyclicBufferSize;
    normalizeLinks(son, cyclicBufferSize * 2, subValue);
    normalizeLinks(hash, hashSizeSum, subValue);
    ReduceOffsets(subValue);
  }

  // Removed unused setter to eliminate dead code and IDE warning.

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
