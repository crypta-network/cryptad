package network.crypta.crypt.ciphers;

import java.security.InvalidKeyException;
import java.util.Arrays;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// ...........................................................................
/**
 * Implements the Rijndael block cipher.
 *
 * <p>Rijndael supports variable block sizes (128, 192, and 256 bits) and variable key sizes (128,
 * 192, and 256 bits). The AES standard (FIPS‑197) corresponds to the 128‑bit block variant. This
 * implementation provides optimized 128‑bit and 256‑bit block modes; the 192‑bit block mode is not
 * implemented.
 *
 * <p>The class precomputes S‑boxes, inverse S‑boxes, round constants, and T/U tables during static
 * initialization. After class loading, methods are stateless and thread‑safe. All arrays passed to
 * the API must be non‑null and large enough to hold the requested block.
 *
 * <p>Rijndael was written by <a href="mailto:rijmen@esat.kuleuven.ac.be">Vincent Rijmen</a> and <a
 * href="mailto:Joan.Daemen@village.uunet.be">Joan Daemen</a>.
 *
 * <p>Portions of this code are <b>Copyright</b> &copy; 1997, 1998 <a
 * href="http://www.systemics.com/">Systemics Ltd</a> on behalf of the <a
 * href="http://www.systemics.com/docs/cryptix/">Cryptix Development Team</a>. <br>
 * All rights reserved.
 *
 * @author Raif S. Naffah
 * @author Paulo S. L. M. Barreto
 * @implNote This class exposes a small, package‑private API that higher‑level ciphers use. It is
 *     not a general‑purpose {@code javax.crypto.Cipher} implementation.
 *     <p>License is apparently available from http://www.cryptix.org/docs/license.html
 */
@SuppressWarnings("OperatorPrecedence")
public final class RijndaelAlgorithm // implicit no-argument constructor
 {
  private static final Logger LOG = LoggerFactory.getLogger(RijndaelAlgorithm.class);

  //	Debugging methods and variables
  //	...........................................................................

  // Logging is controlled by SLF4J. These flags gate additional verbose traces.

  static final String ALGORITHM = "Rijndael";
  static final double VERSION = 0.1;
  static final String FULL_NAME = ALGORITHM + " ver. " + VERSION;

  private static final String NAME = "Rijndael_Algorithm";
  private static final boolean IN = true;
  private static final boolean OUT = false;

  /** When true, emit verbose internal state logs guarded by SLF4J levels. */
  private static final boolean RDEBUG = false;

  /** When true, trace input/output of top‑level API methods. */
  private static final boolean TRACE = false;

  private static final String TRACE_BLOCK_ENCRYPT = "blockEncrypt()";
  private static final String TRACE_BLOCK_DECRYPT = "blockDecrypt()";
  private static final String TRACE_BLOCK_DECRYPT_OPEN = "blockDecrypt(";

  private static void debug(String s) {
    if (LOG.isTraceEnabled()) LOG.trace(">>> " + NAME + ": {}", s);
  }

  private static void trace(boolean in, String s) {
    if (TRACE && LOG.isTraceEnabled()) LOG.trace("{}" + NAME + ".{}", in ? "==> " : "<== ", s);
  }

  //	Constants and variables
  //	...........................................................................

  /** Default block size in bytes (128‑bit blocks). */
  private static final int BLOCK_SIZE = 16; // default block size in bytes

  private static final int[] alog = new int[256];
  // Discrete logarithm table (base 3) for GF(2^8) with modulus 0x11B.
  private static final int[] LOG_TABLE = new int[256];

  private static final byte[] S = new byte[256];
  private static final byte[] Si = new byte[256];
  private static final int[] T1 = new int[256];
  private static final int[] T2 = new int[256];
  private static final int[] T3 = new int[256];
  private static final int[] T4 = new int[256];
  private static final int[] T5 = new int[256];
  private static final int[] T6 = new int[256];
  private static final int[] T7 = new int[256];
  private static final int[] T8 = new int[256];
  private static final int[] U1 = new int[256];
  private static final int[] U2 = new int[256];
  private static final int[] U3 = new int[256];
  private static final int[] U4 = new int[256];
  private static final byte[] rcon = new byte[30];

  private static final int[][][] shifts =
      new int[][][] {
        {{0, 0}, {1, 3}, {2, 2}, {3, 1}},
        {{0, 0}, {1, 5}, {2, 4}, {3, 3}},
        {{0, 0}, {1, 7}, {3, 5}, {4, 4}}
      };

  private static final char[] HEX_DIGITS = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
  };

  //	Static code - to initialize S‑boxes and T‑boxes
  //	...........................................................................

  static {
    long time = System.currentTimeMillis();

    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("Algorithm Name: {}", FULL_NAME);
      LOG.debug("Electronic Codebook (ECB) Mode");
      LOG.debug("init.section=ecb-mode.end");
    }
    int root = 0x11B;
    int i;
    int j;

    //
    // Produce log and antilog tables used for multiplication in GF(2^8)
    // with generator 3 and irreducible polynomial 0x11B.
    //
    generateLogAndAlogTables(root);
    generateSBoxes();

    //
    // T‑boxes (combine SubBytes + MixColumns for speed)
    //
    byte[][] g =
        new byte[][] {
          {2, 1, 1, 3},
          {3, 2, 1, 1},
          {1, 3, 2, 1},
          {1, 1, 3, 2}
        };
    byte[][] iG = generateInvertedGMatrix(g);
    generateTBoxes(g, iG);

    //
    // Round constants for the key schedule
    //
    rcon[0] = 1;
    int r = 1;
    for (int t = 1; t < 30; t++) {
      r = mul(2, r);
      rcon[t] = (byte) r;
    }

    time = System.currentTimeMillis() - time;

    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("init.banner=begin");
      LOG.debug("init.section=static-data.start");
      LOG.debug("Static Data");
      LOG.debug("init.section=static-data.header.end");
      LOG.debug("S[]:");
      for (i = 0; i < 16; i++) {
        StringBuilder sb = new StringBuilder();
        for (j = 0; j < 16; j++) sb.append("0x").append(byteToString(S[i * 16 + j])).append(", ");
        LOG.debug(sb.toString());
      }
      LOG.debug("init.section=sbox.end");
      LOG.debug("Si[]:");
      for (i = 0; i < 16; i++) {
        StringBuilder sb2 = new StringBuilder();
        for (j = 0; j < 16; j++) sb2.append("0x").append(byteToString(Si[i * 16 + j])).append(", ");
        LOG.debug(sb2.toString());
      }

      LOG.debug("init.section=inv-sbox.end");
      LOG.debug("iG[]:");
      for (i = 0; i < 4; i++) {
        StringBuilder sb3 = new StringBuilder();
        for (j = 0; j < 4; j++) sb3.append("0x").append(byteToString(iG[i][j])).append(", ");
        LOG.debug(sb3.toString());
      }

      LOG.debug("init.section=ig.end");
      LOG.debug("T1[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT1 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT1.append("0x").append(intToString(T1[i * 4 + j])).append(", ");
        LOG.debug(sbT1.toString());
      }
      LOG.debug("init.section=t1.end");
      LOG.debug("T2[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT2 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT2.append("0x").append(intToString(T2[i * 4 + j])).append(", ");
        LOG.debug(sbT2.toString());
      }
      LOG.debug("init.section=t2.end");
      LOG.debug("T3[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT3 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT3.append("0x").append(intToString(T3[i * 4 + j])).append(", ");
        LOG.debug(sbT3.toString());
      }
      LOG.debug("init.section=t3.end");
      LOG.debug("T4[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT4 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT4.append("0x").append(intToString(T4[i * 4 + j])).append(", ");
        LOG.debug(sbT4.toString());
      }
      LOG.debug("init.section=t4.end");
      LOG.debug("T5[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT5 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT5.append("0x").append(intToString(T5[i * 4 + j])).append(", ");
        LOG.debug(sbT5.toString());
      }
      LOG.debug("init.section=t5.end");
      LOG.debug("T6[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT6 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT6.append("0x").append(intToString(T6[i * 4 + j])).append(", ");
        LOG.debug(sbT6.toString());
      }
      LOG.debug("init.section=t6.end");
      LOG.debug("T7[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT7 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT7.append("0x").append(intToString(T7[i * 4 + j])).append(", ");
        LOG.debug(sbT7.toString());
      }
      LOG.debug("init.section=t7.end");
      LOG.debug("T8[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT8 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT8.append("0x").append(intToString(T8[i * 4 + j])).append(", ");
        LOG.debug(sbT8.toString());
      }

      LOG.debug("init.section=t8.end");
      LOG.debug("U1[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbU1 = new StringBuilder();
        for (j = 0; j < 4; j++) sbU1.append("0x").append(intToString(U1[i * 4 + j])).append(", ");
        LOG.debug(sbU1.toString());
      }
      LOG.debug("init.section=u1.end");
      LOG.debug("U2[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbU2 = new StringBuilder();
        for (j = 0; j < 4; j++) sbU2.append("0x").append(intToString(U2[i * 4 + j])).append(", ");
        LOG.debug(sbU2.toString());
      }
      LOG.debug("init.section=u2.end");
      LOG.debug("U3[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbU3 = new StringBuilder();
        for (j = 0; j < 4; j++) sbU3.append("0x").append(intToString(U3[i * 4 + j])).append(", ");
        LOG.debug(sbU3.toString());
      }
      LOG.debug("init.section=u3.end");
      LOG.debug("U4[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbU4 = new StringBuilder();
        for (j = 0; j < 4; j++) sbU4.append("0x").append(intToString(U4[i * 4 + j])).append(", ");
        LOG.debug(sbU4.toString());
      }

      LOG.debug("init.section=u4.end");
      LOG.debug("rcon[]:");
      for (i = 0; i < 5; i++) {
        StringBuilder sbR = new StringBuilder();
        for (j = 0; j < 6; j++) sbR.append("0x").append(byteToString(rcon[i * 6 + j])).append(", ");
        LOG.debug(sbR.toString());
      }

      LOG.debug("init.section=rcon.end");
      LOG.debug("Total initialization time: {} ms.", time);
      LOG.debug("init.section=complete");
    }
  }

  /** Build base‑3 log/antilog tables for GF(2^8) using the given modulus. */
  private static void generateLogAndAlogTables(int root) {
    alog[0] = 1;
    for (int i = 1; i < 256; i++) {
      int j = alog[i - 1] << 1 ^ alog[i - 1];
      if ((j & 0x100) != 0) j ^= root;
      alog[i] = j;
    }
    for (int i = 1; i < 255; i++) LOG_TABLE[alog[i]] = i;
  }

  /**
   * Compute the forward and inverse S‑boxes.
   *
   * <p>Each S‑box entry is the multiplicative inverse in GF(2^8) (with 0 mapped to 0), followed by
   * the affine transform defined by the Rijndael specification. The inverse S‑box {@code Si}
   * satisfies {@code Si[S[x]] == x} for all bytes {@code x}.
   */
  private static void generateSBoxes() {
    byte[][] aMatrix =
        new byte[][] {
          {1, 1, 1, 1, 1, 0, 0, 0},
          {0, 1, 1, 1, 1, 1, 0, 0},
          {0, 0, 1, 1, 1, 1, 1, 0},
          {0, 0, 0, 1, 1, 1, 1, 1},
          {1, 0, 0, 0, 1, 1, 1, 1},
          {1, 1, 0, 0, 0, 1, 1, 1},
          {1, 1, 1, 0, 0, 0, 1, 1},
          {1, 1, 1, 1, 0, 0, 0, 1}
        };
    byte[] bVector = new byte[] {0, 1, 1, 0, 0, 0, 1, 1};

    //
    // Substitution box based on F^{-1}(x)
    //
    byte[][] box = new byte[256][8];
    box[1][7] = 1;
    for (int i = 2; i < 256; i++) {
      int j = alog[255 - LOG_TABLE[i]];
      for (int t = 0; t < 8; t++) box[i][t] = (byte) (j >>> 7 - t & 0x01);
    }
    //
    // Affine transform:  box[i] <- bVector + aMatrix*box[i]
    //
    byte[][] cox = new byte[256][8];
    for (int i = 0; i < 256; i++)
      for (int t = 0; t < 8; t++) {
        cox[i][t] = bVector[t];
        for (int j = 0; j < 8; j++) {
          // Compute in the int domain and narrow once to avoid sign extension surprises.
          cox[i][t] =
              (byte)
                  ((cox[i][t] & 0xFF ^ (aMatrix[t][j] & 0xFF) * (box[i][j] & 0xFF) & 0xFF) & 0xFF);
        }
      }
    //
    // S-boxes and inverse S-boxes
    //
    for (int i = 0; i < 256; i++) {
      S[i] = (byte) ((cox[i][0] & 0xFF) << 7);
      for (int t = 1; t < 8; t++) {
        // Compute as int and cast once to avoid lossy implicit narrowing.
        S[i] = (byte) ((S[i] & 0xFF ^ (cox[i][t] & 0xFF) << 7 - t & 0xFF) & 0xFF);
      }
      Si[S[i] & 0xFF] = (byte) i;
    }
  }

  /**
   * Invert the 4×4 MixColumns matrix in GF(2^8) via Gaussian elimination.
   *
   * @param gMatrix The MixColumns matrix.
   * @return The inverse matrix {@code iG} such that {@code gMatrix * iG = I} in GF(2^8).
   */
  private static byte[][] generateInvertedGMatrix(byte[][] gMatrix) {
    byte[][] aa = new byte[4][8];
    for (int i = 0; i < 4; i++) {
      System.arraycopy(gMatrix[i], 0, aa[i], 0, 4);
      aa[i][i + 4] = 1;
    }
    for (int i = 0; i < 4; i++) {
      byte pivot = aa[i][i];
      if (pivot == 0) {
        int t = i + 1;
        while (t < 4 && aa[t][i] == 0) t++;
        if (t == 4) throw new IllegalArgumentException("G matrix is not invertible");
        swapRows(aa, i, t);
        pivot = aa[i][i];
      }
      normalizeRow(aa, i, pivot);
      eliminateColumn(aa, i);
    }
    byte[][] iG = new byte[4][4];
    for (int i = 0; i < 4; i++) System.arraycopy(aa[i], 4, iG[i], 0, 4);
    return iG;
  }

  private static void swapRows(byte[][] a, int r1, int r2) {
    for (int j = 0; j < 8; j++) {
      byte tmp = a[r1][j];
      a[r1][j] = a[r2][j];
      a[r2][j] = tmp;
    }
  }

  private static void normalizeRow(byte[][] aa, int i, byte pivot) {
    for (int j = 0; j < 8; j++) {
      if (aa[i][j] != 0) {
        aa[i][j] = (byte) alog[(255 + LOG_TABLE[aa[i][j] & 0xFF] - LOG_TABLE[pivot & 0xFF]) % 255];
      }
    }
  }

  /** Eliminate column {@code i} from all rows except {@code i} in-place (GF(2^8)). */
  private static void eliminateColumn(byte[][] aa, int i) {
    for (int t = 0; t < 4; t++) {
      if (i != t) {
        for (int j = i + 1; j < 8; j++) {
          // Narrow the XOR result explicitly to byte.
          aa[t][j] =
              (byte) ((aa[t][j] & 0xFF ^ mul(aa[i][j] & 0xFF, aa[t][i] & 0xFF) & 0xFF) & 0xFF);
        }
        aa[t][i] = 0;
      }
    }
  }

  /**
   * Precompute the T/U tables.
   *
   * <p>T1..T4 combine SubBytes and MixColumns for encryption; T5..T8 and U1..U4 are the analogous
   * tables for decryption and inverse MixColumns.
   */
  private static void generateTBoxes(byte[][] g, byte[][] iG) {
    for (int t = 0; t < 256; t++) {
      int s = S[t];
      T1[t] = mul4(s, g[0]);
      T2[t] = mul4(s, g[1]);
      T3[t] = mul4(s, g[2]);
      T4[t] = mul4(s, g[3]);

      s = Si[t];
      T5[t] = mul4(s, iG[0]);
      T6[t] = mul4(s, iG[1]);
      T7[t] = mul4(s, iG[2]);
      T8[t] = mul4(s, iG[3]);

      U1[t] = mul4(t, iG[0]);
      U2[t] = mul4(t, iG[1]);
      U3[t] = mul4(t, iG[2]);
      U4[t] = mul4(t, iG[3]);
    }
  }

  // Multiply two elements of GF(2^8) using log/antilog tables.
  private static int mul(int a, int b) {
    return a != 0 && b != 0 ? alog[(LOG_TABLE[a & 0xFF] + LOG_TABLE[b & 0xFF]) % 255] : 0;
  }

  // Multiply element 'a' by the 4‑vector 'b' in GF(2^8) and pack into a 32‑bit word.
  private static int mul4(int a, byte[] b) {
    if (a == 0) return 0;
    a = LOG_TABLE[a & 0xFF];
    int a0 = b[0] != 0 ? alog[(a + LOG_TABLE[b[0] & 0xFF]) % 255] & 0xFF : 0;
    int a1 = b[1] != 0 ? alog[(a + LOG_TABLE[b[1] & 0xFF]) % 255] & 0xFF : 0;
    int a2 = b[2] != 0 ? alog[(a + LOG_TABLE[b[2] & 0xFF]) % 255] & 0xFF : 0;
    int a3 = b[3] != 0 ? alog[(a + LOG_TABLE[b[3] & 0xFF]) % 255] & 0xFF : 0;
    return a0 << 24 | a1 << 16 | a2 << 8 | a3;
  }

  //	Basic API methods
  //	...........................................................................

  /**
   * Encrypt one 128‑bit block.
   *
   * <p>This is the optimized path for the default block size. The {@code sessionKey} must be the
   * object returned by {@link #makeKey(byte[], int)} for a 16‑byte block size.
   *
   * @param in The plaintext buffer.
   * @param result The output buffer for the ciphertext; must have at least 16 writable bytes.
   * @param inOffset Byte offset into {@code in} where the block starts.
   * @param sessionKey A session key created with {@code blockSize == 16}.
   */
  private static void blockEncrypt(byte[] in, byte[] result, int inOffset, Object sessionKey) {
    if (RDEBUG)
      trace(IN, "blockEncrypt(" + Arrays.toString(in) + ", " + inOffset + ", " + sessionKey + ')');
    int[][] ke = (int[][]) ((Object[]) sessionKey)[0]; // extract encryption round keys
    int rounds = ke.length - 1;
    int[] ker = ke[0];

    // plaintext to ints + key
    int t0 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ ker[0];
    int t1 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ ker[1];
    int t2 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ ker[2];
    int t3 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset] & 0xFF)
            ^ ker[3];

    int a0;
    int a1;
    int a2;
    int a3;
    for (int r = 1; r < rounds; r++) { // apply round transforms
      ker = ke[r];
      a0 =
          T1[t0 >>> 24 & 0xFF]
              ^ T2[t1 >>> 16 & 0xFF]
              ^ T3[t2 >>> 8 & 0xFF]
              ^ T4[t3 & 0xFF]
              ^ ker[0];
      a1 =
          T1[t1 >>> 24 & 0xFF]
              ^ T2[t2 >>> 16 & 0xFF]
              ^ T3[t3 >>> 8 & 0xFF]
              ^ T4[t0 & 0xFF]
              ^ ker[1];
      a2 =
          T1[t2 >>> 24 & 0xFF]
              ^ T2[t3 >>> 16 & 0xFF]
              ^ T3[t0 >>> 8 & 0xFF]
              ^ T4[t1 & 0xFF]
              ^ ker[2];
      a3 =
          T1[t3 >>> 24 & 0xFF]
              ^ T2[t0 >>> 16 & 0xFF]
              ^ T3[t1 >>> 8 & 0xFF]
              ^ T4[t2 & 0xFF]
              ^ ker[3];
      t0 = a0;
      t1 = a1;
      t2 = a2;
      t3 = a3;
      if (RDEBUG && LOG.isDebugEnabled()) {
        LOG.debug(
            "event=blockEncrypt.round.ct round={} ct={}",
            r,
            intToString(t0) + intToString(t1) + intToString(t2) + intToString(t3));
      }
    }

    // the last round is special
    ker = ke[rounds];
    int tt = ker[0];
    result[0] = (byte) (S[t0 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[1] = (byte) (S[t1 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[2] = (byte) (S[t2 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[3] = (byte) (S[t3 & 0xFF] ^ tt & 0xFF);
    tt = ker[1];
    result[4] = (byte) (S[t1 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[5] = (byte) (S[t2 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[6] = (byte) (S[t3 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[7] = (byte) (S[t0 & 0xFF] ^ tt & 0xFF);
    tt = ker[2];
    result[8] = (byte) (S[t2 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[9] = (byte) (S[t3 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[10] = (byte) (S[t0 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[11] = (byte) (S[t1 & 0xFF] ^ tt & 0xFF);
    tt = ker[3];
    result[12] = (byte) (S[t3 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[13] = (byte) (S[t0 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[14] = (byte) (S[t1 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[15] = (byte) (S[t2 & 0xFF] ^ tt & 0xFF);
    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("event=blockEncrypt.final.ct ct={}", toString(result));
      LOG.debug("event=blockEncrypt.final.ct end");
    }
    if (RDEBUG) trace(OUT, TRACE_BLOCK_ENCRYPT);
  }

  /**
   * Encrypt one 256‑bit block (Rijndael‑256; not standard AES).
   *
   * @param in The plaintext buffer.
   * @param result The output buffer for the ciphertext; must have at least 32 writable bytes.
   * @param inOffset Byte offset into {@code in} where the block starts.
   * @param sessionKey A session key created with {@code blockSize == 32}.
   */
  private static void blockEncrypt256(byte[] in, byte[] result, int inOffset, Object sessionKey) {
    if (RDEBUG)
      trace(
          IN, "blockEncrypt256(" + Arrays.toString(in) + ", " + inOffset + ", " + sessionKey + ')');
    int[][] ke = (int[][]) ((Object[]) sessionKey)[0]; // extract encryption round keys
    int rounds = ke.length - 1;
    int[] ker = ke[0];

    // plaintext to ints + key
    int t0 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ ker[0];
    int t1 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ ker[1];
    int t2 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ ker[2];
    int t3 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ ker[3];
    int t4 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ ker[4];
    int t5 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ ker[5];
    int t6 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ ker[6];
    int t7 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset] & 0xFF)
            ^ ker[7];

    int a0;
    int a1;
    int a2;
    int a3;
    int a4;
    int a5;
    int a6;
    int a7;
    for (int r = 1; r < rounds; r++) { // apply round transforms
      ker = ke[r];
      a0 =
          T1[t0 >>> 24 & 0xFF]
              ^ T2[t1 >>> 16 & 0xFF]
              ^ T3[t3 >>> 8 & 0xFF]
              ^ T4[t4 & 0xFF]
              ^ ker[0];

      a1 =
          T1[t1 >>> 24 & 0xFF]
              ^ T2[t2 >>> 16 & 0xFF]
              ^ T3[t4 >>> 8 & 0xFF]
              ^ T4[t5 & 0xFF]
              ^ ker[1];

      a2 =
          T1[t2 >>> 24 & 0xFF]
              ^ T2[t3 >>> 16 & 0xFF]
              ^ T3[t5 >>> 8 & 0xFF]
              ^ T4[t6 & 0xFF]
              ^ ker[2];

      a3 =
          T1[t3 >>> 24 & 0xFF]
              ^ T2[t4 >>> 16 & 0xFF]
              ^ T3[t6 >>> 8 & 0xFF]
              ^ T4[t7 & 0xFF]
              ^ ker[3];

      a4 =
          T1[t4 >>> 24 & 0xFF]
              ^ T2[t5 >>> 16 & 0xFF]
              ^ T3[t7 >>> 8 & 0xFF]
              ^ T4[t0 & 0xFF]
              ^ ker[4];

      a5 =
          T1[t5 >>> 24 & 0xFF]
              ^ T2[t6 >>> 16 & 0xFF]
              ^ T3[t0 >>> 8 & 0xFF]
              ^ T4[t1 & 0xFF]
              ^ ker[5];

      a6 =
          T1[t6 >>> 24 & 0xFF]
              ^ T2[t7 >>> 16 & 0xFF]
              ^ T3[t1 >>> 8 & 0xFF]
              ^ T4[t2 & 0xFF]
              ^ ker[6];

      a7 =
          T1[t7 >>> 24 & 0xFF]
              ^ T2[t0 >>> 16 & 0xFF]
              ^ T3[t2 >>> 8 & 0xFF]
              ^ T4[t3 & 0xFF]
              ^ ker[7];
      t0 = a0;
      t1 = a1;
      t2 = a2;
      t3 = a3;
      t4 = a4;
      t5 = a5;
      t6 = a6;
      t7 = a7;
      if (RDEBUG && LOG.isDebugEnabled()) {
        LOG.debug(
            "event=blockEncrypt256.round.ct round={} ct={}",
            r,
            intToString(t0) + intToString(t1) + intToString(t2) + intToString(t3));
      }
    }

    // the last round is special
    ker = ke[rounds];
    int tt = ker[0];
    result[0] = (byte) (S[t0 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[1] = (byte) (S[t1 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[2] = (byte) (S[t3 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[3] = (byte) (S[t4 & 0xFF] ^ tt & 0xFF);
    tt = ker[1];
    result[4] = (byte) (S[t1 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[5] = (byte) (S[t2 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[6] = (byte) (S[t4 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[7] = (byte) (S[t5 & 0xFF] ^ tt & 0xFF);
    tt = ker[2];
    result[8] = (byte) (S[t2 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[9] = (byte) (S[t3 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[10] = (byte) (S[t5 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[11] = (byte) (S[t6 & 0xFF] ^ tt & 0xFF);
    tt = ker[3];
    result[12] = (byte) (S[t3 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[13] = (byte) (S[t4 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[14] = (byte) (S[t6 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[15] = (byte) (S[t7 & 0xFF] ^ tt & 0xFF);
    tt = ker[4];
    result[16] = (byte) (S[t4 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[17] = (byte) (S[t5 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[18] = (byte) (S[t7 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[19] = (byte) (S[t0 & 0xFF] ^ tt & 0xFF);
    tt = ker[5];
    result[20] = (byte) (S[t5 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[21] = (byte) (S[t6 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[22] = (byte) (S[t0 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[23] = (byte) (S[t1 & 0xFF] ^ tt & 0xFF);
    tt = ker[6];
    result[24] = (byte) (S[t6 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[25] = (byte) (S[t7 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[26] = (byte) (S[t1 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[27] = (byte) (S[t2 & 0xFF] ^ tt & 0xFF);
    tt = ker[7];
    result[28] = (byte) (S[t7 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[29] = (byte) (S[t0 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[30] = (byte) (S[t2 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[31] = (byte) (S[t3 & 0xFF] ^ tt & 0xFF);
    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("event=blockEncrypt256.final.ct ct={}", toString(result));
      LOG.debug("event=blockEncrypt256.final.ct end");
    }
    if (RDEBUG) trace(OUT, TRACE_BLOCK_ENCRYPT);
  }

  /**
   * Decrypt one 128‑bit block.
   *
   * <p>This is the optimized path for the default block size. The {@code sessionKey} must be the
   * object returned by {@link #makeKey(byte[], int)} for a 16‑byte block size.
   *
   * @param in The ciphertext buffer.
   * @param result The output buffer for the plaintext; must have at least 16 writable bytes.
   * @param inOffset Byte offset into {@code in} where the block starts.
   * @param sessionKey A session key created with {@code blockSize == 16}.
   */
  private static void blockDecrypt(byte[] in, byte[] result, int inOffset, Object sessionKey) {
    if (RDEBUG)
      trace(
          IN,
          TRACE_BLOCK_DECRYPT_OPEN
              + Arrays.toString(in)
              + ", "
              + inOffset
              + ", "
              + sessionKey
              + ')');
    int[][] kd = (int[][]) ((Object[]) sessionKey)[1]; // extract decryption round keys
    int rounds = kd.length - 1;
    int[] kdr = kd[0];

    // ciphertext to ints + key
    int t0 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ kdr[0];
    int t1 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ kdr[1];
    int t2 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ kdr[2];
    int t3 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset] & 0xFF)
            ^ kdr[3];

    int a0;
    int a1;
    int a2;
    int a3;
    for (int r = 1; r < rounds; r++) { // apply round transforms
      kdr = kd[r];
      a0 =
          T5[t0 >>> 24 & 0xFF]
              ^ T6[t3 >>> 16 & 0xFF]
              ^ T7[t2 >>> 8 & 0xFF]
              ^ T8[t1 & 0xFF]
              ^ kdr[0];
      a1 =
          T5[t1 >>> 24 & 0xFF]
              ^ T6[t0 >>> 16 & 0xFF]
              ^ T7[t3 >>> 8 & 0xFF]
              ^ T8[t2 & 0xFF]
              ^ kdr[1];
      a2 =
          T5[t2 >>> 24 & 0xFF]
              ^ T6[t1 >>> 16 & 0xFF]
              ^ T7[t0 >>> 8 & 0xFF]
              ^ T8[t3 & 0xFF]
              ^ kdr[2];
      a3 =
          T5[t3 >>> 24 & 0xFF]
              ^ T6[t2 >>> 16 & 0xFF]
              ^ T7[t1 >>> 8 & 0xFF]
              ^ T8[t0 & 0xFF]
              ^ kdr[3];
      t0 = a0;
      t1 = a1;
      t2 = a2;
      t3 = a3;
      if (RDEBUG && LOG.isDebugEnabled()) {
        LOG.debug(
            "event=blockDecrypt.round.pt round={} pt={}",
            r,
            intToString(t0) + intToString(t1) + intToString(t2) + intToString(t3));
      }
    }

    // the last round is special
    kdr = kd[rounds];
    int tt = kdr[0];
    result[0] = (byte) (Si[t0 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[1] = (byte) (Si[t3 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[2] = (byte) (Si[t2 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[3] = (byte) (Si[t1 & 0xFF] ^ tt & 0xFF);
    tt = kdr[1];
    result[4] = (byte) (Si[t1 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[5] = (byte) (Si[t0 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[6] = (byte) (Si[t3 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[7] = (byte) (Si[t2 & 0xFF] ^ tt & 0xFF);
    tt = kdr[2];
    result[8] = (byte) (Si[t2 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[9] = (byte) (Si[t1 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[10] = (byte) (Si[t0 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[11] = (byte) (Si[t3 & 0xFF] ^ tt & 0xFF);
    tt = kdr[3];
    result[12] = (byte) (Si[t3 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[13] = (byte) (Si[t2 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[14] = (byte) (Si[t1 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[15] = (byte) (Si[t0 & 0xFF] ^ tt & 0xFF);
    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("event=blockDecrypt.final.pt pt={}", toString(result));
      LOG.debug("event=blockDecrypt.final.pt end");
    }
    if (RDEBUG) trace(OUT, TRACE_BLOCK_DECRYPT);
  }

  /**
   * Decrypt one 256‑bit block (Rijndael‑256; not standard AES).
   *
   * @param in The ciphertext buffer.
   * @param result The output buffer for the plaintext; must have at least 32 writable bytes.
   * @param inOffset Byte offset into {@code in} where the block starts.
   * @param sessionKey A session key created with {@code blockSize == 32}.
   */
  private static void blockDecrypt256(byte[] in, byte[] result, int inOffset, Object sessionKey) {
    if (RDEBUG)
      trace(
          IN,
          TRACE_BLOCK_DECRYPT_OPEN
              + Arrays.toString(in)
              + ", "
              + inOffset
              + ", "
              + sessionKey
              + ')');
    int[][] kd = (int[][]) ((Object[]) sessionKey)[1]; // extract decryption round keys
    int rounds = kd.length - 1;
    int[] kdr = kd[0];

    // ciphertext to ints + key
    int t0 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ kdr[0];
    int t1 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ kdr[1];
    int t2 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ kdr[2];
    int t3 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ kdr[3];
    int t4 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ kdr[4];
    int t5 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ kdr[5];
    int t6 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset++] & 0xFF)
            ^ kdr[6];
    int t7 =
        ((in[inOffset++] & 0xFF) << 24
                | (in[inOffset++] & 0xFF) << 16
                | (in[inOffset++] & 0xFF) << 8
                | in[inOffset] & 0xFF)
            ^ kdr[7];

    int a0;
    int a1;
    int a2;
    int a3;
    int a4;
    int a5;
    int a6;
    int a7;
    for (int r = 1; r < rounds; r++) { // apply round transforms
      kdr = kd[r];
      a0 =
          T5[t0 >>> 24 & 0xFF]
              ^ T6[t7 >>> 16 & 0xFF]
              ^ T7[t5 >>> 8 & 0xFF]
              ^ T8[t4 & 0xFF]
              ^ kdr[0];

      a1 =
          T5[t1 >>> 24 & 0xFF]
              ^ T6[t0 >>> 16 & 0xFF]
              ^ T7[t6 >>> 8 & 0xFF]
              ^ T8[t5 & 0xFF]
              ^ kdr[1];

      a2 =
          T5[t2 >>> 24 & 0xFF]
              ^ T6[t1 >>> 16 & 0xFF]
              ^ T7[t7 >>> 8 & 0xFF]
              ^ T8[t6 & 0xFF]
              ^ kdr[2];

      a3 =
          T5[t3 >>> 24 & 0xFF]
              ^ T6[t2 >>> 16 & 0xFF]
              ^ T7[t0 >>> 8 & 0xFF]
              ^ T8[t7 & 0xFF]
              ^ kdr[3];

      a4 =
          T5[t4 >>> 24 & 0xFF]
              ^ T6[t3 >>> 16 & 0xFF]
              ^ T7[t1 >>> 8 & 0xFF]
              ^ T8[t0 & 0xFF]
              ^ kdr[4];

      a5 =
          T5[t5 >>> 24 & 0xFF]
              ^ T6[t4 >>> 16 & 0xFF]
              ^ T7[t2 >>> 8 & 0xFF]
              ^ T8[t1 & 0xFF]
              ^ kdr[5];

      a6 =
          T5[t6 >>> 24 & 0xFF]
              ^ T6[t5 >>> 16 & 0xFF]
              ^ T7[t3 >>> 8 & 0xFF]
              ^ T8[t2 & 0xFF]
              ^ kdr[6];

      a7 =
          T5[t7 >>> 24 & 0xFF]
              ^ T6[t6 >>> 16 & 0xFF]
              ^ T7[t4 >>> 8 & 0xFF]
              ^ T8[t3 & 0xFF]
              ^ kdr[7];
      t0 = a0;
      t1 = a1;
      t2 = a2;
      t3 = a3;
      t4 = a4;
      t5 = a5;
      t6 = a6;
      t7 = a7;
      if (RDEBUG && LOG.isDebugEnabled()) {
        LOG.debug(
            "event=blockDecrypt256.round.pt round={} pt0={} pt1={} pt2={} pt3={}",
            r,
            intToString(t0),
            intToString(t1),
            intToString(t2),
            intToString(t3));
      }
    }

    // the last round is special
    kdr = kd[rounds];
    int tt = kdr[0];
    result[0] = (byte) (Si[t0 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[1] = (byte) (Si[t7 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[2] = (byte) (Si[t5 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[3] = (byte) (Si[t4 & 0xFF] ^ tt & 0xFF);
    tt = kdr[1];
    result[4] = (byte) (Si[t1 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[5] = (byte) (Si[t0 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[6] = (byte) (Si[t6 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[7] = (byte) (Si[t5 & 0xFF] ^ tt & 0xFF);
    tt = kdr[2];
    result[8] = (byte) (Si[t2 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[9] = (byte) (Si[t1 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[10] = (byte) (Si[t7 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[11] = (byte) (Si[t6 & 0xFF] ^ tt & 0xFF);
    tt = kdr[3];
    result[12] = (byte) (Si[t3 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[13] = (byte) (Si[t2 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[14] = (byte) (Si[t0 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[15] = (byte) (Si[t7 & 0xFF] ^ tt & 0xFF);
    tt = kdr[4];
    result[16] = (byte) (Si[t4 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[17] = (byte) (Si[t3 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[18] = (byte) (Si[t1 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[19] = (byte) (Si[t0 & 0xFF] ^ tt & 0xFF);
    tt = kdr[5];
    result[20] = (byte) (Si[t5 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[21] = (byte) (Si[t4 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[22] = (byte) (Si[t2 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[23] = (byte) (Si[t1 & 0xFF] ^ tt & 0xFF);
    tt = kdr[6];
    result[24] = (byte) (Si[t6 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[25] = (byte) (Si[t5 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[26] = (byte) (Si[t3 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[27] = (byte) (Si[t2 & 0xFF] ^ tt & 0xFF);
    tt = kdr[7];
    result[28] = (byte) (Si[t7 >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
    result[29] = (byte) (Si[t6 >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
    result[30] = (byte) (Si[t4 >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
    result[31] = (byte) (Si[t3 & 0xFF] ^ tt & 0xFF);
    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("event=blockDecrypt256.final.pt pt={}", toString(result));
      LOG.debug("event=blockDecrypt256.final.pt end");
    }
    if (RDEBUG) trace(OUT, TRACE_BLOCK_DECRYPT);
  }

  /**
   * Run a basic encrypt/decrypt round‑trip test using the default block size.
   *
   * @return {@code true} if the round‑trip returns the original plaintext
   */
  static boolean selfTest() {
    return selfTest(BLOCK_SIZE);
  }

  //	Rijndael own methods
  //	...........................................................................

  /** Returns the default block size in bytes (16). */
  static int blockSize() {
    return BLOCK_SIZE;
  }

  /**
   * Expand a user‑supplied key into an opaque session key.
   *
   * <p>The returned object must be passed unchanged to {@link #blockEncrypt(byte[], byte[], int,
   * Object, int)} and {@link #blockDecrypt(byte[], byte[], int, Object, int)} with the same {@code
   * blockSize}.
   *
   * @param k The 128‑, 192‑, or 256‑bit user key.
   * @param blockSize Block size in bytes (supported: 16 or 32).
   * @return An opaque session key object for use with {@code blockEncrypt}/{@code blockDecrypt}.
   * @throws InvalidKeyException If {@code k} is {@code null}; if {@code k.length} is not 16, 24, or
   *     32; or if {@code blockSize} is not supported.
   */
  static Object makeKey(byte[] k, int blockSize) throws InvalidKeyException {
    if (RDEBUG) trace(IN, "makeKey(" + Arrays.toString(k) + ", " + blockSize + ')');
    if (k == null) throw new InvalidKeyException("Empty key");
    if (!(k.length == 16 || k.length == 24 || k.length == 32))
      throw new InvalidKeyException("Incorrect key length");
    int rounds = getRounds(k.length, blockSize);
    int bc = blockSize / 4;
    final int bcShift =
        switch (bc) {
          case 4 -> 2;
          case 8 -> 3;
          default -> throw new InvalidKeyException("Unsupported block size: " + blockSize);
        };
    int[][] ke = new int[rounds + 1][bc]; // encryption round keys
    int[][] kd = new int[rounds + 1][bc]; // decryption round keys
    int roundKeyCount = rounds + 1 << bcShift;
    int kc = k.length / 4;
    int[] tk = new int[kc];
    // copy user material bytes into temporary ints
    fillTkFromKey(k, kc, tk);
    // Build a small context to avoid long param lists
    KeyScheduleCtx ctx = new KeyScheduleCtx(ke, kd, rounds, bcShift, bc, kc, roundKeyCount);
    // copy initial round keys
    int t = copyRoundKeysFromTk(ctx, tk, 0);
    // evolve a key schedule and continue copying until filled
    evolveKeySchedule(ctx, tk, t);
    // inverse MixColumn where needed for decryption keys
    inverseMixColumnsOnKd(ctx.kd, ctx.rounds, ctx.bc);
    // assemble the encryption (Ke) and decryption (Kd) round keys into
    // one sessionKey object
    Object[] sessionKey = new Object[] {ke, kd};
    if (RDEBUG) trace(OUT, "makeKey()");
    return sessionKey;
  }

  private static void fillTkFromKey(byte[] k, int kc, int[] tk) {
    int i;
    int j;
    for (i = 0, j = 0; i < kc; ) {
      tk[i++] =
          (k[j++] & 0xFF) << 24 | (k[j++] & 0xFF) << 16 | (k[j++] & 0xFF) << 8 | k[j++] & 0xFF;
    }
  }

  private static int copyRoundKeysFromTk(KeyScheduleCtx ctx, int[] tk, int t) {
    for (int j = 0; j < ctx.kc && t < ctx.roundKeyCount; j++, t++) {
      ctx.ke[t >>> ctx.bcShift][t & ctx.bc - 1] = tk[j];
      ctx.kd[ctx.rounds - (t >>> ctx.bcShift)][t & ctx.bc - 1] = tk[j];
    }
    return t;
  }

  @SuppressWarnings("UnusedReturnValue")
  private static int evolveKeySchedule(KeyScheduleCtx ctx, int[] tk, int t) {
    int rconPointer = 0;
    while (t < ctx.roundKeyCount) {
      int tt = tk[ctx.kc - 1];
      // phi evolution
      tk[0] ^=
          (S[tt >>> 16 & 0xFF] & 0xFF) << 24
              ^ (S[tt >>> 8 & 0xFF] & 0xFF) << 16
              ^ (S[tt & 0xFF] & 0xFF) << 8
              ^ S[tt >>> 24 & 0xFF] & 0xFF
              ^ (rcon[rconPointer++] & 0xFF) << 24;
      if (ctx.kc != 8) {
        kcNot8Evolution(ctx.kc, tk);
      } else {
        kc8Evolution(ctx.kc, tk);
      }
      t = copyRoundKeysFromTk(ctx, tk, t);
    }
    return t;
  }

  private static void kcNot8Evolution(int kc, int[] tk) {
    for (int i = 1, j = 0; i < kc; i++, j++) {
      tk[i] ^= tk[j];
    }
  }

  private static void kc8Evolution(int kc, int[] tk) {
    int i;
    int j;
    for (i = 1, j = 0; i < kc / 2; i++, j++) {
      tk[i] ^= tk[j];
    }
    int tt = tk[kc / 2 - 1];
    tk[kc / 2] ^=
        S[tt & 0xFF] & 0xFF
            ^ (S[tt >>> 8 & 0xFF] & 0xFF) << 8
            ^ (S[tt >>> 16 & 0xFF] & 0xFF) << 16
            ^ (S[tt >>> 24 & 0xFF] & 0xFF) << 24;
    for (j = kc / 2, i = j + 1; i < kc; i++, j++) {
      tk[i] ^= tk[j];
    }
  }

  // Apply inverse MixColumns to intermediate decryption round keys (not to the first/last rounds).
  private static void inverseMixColumnsOnKd(int[][] kd, int rounds, int bc) {
    for (int r = 1; r < rounds; r++) {
      for (int j = 0; j < bc; j++) {
        int tt = kd[r][j];
        kd[r][j] =
            U1[tt >>> 24 & 0xFF] ^ U2[tt >>> 16 & 0xFF] ^ U3[tt >>> 8 & 0xFF] ^ U4[tt & 0xFF];
      }
    }
  }

  private record KeyScheduleCtx(
      int[][] ke, int[][] kd, int rounds, int bcShift, int bc, int kc, int roundKeyCount) {
    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (!(o
          instanceof
          KeyScheduleCtx(
              int[][] ke1,
              int[][] kd1,
              int rounds1,
              int shift,
              int bc1,
              int kc1,
              int keyCount))) return false;
      return rounds == rounds1
          && bcShift == shift
          && bc == bc1
          && kc == kc1
          && roundKeyCount == keyCount
          && Arrays.deepEquals(ke, ke1)
          && Arrays.deepEquals(kd, kd1);
    }

    @Override
    public int hashCode() {
      int result = Integer.hashCode(rounds);
      result = 31 * result + Integer.hashCode(bcShift);
      result = 31 * result + Integer.hashCode(bc);
      result = 31 * result + Integer.hashCode(kc);
      result = 31 * result + Integer.hashCode(roundKeyCount);
      result = 31 * result + Arrays.deepHashCode(ke);
      result = 31 * result + Arrays.deepHashCode(kd);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "KeyScheduleCtx{"
          + "ke="
          + Arrays.deepToString(ke)
          + ", kd="
          + Arrays.deepToString(kd)
          + ", rounds="
          + rounds
          + ", bcShift="
          + bcShift
          + ", bc="
          + bc
          + ", kc="
          + kc
          + ", roundKeyCount="
          + roundKeyCount
          + '}';
    }
  }

  /**
   * Encrypt exactly one block.
   *
   * <p>Supports generic Rijndael block sizes. Optimized 128‑/256‑bit paths are used when possible.
   *
   * @param in The plaintext buffer.
   * @param result The output buffer for the ciphertext; must have at least {@code blockSize}
   *     writable bytes.
   * @param inOffset Byte offset into {@code in} where the block starts.
   * @param sessionKey A session key previously created by {@link #makeKey(byte[], int)} with the
   *     same {@code blockSize}.
   * @param blockSize Block size in bytes.
   */
  static void blockEncrypt(
      byte[] in, byte[] result, int inOffset, Object sessionKey, int blockSize) {
    if (blockSize == BLOCK_SIZE) {
      blockEncrypt(in, result, inOffset, sessionKey);
      return;
    }
    if (blockSize == 256 / 8) {
      blockEncrypt256(in, result, inOffset, sessionKey);
      return;
    }
    if (RDEBUG)
      trace(
          IN,
          "blockEncrypt("
              + Arrays.toString(in)
              + ", "
              + inOffset
              + ", "
              + sessionKey
              + ", "
              + blockSize
              + ')');
    Object[] sKey = (Object[]) sessionKey; // extract encryption round keys
    int[][] ke = (int[][]) sKey[0];

    int bc = blockSize / 4;
    int rounds = ke.length - 1;
    int sc =
        switch (bc) {
          case 4 -> 0;
          case 6 -> 1;
          default -> 2;
        };
    int s1 = shifts[sc][1][0];
    int s2 = shifts[sc][2][0];
    int s3 = shifts[sc][3][0];
    int[] sEnc = new int[] {s1, s2, s3};
    int[] a = new int[bc];
    int[] t = new int[bc]; // temporary work array
    int i;

    for (i = 0; i < bc; i++) { // plaintext to ints + key
      t[i] =
          ((in[inOffset++] & 0xFF) << 24
                  | (in[inOffset++] & 0xFF) << 16
                  | (in[inOffset++] & 0xFF) << 8
                  | in[inOffset++] & 0xFF)
              ^ ke[0][i];
    }
    for (int r = 1; r < rounds; r++) { // apply round transforms
      for (i = 0; i < bc; i++)
        a[i] =
            T1[t[i] >>> 24 & 0xFF]
                ^ T2[t[(i + s1) % bc] >>> 16 & 0xFF]
                ^ T3[t[(i + s2) % bc] >>> 8 & 0xFF]
                ^ T4[t[(i + s3) % bc] & 0xFF]
                ^ ke[r][i];
      System.arraycopy(a, 0, t, 0, bc);
      if (RDEBUG && LOG.isDebugEnabled())
        LOG.debug("event=blockEncryptGeneric.round.ct round={} ct={}", r, toString(t));
    }
    finalRoundEncryptGeneric(ke, rounds, bc, sEnc, t, result);
    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("event=blockEncryptGeneric.final.ct ct={}", toString(result));
      LOG.debug("event=blockEncryptGeneric.final.ct end");
    }
    if (RDEBUG) trace(OUT, TRACE_BLOCK_ENCRYPT);
  }

  /**
   * Decrypt exactly one block.
   *
   * <p>Supports generic Rijndael block sizes. Optimized 128‑/256‑bit paths are used when possible.
   *
   * @param in The ciphertext buffer.
   * @param result The output buffer for the plaintext; must have at least {@code blockSize}
   *     writable bytes.
   * @param inOffset Byte offset into {@code in} where the block starts.
   * @param sessionKey A session key previously created by {@link #makeKey(byte[], int)} with the
   *     same {@code blockSize}.
   * @param blockSize Block size in bytes.
   */
  @SuppressWarnings("SameParameterValue")
  static void blockDecrypt(
      byte[] in, byte[] result, int inOffset, Object sessionKey, int blockSize) {
    if (blockSize == BLOCK_SIZE) {
      blockDecrypt(in, result, inOffset, sessionKey);
      return;
    }
    if (blockSize == 256 / 8) {
      blockDecrypt256(in, result, inOffset, sessionKey);
      return;
    }

    if (RDEBUG)
      trace(
          IN,
          TRACE_BLOCK_DECRYPT_OPEN
              + Arrays.toString(in)
              + ", "
              + inOffset
              + ", "
              + sessionKey
              + ", "
              + blockSize
              + ')');
    Object[] sKey = (Object[]) sessionKey; // extract decryption round keys
    int[][] kd = (int[][]) sKey[1];

    int bc = blockSize / 4;
    int rounds = kd.length - 1;
    int sc =
        switch (bc) {
          case 4 -> 0;
          case 6 -> 1;
          default -> 2;
        };
    int s1 = shifts[sc][1][1];
    int s2 = shifts[sc][2][1];
    int s3 = shifts[sc][3][1];
    int[] sDec = new int[] {s1, s2, s3};
    int[] a = new int[bc];
    int[] t = new int[bc]; // temporary work array
    int i;

    for (i = 0; i < bc; i++) { // ciphertext to ints + key
      t[i] =
          ((in[inOffset++] & 0xFF) << 24
                  | (in[inOffset++] & 0xFF) << 16
                  | (in[inOffset++] & 0xFF) << 8
                  | in[inOffset++] & 0xFF)
              ^ kd[0][i];
    }
    for (int r = 1; r < rounds; r++) { // apply round transforms
      for (i = 0; i < bc; i++)
        a[i] =
            T5[t[i] >>> 24 & 0xFF]
                ^ T6[t[(i + s1) % bc] >>> 16 & 0xFF]
                ^ T7[t[(i + s2) % bc] >>> 8 & 0xFF]
                ^ T8[t[(i + s3) % bc] & 0xFF]
                ^ kd[r][i];
      System.arraycopy(a, 0, t, 0, bc);
      if (RDEBUG && LOG.isDebugEnabled())
        LOG.debug("event=blockDecryptGeneric.round.pt round={} pt={}", r, toString(t));
    }
    finalRoundDecryptGeneric(kd, rounds, bc, sDec, t, result);
    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("event=blockDecryptGeneric.final.pt pt={}", toString(result));
      LOG.debug("event=blockDecryptGeneric.final.pt end");
    }
    if (RDEBUG) trace(OUT, TRACE_BLOCK_DECRYPT);
  }

  /**
   * Run a basic encrypt/decrypt round‑trip test for a given key size (in bytes).
   *
   * @param keysize Key size in bytes (16, 24, or 32).
   * @return {@code true} if the round‑trip returns the original plaintext
   */
  private static boolean selfTest(int keysize) {
    if (RDEBUG) trace(IN, "selfTest(" + keysize + ')');
    boolean ok;
    try {
      byte[] kb = new byte[keysize];
      byte[] pt = new byte[BLOCK_SIZE];
      int i;

      for (i = 0; i < keysize; i++) kb[i] = (byte) i;
      for (i = 0; i < BLOCK_SIZE; i++) pt[i] = (byte) i;

      if (RDEBUG && LOG.isDebugEnabled()) {
        LOG.debug("selftest.banner=begin");
        LOG.debug("selftest.section=header.start");
        LOG.debug("selftest.keysize.bits={}", 8 * keysize);
        LOG.debug("selftest.key.material={}", toString(kb));
        LOG.debug("selftest.section=header.end");
      }
      ok = encryptDecryptAndCompare(kb, pt);
      if (!ok) throw new IllegalStateException("Symmetric operation failed");
    } catch (Exception x) {
      // Always log unexpected runtime exceptions at the error level.
      LOG.error("Self-test failed for keysize {}", keysize, x);
      ok = false;
    }
    if (RDEBUG) debug("Self-test OK? " + ok);
    if (RDEBUG) trace(OUT, "selfTest()");
    return ok;
  }

  private static boolean encryptDecryptAndCompare(byte[] kb, byte[] pt) throws InvalidKeyException {
    Object key = makeKey(kb, BLOCK_SIZE);
    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("Intermediate Ciphertext Values (Encryption)");
      LOG.debug("selftest.section=encrypt.intermediate.start");
      LOG.debug("event=selftest.intermediate.pt block=128 pt={}", toString(pt));
    }
    byte[] ct = new byte[BLOCK_SIZE];
    blockEncrypt(pt, ct, 0, key, BLOCK_SIZE);
    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("Intermediate Plaintext Values (Decryption)");
      LOG.debug("selftest.section=decrypt.intermediate.start");
      LOG.debug("event=selftest.intermediate.ct block=128 ct={}", toString(ct));
    }
    byte[] cpt = new byte[BLOCK_SIZE];
    blockDecrypt(ct, cpt, 0, key, BLOCK_SIZE);
    return areEqual(pt, cpt);
  }

  /**
   * Compute the number of rounds for a given key size and block size.
   *
   * @param keySize Key size in bytes (16, 24, or 32).
   * @param blockSize Block size in bytes (16, 24, or 32).
   * @return The number of rounds dictated by the Rijndael specification.
   */
  private static int getRounds(int keySize, int blockSize) {
    return switch (keySize) {
      case 16 -> {
        int rounds;
        switch (blockSize) {
          case 16 -> rounds = 10;
          case 24 -> rounds = 12;
          default -> rounds = 14;
        }
        yield rounds;
      }
      case 24 -> blockSize != 32 ? 12 : 14;
      default -> 14;
    };
  }

  private static void finalRoundEncryptGeneric(
      int[][] ke, int rounds, int bc, int[] s, int[] t, byte[] result) {
    int j = 0;
    for (int i = 0; i < bc; i++) {
      int tt = ke[rounds][i];
      result[j++] = (byte) (S[t[i] >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
      result[j++] = (byte) (S[t[(i + s[0]) % bc] >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
      result[j++] = (byte) (S[t[(i + s[1]) % bc] >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
      result[j++] = (byte) (S[t[(i + s[2]) % bc] & 0xFF] ^ tt & 0xFF);
    }
  }

  private static void finalRoundDecryptGeneric(
      int[][] kd, int rounds, int bc, int[] s, int[] t, byte[] result) {
    int j = 0;
    for (int i = 0; i < bc; i++) {
      int tt = kd[rounds][i];
      result[j++] = (byte) (Si[t[i] >>> 24 & 0xFF] ^ tt >>> 24 & 0xFF);
      result[j++] = (byte) (Si[t[(i + s[0]) % bc] >>> 16 & 0xFF] ^ tt >>> 16 & 0xFF);
      result[j++] = (byte) (Si[t[(i + s[1]) % bc] >>> 8 & 0xFF] ^ tt >>> 8 & 0xFF);
      result[j++] = (byte) (Si[t[(i + s[2]) % bc] & 0xFF] ^ tt & 0xFF);
    }
  }

  //	Utility static methods (from cryptix.util.core ArrayUtil and Hex classes)
  //	...........................................................................

  /**
   * Compares two byte arrays for equality.
   *
   * @return true if the arrays have identical contents
   */
  private static boolean areEqual(byte[] a, byte[] b) {
    int aLength = a.length;
    if (aLength != b.length) return false;
    for (int i = 0; i < aLength; i++) if (a[i] != b[i]) return false;
    return true;
  }

  /**
   * Returns a string of 2 hexadecimal digits (the most significant digit first) corresponding to
   * the lowest 8 bits of <i>n</i>.
   */
  private static String byteToString(int n) {
    char[] buf = {HEX_DIGITS[n >>> 4 & 0x0F], HEX_DIGITS[n & 0x0F]};
    return new String(buf);
  }

  /**
   * Returns a string of 8 hexadecimal digits (the most significant digit first) corresponding to
   * the integer <i>n</i>, which is treated as unsigned.
   */
  private static String intToString(int n) {
    char[] buf = new char[8];
    for (int i = 7; i >= 0; i--) {
      buf[i] = HEX_DIGITS[n & 0x0F];
      n >>>= 4;
    }
    return new String(buf);
  }

  /**
   * Returns a string of hexadecimal digits from a byte array. Each byte is converted to 2 hex
   * symbols.
   */
  private static String toString(byte[] ba) {
    int length = ba.length;
    char[] buf = new char[length * 2];
    int j = 0;
    for (int k : ba) {
      buf[j++] = HEX_DIGITS[k >>> 4 & 0x0F];
      buf[j++] = HEX_DIGITS[k & 0x0F];
    }
    return new String(buf);
  }

  /**
   * Returns a string of hexadecimal digits from an integer array. Each int is converted to 4 hex
   * symbols.
   */
  private static String toString(int[] ia) {
    int length = ia.length;
    char[] buf = new char[length * 8];
    int j = 0;
    for (int k : ia) {
      buf[j++] = HEX_DIGITS[k >>> 28 & 0x0F];
      buf[j++] = HEX_DIGITS[k >>> 24 & 0x0F];
      buf[j++] = HEX_DIGITS[k >>> 20 & 0x0F];
      buf[j++] = HEX_DIGITS[k >>> 16 & 0x0F];
      buf[j++] = HEX_DIGITS[k >>> 12 & 0x0F];
      buf[j++] = HEX_DIGITS[k >>> 8 & 0x0F];
      buf[j++] = HEX_DIGITS[k >>> 4 & 0x0F];
      buf[j++] = HEX_DIGITS[k & 0x0F];
    }
    return new String(buf);
  }

  //	main(): generate Intermediate Values KAT / quick self‑test hooks
  //	...........................................................................

  /**
   * Entry point for ad‑hoc testing.
   *
   * <p>Runs internal self‑tests for 128‑, 192‑, and 256‑bit keys using the default 128‑bit block
   * size. Intended for developers; production code does not invoke this method.
   */
  static void main() {
    selfTest(16);
    selfTest(24);
    selfTest(32);
  }
}
