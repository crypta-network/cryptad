package network.crypta.crypt.ciphers;

import java.security.InvalidKeyException;
import java.util.Arrays;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// ...........................................................................
/**
 * Rijndael --pronounced Reindaal-- is a variable block-size (128-, 192- and 256-bit), variable
 * key-size (128-, 192- and 256-bit) symmetric cipher.
 *
 * <p>Rijndael was written by <a href="mailto:rijmen@esat.kuleuven.ac.be">Vincent Rijmen</a> and <a
 * href="mailto:Joan.Daemen@village.uunet.be">Joan Daemen</a>.
 *
 * <p>Portions of this code are <b>Copyright</b> &copy; 1997, 1998 <a
 * href="http://www.systemics.com/">Systemics Ltd</a> on behalf of the <a
 * href="http://www.systemics.com/docs/cryptix/">Cryptix Development Team</a>. <br>
 * All rights reserved.
 *
 * <p>
 *
 * @author Raif S. Naffah
 * @author Paulo S. L. M. Barreto
 *     <p>License is apparently available from http://www.cryptix.org/docs/license.html
 */
public final class RijndaelAlgorithm // implicit no-argument constructor
 {
  private static final Logger LOG = LoggerFactory.getLogger(RijndaelAlgorithm.class);

  //	Debugging methods and variables
  //	...........................................................................

  // removed unused empty static initializer

  // Legacy debug flags replaced by SLF4J level checks

  static final String ALGORITHM = "Rijndael";
  static final double VERSION = 0.1;
  static final String FULL_NAME = ALGORITHM + " ver. " + VERSION;

  private static final String NAME = "Rijndael_Algorithm";
  private static final boolean IN = true;
  private static final boolean OUT = false;

  /** Must be enabled to see most (all?) of the logging */
  private static final boolean RDEBUG = false;

  /** Enable to see input and output of the API functions */
  private static final boolean TRACE = false;

  private static final String TRACE_BLOCK_ENCRYPT = "blockEncrypt()";
  private static final String TRACE_BLOCK_DECRYPT = "blockDecrypt()";
  private static final String TRACE_BLOCK_DECRYPT_OPEN = "blockDecrypt(";
  private static final String LOG_FMT_CT_WITH_ROUND = "CT{}={}";
  private static final String LOG_FMT_CT = "CT={}";
  private static final String LOG_FMT_PT_WITH_ROUND = "PT{}={}";
  private static final String LOG_FMT_PT = "PT={}";

  private static void debug(String s) {
    if (LOG.isTraceEnabled()) LOG.trace(">>> " + NAME + ": {}", s);
  }

  private static void trace(boolean in, String s) {
    if (TRACE && LOG.isTraceEnabled()) LOG.trace("{}" + NAME + ".{}", in ? "==> " : "<== ", s);
  }

  //	Constants and variables
  //	...........................................................................

  private static final int BLOCK_SIZE = 16; // default block size in bytes

  private static final int[] alog = new int[256];
  // Renamed to avoid confusion with logger name LOG
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

  //	Static code - to intialise S-boxes and T-boxes
  //	...........................................................................

  static {
    long time = System.currentTimeMillis();

    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("Algorithm Name: {}", FULL_NAME);
      LOG.debug("Electronic Codebook (ECB) Mode");
      LOG.debug("");
    }
    int root = 0x11B;
    int i;
    int j;

    //
    // produce log and alog tables, needed for multiplying in the
    // field GF(2^m) (generator = 3)
    //
    generateLogAndAlogTables(root);
    generateSBoxes();

    //
    // T-boxes
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
    // round constants
    //
    rcon[0] = 1;
    int r = 1;
    for (int t = 1; t < 30; t++) {
      r = mul(2, r);
      rcon[t] = (byte) r;
    }

    time = System.currentTimeMillis() - time;

    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("==========");
      LOG.debug("");
      LOG.debug("Static Data");
      LOG.debug("");
      LOG.debug("S[]:");
      for (i = 0; i < 16; i++) {
        StringBuilder sb = new StringBuilder();
        for (j = 0; j < 16; j++) sb.append("0x").append(byteToString(S[i * 16 + j])).append(", ");
        LOG.debug(sb.toString());
      }
      LOG.debug("");
      LOG.debug("Si[]:");
      for (i = 0; i < 16; i++) {
        StringBuilder sb2 = new StringBuilder();
        for (j = 0; j < 16; j++) sb2.append("0x").append(byteToString(Si[i * 16 + j])).append(", ");
        LOG.debug(sb2.toString());
      }

      LOG.debug("");
      LOG.debug("iG[]:");
      for (i = 0; i < 4; i++) {
        StringBuilder sb3 = new StringBuilder();
        for (j = 0; j < 4; j++) sb3.append("0x").append(byteToString(iG[i][j])).append(", ");
        LOG.debug(sb3.toString());
      }

      LOG.debug("");
      LOG.debug("T1[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT1 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT1.append("0x").append(intToString(T1[i * 4 + j])).append(", ");
        LOG.debug(sbT1.toString());
      }
      LOG.debug("");
      LOG.debug("T2[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT2 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT2.append("0x").append(intToString(T2[i * 4 + j])).append(", ");
        LOG.debug(sbT2.toString());
      }
      LOG.debug("");
      LOG.debug("T3[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT3 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT3.append("0x").append(intToString(T3[i * 4 + j])).append(", ");
        LOG.debug(sbT3.toString());
      }
      LOG.debug("");
      LOG.debug("T4[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT4 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT4.append("0x").append(intToString(T4[i * 4 + j])).append(", ");
        LOG.debug(sbT4.toString());
      }
      LOG.debug("");
      LOG.debug("T5[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT5 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT5.append("0x").append(intToString(T5[i * 4 + j])).append(", ");
        LOG.debug(sbT5.toString());
      }
      LOG.debug("");
      LOG.debug("T6[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT6 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT6.append("0x").append(intToString(T6[i * 4 + j])).append(", ");
        LOG.debug(sbT6.toString());
      }
      LOG.debug("");
      LOG.debug("T7[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT7 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT7.append("0x").append(intToString(T7[i * 4 + j])).append(", ");
        LOG.debug(sbT7.toString());
      }
      LOG.debug("");
      LOG.debug("T8[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbT8 = new StringBuilder();
        for (j = 0; j < 4; j++) sbT8.append("0x").append(intToString(T8[i * 4 + j])).append(", ");
        LOG.debug(sbT8.toString());
      }

      LOG.debug("");
      LOG.debug("U1[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbU1 = new StringBuilder();
        for (j = 0; j < 4; j++) sbU1.append("0x").append(intToString(U1[i * 4 + j])).append(", ");
        LOG.debug(sbU1.toString());
      }
      LOG.debug("");
      LOG.debug("U2[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbU2 = new StringBuilder();
        for (j = 0; j < 4; j++) sbU2.append("0x").append(intToString(U2[i * 4 + j])).append(", ");
        LOG.debug(sbU2.toString());
      }
      LOG.debug("");
      LOG.debug("U3[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbU3 = new StringBuilder();
        for (j = 0; j < 4; j++) sbU3.append("0x").append(intToString(U3[i * 4 + j])).append(", ");
        LOG.debug(sbU3.toString());
      }
      LOG.debug("");
      LOG.debug("U4[]:");
      for (i = 0; i < 64; i++) {
        StringBuilder sbU4 = new StringBuilder();
        for (j = 0; j < 4; j++) sbU4.append("0x").append(intToString(U4[i * 4 + j])).append(", ");
        LOG.debug(sbU4.toString());
      }

      LOG.debug("");
      LOG.debug("rcon[]:");
      for (i = 0; i < 5; i++) {
        StringBuilder sbR = new StringBuilder();
        for (j = 0; j < 6; j++) sbR.append("0x").append(byteToString(rcon[i * 6 + j])).append(", ");
        LOG.debug(sbR.toString());
      }

      LOG.debug("");
      LOG.debug("Total initialization time: {} ms.", time);
      LOG.debug("");
    }
  }

  private static void generateLogAndAlogTables(int root) {
    alog[0] = 1;
    for (int i = 1; i < 256; i++) {
      int j = alog[i - 1] << 1 ^ alog[i - 1];
      if ((j & 0x100) != 0) j ^= root;
      alog[i] = j;
    }
    for (int i = 1; i < 255; i++) LOG_TABLE[alog[i]] = i;
  }

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
    // substitution box based on F^{-1}(x)
    //
    byte[][] box = new byte[256][8];
    box[1][7] = 1;
    for (int i = 2; i < 256; i++) {
      int j = alog[255 - LOG_TABLE[i]];
      for (int t = 0; t < 8; t++) box[i][t] = (byte) (j >>> 7 - t & 0x01);
    }
    //
    // affine transform:  box[i] <- bVector + aMatrix*box[i]
    //
    byte[][] cox = new byte[256][8];
    for (int i = 0; i < 256; i++)
      for (int t = 0; t < 8; t++) {
        cox[i][t] = bVector[t];
        for (int j = 0; j < 8; j++) {
          // Avoid lossy implicit narrowing in compound assignment; operate in int then narrow once.
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
        // Avoid lossy implicit narrowing; compute as int and cast once.
        S[i] = (byte) ((S[i] & 0xFF ^ (cox[i][t] & 0xFF) << 7 - t & 0xFF) & 0xFF);
      }
      Si[S[i] & 0xFF] = (byte) i;
    }
  }

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

  private static void eliminateColumn(byte[][] aa, int i) {
    for (int t = 0; t < 4; t++) {
      if (i != t) {
        for (int j = i + 1; j < 8; j++) {
          // Avoid lossy implicit narrowing; narrow the XOR result explicitly to byte.
          aa[t][j] =
              (byte) ((aa[t][j] & 0xFF ^ mul(aa[i][j] & 0xFF, aa[t][i] & 0xFF) & 0xFF) & 0xFF);
        }
        aa[t][i] = 0;
      }
    }
  }

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

  // multiply two elements of GF(2^m)
  private static int mul(int a, int b) {
    return a != 0 && b != 0 ? alog[(LOG_TABLE[a & 0xFF] + LOG_TABLE[b & 0xFF]) % 255] : 0;
  }

  // convenience method used in generating Transposition boxes
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
   * Convenience method to encrypt exactly one block of plaintext, assuming Rijndael's default block
   * size (128-bit).
   *
   * @param in The plaintext.
   * @param result The buffer into which to write the resulting ciphertext.
   * @param inOffset Index of in from which to start considering data.
   * @param sessionKey The session key to use for encryption.
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
            LOG_FMT_CT_WITH_ROUND,
            r,
            intToString(t0) + intToString(t1) + intToString(t2) + intToString(t3));
      }
    }

    // last round is special
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
      LOG.debug(LOG_FMT_CT, toString(result));
      LOG.debug("");
    }
    if (RDEBUG) trace(OUT, TRACE_BLOCK_ENCRYPT);
  }

  /**
   * Convenience method to encrypt exactly one block of plaintext, assuming Rijndael's non-standard
   * block size 256 bit).
   *
   * @param in The plaintext.
   * @param result The buffer into which to write the resulting ciphertext.
   * @param inOffset Index of in from which to start considering data.
   * @param sessionKey The session key to use for encryption.
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
            LOG_FMT_CT_WITH_ROUND,
            r,
            intToString(t0) + intToString(t1) + intToString(t2) + intToString(t3));
      }
    }

    // last round is special
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
      LOG.debug(LOG_FMT_CT, toString(result));
      LOG.debug("");
    }
    if (RDEBUG) trace(OUT, TRACE_BLOCK_ENCRYPT);
  }

  /**
   * Convenience method to decrypt exactly one block of plaintext, assuming Rijndael's default block
   * size (128-bit).
   *
   * @param in The ciphertext.
   * @param result the resulting ciphertext
   * @param inOffset Index of in from which to start considering data.
   * @param sessionKey The session key to use for decryption.
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
            LOG_FMT_PT_WITH_ROUND,
            r,
            intToString(t0) + intToString(t1) + intToString(t2) + intToString(t3));
      }
    }

    // last round is special
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
      LOG.debug(LOG_FMT_PT, toString(result));
      LOG.debug("");
    }
    if (RDEBUG) trace(OUT, TRACE_BLOCK_DECRYPT);
  }

  /**
   * Convenience method to decrypt exactly one block of plaintext, assuming Rijndael's non-standard
   * block size 256 bit.
   *
   * @param in The ciphertext.
   * @param result the resulting ciphertext
   * @param inOffset Index of in from which to start considering data.
   * @param sessionKey The session key to use for decryption.
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
            "PT{}={}{}{}{}", r, intToString(t0), intToString(t1), intToString(t2), intToString(t3));
      }
    }

    // last round is special
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
      LOG.debug(LOG_FMT_PT, toString(result));
      LOG.debug("");
    }
    if (RDEBUG) trace(OUT, TRACE_BLOCK_DECRYPT);
  }

  /** A basic symmetric encryption/decryption test. */
  static boolean selfTest() {
    return selfTest(BLOCK_SIZE);
  }

  //	Rijndael own methods
  //	...........................................................................

  /**
   * @return The default length in bytes of the Algorithm input block.
   */
  static int blockSize() {
    return BLOCK_SIZE;
  }

  /**
   * Expand a user-supplied key material into a session key.
   *
   * @param k The 128/192/256-bit user-key to use.
   * @param blockSize The block size in bytes of this Rijndael.
   * @exception InvalidKeyException If the key is invalid.
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
    // evolve key schedule and continue copying until filled
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
   * Encrypt exactly one block of plaintext.
   *
   * @param in The plaintext.
   * @param result The buffer into which to write the resulting ciphertext.
   * @param inOffset Index of in from which to start considering data.
   * @param sessionKey The session key to use for encryption.
   * @param blockSize The block size in bytes of this Rijndael.
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
      if (RDEBUG && LOG.isDebugEnabled()) LOG.debug(LOG_FMT_CT_WITH_ROUND, r, toString(t));
    }
    finalRoundEncryptGeneric(ke, rounds, bc, sEnc, t, result);
    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug(LOG_FMT_CT, toString(result));
      LOG.debug("");
    }
    if (RDEBUG) trace(OUT, TRACE_BLOCK_ENCRYPT);
  }

  /**
   * Decrypt exactly one block of ciphertext.
   *
   * @param in The ciphertext.
   * @param result The resulting ciphertext.
   * @param inOffset Index of in from which to start considering data.
   * @param sessionKey The session key to use for decryption.
   * @param blockSize The block size in bytes of this Rijndael.
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
      if (RDEBUG && LOG.isDebugEnabled()) LOG.debug(LOG_FMT_PT_WITH_ROUND, r, toString(t));
    }
    finalRoundDecryptGeneric(kd, rounds, bc, sDec, t, result);
    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug(LOG_FMT_PT, toString(result));
      LOG.debug("");
    }
    if (RDEBUG) trace(OUT, TRACE_BLOCK_DECRYPT);
  }

  /** A basic symmetric encryption/decryption test for a given key size. */
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
        LOG.debug("==========");
        LOG.debug("");
        LOG.debug("KEYSIZE={}", 8 * keysize);
        LOG.debug("KEY={}", toString(kb));
        LOG.debug("");
      }
      ok = encryptDecryptAndCompare(kb, pt);
      if (!ok) throw new IllegalStateException("Symmetric operation failed");
    } catch (Exception x) {
      // Do not ignore unexpected runtime exceptions; always log at error level.
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
      LOG.debug("");
      LOG.debug(LOG_FMT_PT, toString(pt));
    }
    byte[] ct = new byte[BLOCK_SIZE];
    blockEncrypt(pt, ct, 0, key, BLOCK_SIZE);
    if (RDEBUG && LOG.isDebugEnabled()) {
      LOG.debug("Intermediate Plaintext Values (Decryption)");
      LOG.debug("");
      LOG.debug(LOG_FMT_CT, toString(ct));
    }
    byte[] cpt = new byte[BLOCK_SIZE];
    blockDecrypt(ct, cpt, 0, key, BLOCK_SIZE);
    return areEqual(pt, cpt);
  }

  /**
   * Return The number of rounds for a given Rijndael's key and block sizes.
   *
   * @param keySize The size of the user key material in bytes.
   * @param blockSize The desired block size in bytes.
   * @return The number of rounds for a given Rijndael's key and block sizes.
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

  //	utility static methods (from cryptix.util.core ArrayUtil and Hex classes)
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
   * Returns a string of 2 hexadecimal digits (most significant digit first) corresponding to the
   * lowest 8 bits of <i>n</i>.
   */
  private static String byteToString(int n) {
    char[] buf = {HEX_DIGITS[n >>> 4 & 0x0F], HEX_DIGITS[n & 0x0F]};
    return new String(buf);
  }

  /**
   * Returns a string of 8 hexadecimal digits (most significant digit first) corresponding to the
   * integer <i>n</i>, which is treated as unsigned.
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

  //	main(): use to generate the Intermediate Values KAT
  //	...........................................................................

  public static void main(String[] args) {
    selfTest(16);
    selfTest(24);
    selfTest(32);
  }
}
