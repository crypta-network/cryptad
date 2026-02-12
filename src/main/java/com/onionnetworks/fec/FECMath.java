package com.onionnetworks.fec;

import com.onionnetworks.util.Util;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Implements the finite-field arithmetic and matrix utilities used by the Vandermonde-based forward
 * error correction (FEC) codec. The logic is adapted from Luigi Rizzo's reference C implementation
 * and provides the field generation, multiplication helpers, and matrix routines needed to build
 * encoder and decoder transforms over GF(2^m).
 *
 * <p>The instance is configured for a specific field size via {@code gfBits} and lazily precomputes
 * exponent, logarithm, inverse, and multiplication tables during construction. After construction
 * the internal tables remain read-only; methods only mutate caller-provided buffers, so an instance
 * can be shared safely across threads provided destination arrays are not concurrently mutated. The
 * algorithms favor table lookups for {@code gfBits <= 8} and fall back to logarithmic identities
 * otherwise, trading memory for speed on small fields.
 *
 * <p>Typical usage flow:
 *
 * <ul>
 *   <li>Create an instance with the desired field width.
 *   <li>Call {@link #createEncodeMatrix(int, int)} to get a systematic generator matrix.
 *   <li>Use {@link #createDecodeMatrix(char[], int[], int, int)} with available symbol indexes to
 *       reconstruct a decoding matrix.
 *   <li>Apply {@link #addMul(char[], int, char[], int, char, int)} or the byte overload to combine
 *       symbols during encoding/decoding.
 * </ul>
 *
 * <p>Copyright (c) 2001 Onion Networks; copyright (c) 2000 OpenCola.
 *
 * @author Justin F. Chapweske (justin@chapweske.com)
 */
public final class FECMath {

  /**
   * The following parameter defines how many bits are used for field elements. This probably only
   * supports 8 and 16-bit codes at this time because Java lacks a typedef construct. This code
   * should perhaps be redone with some sort of template language/ precompiler for Java.
   */

  // code over GF(2**gfBits) - change to suit
  private static final Logger LOGGER = Logger.getLogger(FECMath.class.getName());

  private final int gfBits;

  /*
   * You should not need to change anything beyond this point.
   * The first part of the file implements linear algebra in GF.
   *
   * gf is the type used to store an element of the Galois Field.
   * Must contain at least gfBits bits.
   */
  // 2^n-1 = the number of elements in this extension field
  private final int gfSize; // powers of alpha

  /** Primitive polynomials - see Lin & Costello, Appendix A, and Lee & Messerschmitt, p. 453. */
  private static final String[] PRIM_POLYS = {
    // gfBits	polynomial
    null, //  0            no code
    null, //  1            no code
    "111", //  2            1+x+x^2
    "1101", //  3            1+x+x^3
    "11001", //  4            1+x+x^4
    "101001", //  5            1+x^2+x^5
    "1100001", //  6            1+x+x^6
    "10010001", //  7            1 + x^3 + x^7
    "101110001", //  8            1+x^2+x^3+x^4+x^8
    "1000100001", //  9            1+x^4+x^9
    "10010000001", // 10            1+x^3+x^10
    "101000000001", // 11            1+x^2+x^11
    "1100101000001", // 12            1+x+x^4+x^6+x^12
    "11011000000001", // 13            1+x+x^3+x^4+x^13
    "110000100010001", // 14            1+x+x^6+x^10+x^14
    "1100000000000001", // 15            1+x+x^15
    "11010000000010001" // 16            1+x+x^3+x^12+x^16
  };

  /**
   * To speed up computations, we have tables for logarithm, exponent and inverse of a number. If
   * gfBits <= 8, we use a table for multiplication as well (it takes 64K, no big deal even on a
   * PDA, especially because it can be pre-initialized a put into a ROM!), otherwise we use a table
   * of logarithms.
   */

  // index->poly form conversion table
  private final char[] gfExp;

  // Poly->index form conversion table
  private final int[] gfLog;
  // inverse of field elem.
  private final char[] inverse;

  // inv[\alpha**i]=\alpha**(gfSize-i-1)

  /**
   * gf_mul(x,y) multiplies two numbers. If gfBits<=8, it is much faster to use a multiplication
   * table.
   *
   * <p>USE_GF_MULC, GF_MULC0(c) and GF_ADDMULC(x) can be used when multiplying many numbers by the
   * same constant. In this case the first call sets the constant, and others perform the
   * multiplications. A value related to the multiplication is held in a local variable declared
   * with USE_GF_MULC. See usage in addMul1().
   */
  private char[][] gfMulTable;

  /**
   * Creates a {@code FECMath} instance configured for the default GF(2^8) field width. The
   * constructor populates the internal lookup tables immediately, so the resulting object is ready
   * for encoding or decoding operations without further initialization.
   */
  @SuppressWarnings("unused")
  public FECMath() {
    this(8);
  }

  /**
   * Builds a {@code FECMath} instance for the specified field size.
   *
   * @param gfBits number of exponent bits defining the field; must be between 2 and 16 inclusive
   * @throws IllegalArgumentException if {@code gfBits} falls outside the supported range or no
   *     primitive polynomial is defined
   */
  public FECMath(int gfBits) {
    this.gfBits = gfBits;
    this.gfSize = ((1 << gfBits) - 1);

    gfExp = new char[2 * gfSize];
    gfLog = new int[gfSize + 1];
    inverse = new char[gfSize + 1];

    if (gfBits < 2 || gfBits > 16) {
      throw new IllegalArgumentException("gfBits must be 2 .. 16");
    }
    generateGF();
    if (gfBits <= 8) {
      initMulTable();
    }
  }

  /**
   * Returns the number of bits that define this Galois field, e.g., {@code 8} for GF(256).
   *
   * @return the bit width used to derive field size and primitive polynomial
   */
  @SuppressWarnings("unused")
  public int getGfBits() {
    return gfBits;
  }

  /**
   * Reports the number of non-zero elements in the field, computed as {@code 2^gfBits - 1}.
   *
   * @return multiplicative order of the field, excluding zero
   */
  public int getGfSize() {
    return gfSize;
  }

  /**
   * Exposes the logarithm table where {@code gfLog[value]} yields the exponent of {@code value}
   * relative to the generator {@code alpha}. The array is owned by this instance; callers should
   * treat it as read-only.
   *
   * @return backing logarithm table for the configured field
   */
  public int[] getGfLog() {
    return gfLog;
  }

  /**
   * Exposes the exponentiation table where {@code gfExp[exponent]} returns the field element for
   * {@code alpha^exponent}. The table is extended to twice the field size to avoid modulus during
   * multiplication; callers must not modify it.
   *
   * @return exponentiation lookup table for this field
   */
  public char[] getGfExp() {
    return gfExp;
  }

  /**
   * Generates logarithm, exponent, and inverse lookup tables for the configured field. The routine
   * walks the primitive polynomial bits to list powers of the generator and derives inverse
   * elements for every non-zero value. It is invoked during construction and should not be called
   * concurrently with mutation of the same instance.
   *
   * @throws IllegalArgumentException if no primitive polynomial is available for {@code gfBits}
   */
  public final void generateGF() {
    int i;

    String primPoly = PRIM_POLYS[gfBits];
    if (primPoly == null) {
      throw new IllegalArgumentException("No primitive polynomial for gfBits=" + gfBits);
    }

    char mask = 1; // x ** 0 = 1
    gfExp[gfBits] = 0; // will be updated at the end of the 1st loop
    /*
     * first, generate the (polynomial representation of) powers of \alpha,
     * which are stored in gfExp[i] = \alpha ** i
     * At the same time, build gfLog[gfExp[i]] = i
     * The first gfBits powers are simply bits shifted to the left.
     */
    for (i = 0; i < gfBits; i++, mask = (char) (mask << 1)) {
      gfExp[i] = mask;
      gfLog[gfExp[i]] = i;
      /*
       * If primPoly[i] == 1 then \alpha ** i occurs in poly-repr
       * gfExp[gfBits] = \alpha ** gfBits
       */
      if (primPoly.charAt(i) == '1') {
        gfExp[gfBits] ^= mask;
      }
    }
    /*
     * now gfExp[gfBits] = \alpha ** gfBits is complete, so can als
     * compute its inverse.
     */
    gfLog[gfExp[gfBits]] = gfBits;
    /*
     * Poly-repr of \alpha ** (i+1) is given by poly-repr of
     * \alpha ** i shifted left one-bit and accounting for any
     * \alpha ** gfBits term that may occur when poly-repr of
     * \alpha ** i is shifted.
     */
    mask = (char) (1 << (gfBits - 1));
    for (i = gfBits + 1; i < gfSize; i++) {
      if (gfExp[i - 1] >= mask) {
        gfExp[i] = (char) (gfExp[gfBits] ^ ((gfExp[i - 1] ^ mask) << 1));
      } else {
        gfExp[i] = (char) (gfExp[i - 1] << 1);
      }
      gfLog[gfExp[i]] = i;
    }
    /*
     * log(0) is not defined, so use a special value
     */
    gfLog[0] = gfSize;
    // set the extended gfExp values for fast multiplying
    for (i = 0; i < gfSize; i++) {
      gfExp[i + gfSize] = gfExp[i];
    }

    /*
     * again special cases. 0 has no inverse. This used to
     * be initialized to gfSize, but it should make no difference
     * since noone is supposed to read from here.
     */
    inverse[0] = 0;
    inverse[1] = 1;
    for (i = 2; i <= gfSize; i++) {
      inverse[i] = gfExp[gfSize - gfLog[i]];
    }
  }

  /**
   * Precomputes a full multiplication table for fields up to {@code gfBits <= 8}. The table allows
   * constant-time products via array lookup, trading roughly 64 KiB of memory for predictable
   * speed. For larger fields this method is a no-op because logarithmic multiplication is faster
   * than materializing the expanded table.
   */
  public final void initMulTable() {
    if (gfBits <= 8) {
      gfMulTable = new char[gfSize + 1][gfSize + 1];

      int i;
      int j;
      for (i = 0; i < gfSize + 1; i++) {
        for (j = 0; j < gfSize + 1; j++) {
          gfMulTable[i][j] = gfExp[modnn(gfLog[i] + gfLog[j])];
        }
      }
      for (j = 0; j < gfSize + 1; j++) {
        gfMulTable[0][j] = gfMulTable[j][0] = 0;
      }
    }
  }

  /**
   * Computes {@code x mod gfSize} using a bit folding instead of division. This helper keeps loop
   * indices within the field order when accumulating exponents during multiplication.
   *
   * @param x value to be reduced; negative values are not supported and produce unspecified results
   * @return {@code x} reduced into the range {@code 0..gfSize-1}
   */
  public final char modnn(int x) {
    while (x >= gfSize) {
      x -= gfSize;
      x = (x >> gfBits) + (x & gfSize);
    }
    return (char) x;
  }

  /**
   * Multiplies two field elements. For {@code gfBits <= 8} the operation uses the precomputed
   * multiplication table; otherwise it computes the product through logarithm/exponent arithmetic
   * to avoid oversized tables.
   *
   * @param x first multiplicand encoded as an unsigned field element in a {@code char}
   * @param y second multiplicand encoded as an unsigned field element in a {@code char}
   * @return product {@code x * y} in the configured field, or {@code 0} if either operand is zero
   */
  public final char mul(char x, char y) {
    if (gfBits <= 8) {
      return gfMulTable[x][y];
    } else {
      if (x == 0 || y == 0) {
        return 0;
      }

      return gfExp[gfLog[x] + gfLog[y]];
    }
  }

  /**
   * Allocates a dense row-major matrix backed by a {@code char} array sized to {@code rows * cols}
   * for use with the finite-field linear algebra helpers.
   *
   * @param rows number of matrix rows; callers must provide a non-negative value
   * @param cols number of matrix columns; callers must provide a non-negative value
   * @return newly allocated array initialized to zeros
   */
  public static char[] createGFMatrix(int rows, int cols) {
    return new char[rows * cols];
  }

  /*
   * addMul() computes dst[] = dst[] + c * src[]
   * This is used often, so better optimize it! Currently, the loop is
   * unrolled 16 times, a good value for 486 and pentium-class machines.
   * The case c=0 is also optimized, whereas c=1 is not. These
   * calls are unfrequent in my typical apps, so I did not bother.
   *
   */
  /**
   * Performs the fused operation {@code dst[i] ^= c * src[i]} over {@code len} elements using field
   * multiplication and addition (XOR). The loop is unrolled for speed and leverages the
   * multiplication table when available.
   *
   * @param dst destination buffer updated in place; must have at least {@code dstPos + len}
   *     writable elements
   * @param dstPos starting offset in {@code dst} for the writeback
   * @param src source buffer supplying multiplicands; must have at least {@code srcPos + len}
   *     readable elements
   * @param srcPos starting offset in {@code src} used for multiplication
   * @param c scalar coefficient multiplied against every source element; zero short-circuits
   * @param len number of elements to process; negative values are not supported
   */
  public final void addMul(char[] dst, int dstPos, char[] src, int srcPos, char c, int len) {
    // nop, optimize
    if (c == 0) {
      return;
    }

    int unroll = 16; // unroll the loop 16 times.
    int i = dstPos;
    int j = srcPos;
    int lim = dstPos + len;

    if (gfBits <= 8) { // use our multiplication table.
      // Instead of doing gfMulTable[c,x] for multiplying, we'll save
      // the gfMulTable[c] to a local variable since it is going to
      // be used many times.
      char[] gfMulc = gfMulTable[c];

      // Not sure if loop unrolling has any real benefit in Java, but
      // what the hey.
      for (; i < lim && (lim - i) > unroll; i += unroll, j += unroll) {
        // dst ^= gf_mulc[x] is equal to mult then add (xor == add)

        dst[i] ^= gfMulc[src[j]];
        dst[i + 1] ^= gfMulc[src[j + 1]];
        dst[i + 2] ^= gfMulc[src[j + 2]];
        dst[i + 3] ^= gfMulc[src[j + 3]];
        dst[i + 4] ^= gfMulc[src[j + 4]];
        dst[i + 5] ^= gfMulc[src[j + 5]];
        dst[i + 6] ^= gfMulc[src[j + 6]];
        dst[i + 7] ^= gfMulc[src[j + 7]];
        dst[i + 8] ^= gfMulc[src[j + 8]];
        dst[i + 9] ^= gfMulc[src[j + 9]];
        dst[i + 10] ^= gfMulc[src[j + 10]];
        dst[i + 11] ^= gfMulc[src[j + 11]];
        dst[i + 12] ^= gfMulc[src[j + 12]];
        dst[i + 13] ^= gfMulc[src[j + 13]];
        dst[i + 14] ^= gfMulc[src[j + 14]];
        dst[i + 15] ^= gfMulc[src[j + 15]];
      }

      // final components
      for (; i < lim; i++, j++) {
        dst[i] ^= gfMulc[src[j]];
      }

    } else { // gfBits > 8, no multiplication table
      int mulcPos = gfLog[c];

      // unroll your own damn loop.
      int y;
      for (; i < lim; i++, j++) {
        if ((y = src[j]) != 0) {
          dst[i] ^= gfExp[mulcPos + gfLog[y]];
        }
      }
    }
  }

  /*
   * addMul() computes dst[] = dst[] + c * src[]
   * This is used often, so better optimize it! Currently, the loop is
   * unrolled 16 times, a good value for 486 and pentium-class machines.
   * The case c=0 is also optimized, whereas c=1 is not. These
   * calls are unfrequent in my typical apps, so I did not bother.
   *
   */
  /**
   * Byte-array variant of {@link #addMul(char[], int, char[], int, char, int)} that operates on
   * unsigned byte values encoded in two's complement. The multiplication constant and inputs are
   * widened to {@code char} during arithmetic and narrowed back on writing.
   *
   * @param dst destination byte buffer mutated in place; must accommodate {@code len} updates from
   *     {@code dstPos}
   * @param dstPos starting offset in the destination buffer
   * @param src source byte buffer whose elements are multiplied by {@code c}
   * @param srcPos starting offset in the source buffer
   * @param c scalar multiplier applied to every source element; {@code 0} exits early
   * @param len number of elements to process; negative values are not supported
   */
  public final void addMul(byte[] dst, int dstPos, byte[] src, int srcPos, byte c, int len) {
    // nop, optimize
    if (c == 0) {
      return;
    }

    int unroll = 16; // unroll the loop 16 times.
    int i = dstPos;
    int j = srcPos;
    int lim = dstPos + len;

    // use our multiplication table.
    // Instead of doing gfMulTable[c,x] for multiplying, we'll save
    // the gfMulTable[c] to a local variable since it is going to
    // be used many times.
    char[] gfMulc = gfMulTable[c & 0xff];

    // Not sure if loop unrolling has any real benefit in Java, but
    // what the hey.
    for (; i < lim && (lim - i) > unroll; i += unroll, j += unroll) {
      // dst ^= gf_mulc[x] is equal to mult then add (xor == add)

      dst[i] ^= (byte) gfMulc[src[j] & 0xff];
      dst[i + 1] ^= (byte) gfMulc[src[j + 1] & 0xff];
      dst[i + 2] ^= (byte) gfMulc[src[j + 2] & 0xff];
      dst[i + 3] ^= (byte) gfMulc[src[j + 3] & 0xff];
      dst[i + 4] ^= (byte) gfMulc[src[j + 4] & 0xff];
      dst[i + 5] ^= (byte) gfMulc[src[j + 5] & 0xff];
      dst[i + 6] ^= (byte) gfMulc[src[j + 6] & 0xff];
      dst[i + 7] ^= (byte) gfMulc[src[j + 7] & 0xff];
      dst[i + 8] ^= (byte) gfMulc[src[j + 8] & 0xff];
      dst[i + 9] ^= (byte) gfMulc[src[j + 9] & 0xff];
      dst[i + 10] ^= (byte) gfMulc[src[j + 10] & 0xff];
      dst[i + 11] ^= (byte) gfMulc[src[j + 11] & 0xff];
      dst[i + 12] ^= (byte) gfMulc[src[j + 12] & 0xff];
      dst[i + 13] ^= (byte) gfMulc[src[j + 13] & 0xff];
      dst[i + 14] ^= (byte) gfMulc[src[j + 14] & 0xff];
      dst[i + 15] ^= (byte) gfMulc[src[j + 15] & 0xff];
    }

    // final components
    for (; i < lim; i++, j++) {
      dst[i] ^= (byte) gfMulc[src[j] & 0xff];
    }
  }

  /*
   * computes C = AB where A is n*k, B is k*m, C is n*m
   */
  /**
   * Multiplies two matrices {@code A} and {@code B} over the current field, writing the result into
   * {@code C}. The inputs are interpreted as row-major arrays with dimensions {@code n x k} and
   * {@code k x m}; the output is {@code n x m}. No bounds checking is performed beyond array
   * accesses.
   *
   * @param a left matrix in row-major order containing {@code n * k} elements starting at index
   *     {@code 0}
   * @param b right matrix in row-major order containing {@code k * m} elements starting at index
   *     {@code 0}
   * @param c destination buffer sized for {@code n * m} elements; contents are overwritten
   * @param n number of rows in {@code a} and {@code c}
   * @param k shared dimension (columns of {@code a}, rows of {@code b})
   * @param m number of columns in {@code b} and {@code c}
   */
  public final void matMul(char[] a, char[] b, char[] c, int n, int k, int m) {
    matMul(
        new MatrixMulParams(
            new MatrixSlice(a, 0),
            new MatrixSlice(b, 0),
            new MatrixSlice(c, 0),
            new MatrixMulDimensions(n, k, m)));
  }

  /*
   * computes C = AB where A is n*k, B is k*m, C is n*m
   */
  /**
   * Matrix multiplication with explicit starting offsets for each operand. This overload supports
   * slicing into larger buffers without copying submatrices.
   *
   * @param params grouped matrix slice and dimension settings
   */
  public final void matMul(MatrixMulParams params) {
    char[] a = params.a();
    char[] b = params.b();
    char[] c = params.c();
    int aStart = params.aStart();
    int bStart = params.bStart();
    int cStart = params.cStart();
    int n = params.n();
    int k = params.k();
    int m = params.m();

    for (int row = 0; row < n; row++) {
      for (int col = 0; col < m; col++) {
        int posA = row * k;
        int posB = col;
        char acc = 0;
        for (int i = 0; i < k; i++, posA++, posB += m) {
          acc ^= mul(a[aStart + posA], b[bStart + posB]);
        }
        c[cStart + (row * m + col)] = acc;
      }
    }
  }

  /**
   * Tests whether a square matrix equals the identity matrix. Entries are read row-major from
   * {@code m}; the matrix is considered identity when all diagonal elements equal one and all
   * off-diagonal elements equal zero in the current field.
   *
   * @param m candidate matrix in row-major order containing {@code k * k} elements
   * @param k dimension of the square matrix to test
   * @return {@code true} when {@code m} represents an identity matrix, otherwise {@code false}
   */
  public static boolean isIdentity(char[] m, int k) {
    int pos = 0;
    for (int row = 0; row < k; row++) {
      for (int col = 0; col < k; col++) {
        if ((row == col && m[pos] != 1) || (row != col && m[pos] != 0)) {
          return false;
        } else {
          pos++;
        }
      }
    }
    return true;
  }

  /**
   * Inverts a square matrix in place using Gauss-Jordan elimination. Pivot selection tolerates
   * sparse matrices by searching for a usable element when the diagonal is zero. The source buffer
   * is replaced with its inverse on success.
   *
   * @param src row-major representation of the {@code k x k} matrix to invert; overwritten with the
   *     inverse
   * @param k dimension of the square matrix; must match the buffer length divided by {@code k}
   * @throws IllegalArgumentException if the matrix is singular or indices fall outside bounds
   */
  public final void invertMatrix(char[] src, int k) {

    int[] indxc = new int[k];
    int[] indxr = new int[k];

    // pivotMarks marks elements already used as pivots.
    int[] pivotMarks = new int[k];

    char[] identityRow = createGFMatrix(1, k);

    for (int col = 0; col < k; col++) {
      Pivot pivot = selectPivot(src, pivotMarks, k, col);

      int pivotRow = pivot.row;
      int pivotColumn = pivot.column;

      pivotMarks[pivotColumn] = pivotMarks[pivotColumn] + 1;
      swapRows(src, k, pivotRow, pivotColumn);
      indxr[col] = pivotRow;
      indxc[col] = pivotColumn;

      normalizePivotRow(src, k, pivotColumn, pivotColumn);

      identityRow[pivotColumn] = 1;
      if (!Util.arraysEqual(src, pivotColumn * k, identityRow, 0, k)) {
        eliminateColumn(src, k, pivotColumn, pivotColumn);
      }
      identityRow[pivotColumn] = 0;
    }

    restoreColumnOrder(src, k, indxr, indxc);
  }

  private void restoreColumnOrder(char[] matrix, int size, int[] indxr, int[] indxc) {
    for (int col = size - 1; col >= 0; col--) {
      int rowIndex = indxr[col];
      int colIndex = indxc[col];
      if (rowIndex < 0 || rowIndex >= size) {
        LOGGER.log(Level.SEVERE, "AARGH, indxr[col] {0}", rowIndex);
      } else if (colIndex < 0 || colIndex >= size) {
        LOGGER.log(Level.SEVERE, "AARGH, indxc[col] {0}", colIndex);
      } else if (rowIndex != colIndex) {
        for (int row = 0; row < size; row++) {
          char tmp = matrix[row * size + colIndex];
          matrix[row * size + colIndex] = matrix[row * size + rowIndex];
          matrix[row * size + rowIndex] = tmp;
        }
      }
    }
  }

  private void eliminateColumn(char[] matrix, int size, int pivotRow, int pivotColumn) {
    int pivotRowPos = pivotRow * size;
    for (int row = 0, offset = 0; row < size; row++, offset += size) {
      if (row == pivotRow) {
        continue;
      }
      char factor = matrix[offset + pivotColumn];
      if (factor != 0) {
        matrix[offset + pivotColumn] = 0;
        addMul(matrix, offset, matrix, pivotRowPos, factor, size);
      }
    }
  }

  private void normalizePivotRow(char[] matrix, int size, int pivotRow, int pivotColumn) {
    int pivotRowPos = pivotRow * size;
    char pivotValue = matrix[pivotRowPos + pivotColumn];
    if (pivotValue == 0) {
      throw new IllegalArgumentException("singular matrix 2");
    }
    if (pivotValue != 1) {
      /* otherwise this is a NOP */
      /*
       * this is often done, but optimizing is not so
       * fruitful, at least in the obvious ways (unrolling)
       */
      char scaledPivot = inverse[pivotValue];
      matrix[pivotRowPos + pivotColumn] = 1;
      for (int ix = 0; ix < size; ix++) {
        matrix[pivotRowPos + ix] = mul(scaledPivot, matrix[pivotRowPos + ix]);
      }
    }
  }

  private void swapRows(char[] matrix, int size, int firstRow, int secondRow) {
    if (firstRow == secondRow) {
      return;
    }
    for (int ix = 0; ix < size; ix++) {
      char tmp = matrix[firstRow * size + ix];
      matrix[firstRow * size + ix] = matrix[secondRow * size + ix];
      matrix[secondRow * size + ix] = tmp;
    }
  }

  private Pivot selectPivot(char[] matrix, int[] pivotMarks, int size, int targetColumn) {
    if (pivotMarks[targetColumn] != 1 && matrix[targetColumn * size + targetColumn] != 0) {
      return new Pivot(targetColumn, targetColumn);
    }
    for (int row = 0; row < size; row++) {
      if (pivotMarks[row] == 1) {
        continue;
      }
      for (int col = 0; col < size; col++) {
        if (pivotMarks[col] > 1) {
          throw new IllegalArgumentException("singular matrix");
        }
        if (pivotMarks[col] == 0 && matrix[row * size + col] != 0) {
          return new Pivot(row, col);
        }
      }
    }
    throw new IllegalArgumentException("pivot not found");
  }

  private record Pivot(int row, int column) {}

  /**
   * Inverts a Vandermonde matrix in place using a specialized algorithm adapted from “Numerical
   * Recipes in C” §2.8. The implementation assumes {@code src} already encodes a non-singular
   * Vandermonde matrix and operates primarily on the second column containing the base values
   * {@code p_i}.
   *
   * @param src row-major {@code k x k} Vandermonde matrix that is overwritten with its inverse
   * @param k dimension of the matrix; values outside the buffer size produce undefined behavior
   * @throws IllegalArgumentException if a pivot cannot be located or if the matrix is singular
   */
  public final void invertVandermonde(char[] src, int k) {

    if (k == 1) { // degenerate case, matrix must be p^0 = 1
      return;
    }

    /*
     * c holds the coefficient of P(x) = Prod (x - p_i), i=0..k-1
     * b holds the coefficient for the matrix inversion
     */
    char[] c = createGFMatrix(1, k);
    char[] b = createGFMatrix(1, k);
    char[] p = createGFMatrix(1, k);

    for (int j = 1, i = 0; i < k; i++, j += k) {
      c[i] = 0;
      p[i] = src[j]; /* p[i] */
    }
    /*
     * construct coefficients recursively. We know c[k] = 1 (implicit)
     * and start P_0 = x - p_0. At each stage multiply by x - p_i
     * to extend the polynomial; after k steps we are done.
     */
    c[k - 1] = p[0]; /* really -p(0), but x = -x in GF(2^m) */
    for (int i = 1; i < k; i++) {
      char pElement = p[i]; /* see the above comment */
      for (int j = k - 1 - (i - 1); j < k - 1; j++) {
        c[j] ^= mul(pElement, c[j + 1]);
      }
      c[k - 1] ^= pElement;
    }

    for (int row = 0; row < k; row++) {
      /*
       * synthetic division etc.
       */
      char xx = p[row];
      char t = 1;
      b[k - 1] = 1; /* this is in fact c[k] */
      for (int i = k - 2; i >= 0; i--) {
        b[i] = (char) (c[i + 1] ^ mul(xx, b[i + 1]));
        t = (char) (mul(xx, t) ^ b[i]);
      }
      for (int col = 0; col < k; col++) {
        src[col * k + row] = mul(inverse[t], b[col]);
      }
    }
  }

  /**
   * Builds a systematic Vandermonde encoding matrix suitable for Reed-Solomon style erasure coding.
   * The resulting {@code n x k} matrix contains an identity block on top and parity rows beneath,
   * enabling direct use with {@link #addMul(char[], int, char[], int, char, int)} during encoding.
   *
   * @param k number of data symbols; must be {@code <= n} and not exceed {@code gfSize + 1}
   * @param n total symbols (data and parity) to generate; must be {@code <= gfSize + 1}
   * @return newly allocated encoding matrix in row-major order
   * @throws IllegalArgumentException if the requested dimensions exceed the field capacity or
   *     {@code k > n}
   */
  public final char[] createEncodeMatrix(int k, int n) {
    if (k > gfSize + 1 || n > gfSize + 1 || k > n) {
      throw new IllegalArgumentException(
          "Invalid parameters n=" + n + ",k=" + k + ",gfSize=" + gfSize);
    }

    char[] encMatrix = createGFMatrix(n, k);

    /*
     * The encoding matrix is computed starting with a Vandermonde matrix
     * and then transforming it into a systematic matrix.
     *
     * fill the matrix with powers of field elements, starting from 0.
     * The first row is special, cannot be computed with exp. table.
     */
    char[] tmpMatrix = createGFMatrix(n, k);

    tmpMatrix[0] = 1;
    // the first row should be 0's, fill in the rest.
    for (int pos = k, row = 0; row < n - 1; row++, pos += k) {
      for (int col = 0; col < k; col++) {
        tmpMatrix[pos + col] = gfExp[modnn(row * col)];
      }
    }

    /*
     * quick code to build systematic matrix: invert the top
     * k*k vandermonde matrix, multiply right the bottom n-k rows
     * by the inverse, and construct the identity matrix at the top.
     */
    // much faster than invertMatrix
    invertVandermonde(tmpMatrix, k);
    matMul(
        new MatrixMulParams(
            new MatrixSlice(tmpMatrix, k * k),
            new MatrixSlice(tmpMatrix, 0),
            new MatrixSlice(encMatrix, k * k),
            new MatrixMulDimensions(n - k, k, k)));

    /*
     * the upper matrix is I so do not bother with a slow multiplying
     */
    Util.bzero(encMatrix, 0, k * k);
    for (int i = 0, col = 0; col < k; col++, i += k + 1) {
      encMatrix[i] = 1;
    }

    return encMatrix;
  }

  /**
   * Derives a decoding matrix from a generator matrix and the indexes of available symbols. The
   * selected rows are copied into a square buffer and inverted to produce the transform required to
   * recover missing data symbols.
   *
   * @param encMatrix systematic generator matrix produced by {@link #createEncodeMatrix(int, int)};
   *     treated as read-only
   * @param index indexes of the {@code k} symbols available for decoding; each must be in {@code
   *     [0, n)}
   * @param k number of data symbols to reconstruct; also the dimension of the returned square
   *     matrix
   * @param n total number of symbols the generator matrix was built for; used to validate indexes
   * @return newly allocated {@code k x k} decoding matrix in row-major order
   * @throws IllegalArgumentException if any index is out of bounds or the matrix cannot be inverted
   */
  protected final char[] createDecodeMatrix(char[] encMatrix, int[] index, int k, int n) {

    for (int idx : index) {
      if (idx < 0 || idx >= n) {
        throw new IllegalArgumentException("invalid index " + idx + " for n=" + n);
      }
    }

    char[] matrix = createGFMatrix(k, k);
    for (int i = 0, pos = 0; i < k; i++, pos += k) {
      System.arraycopy(encMatrix, index[i] * k, matrix, pos, k);
    }

    invertMatrix(matrix, k);

    return matrix;
  }
}
