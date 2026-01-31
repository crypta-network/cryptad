package com.onionnetworks.fec;

import org.jetbrains.annotations.NotNull;

/**
 * Parameter carrier for finite-field matrix multiplication slices.
 *
 * @param a backing array for the left matrix
 * @param aStart offset into {@code a} where the {@code n x k} block starts
 * @param b backing array for the right matrix
 * @param bStart offset into {@code b} where the {@code k x m} block starts
 * @param c destination array for the {@code n x m} product
 * @param cStart offset into {@code c} where results are written
 * @param n number of rows in the left matrix and output
 * @param k shared inner dimension of the matrices
 * @param m number of columns in the right matrix and output
 */
@SuppressWarnings("ArrayRecordComponent")
public record MatrixMulParams(
    char[] a, int aStart, char[] b, int bStart, char[] c, int cStart, int n, int k, int m) {

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj
        instanceof
        MatrixMulParams(
            char[] otherA,
            int otherAStart,
            char[] otherB,
            int otherBStart,
            char[] otherC,
            int otherCStart,
            int otherN,
            int otherK,
            int otherM))) {
      return false;
    }
    return java.util.Arrays.equals(a, otherA)
        && aStart == otherAStart
        && java.util.Arrays.equals(b, otherB)
        && bStart == otherBStart
        && java.util.Arrays.equals(c, otherC)
        && cStart == otherCStart
        && n == otherN
        && k == otherK
        && m == otherM;
  }

  @Override
  public int hashCode() {
    int result = java.util.Arrays.hashCode(a);
    result = 31 * result + Integer.hashCode(aStart);
    result = 31 * result + java.util.Arrays.hashCode(b);
    result = 31 * result + Integer.hashCode(bStart);
    result = 31 * result + java.util.Arrays.hashCode(c);
    result = 31 * result + Integer.hashCode(cStart);
    result = 31 * result + Integer.hashCode(n);
    result = 31 * result + Integer.hashCode(k);
    result = 31 * result + Integer.hashCode(m);
    return result;
  }

  @Override
  public @NotNull String toString() {
    return "MatrixMulParams{"
        + "a="
        + java.util.Arrays.toString(a)
        + ", aStart="
        + aStart
        + ", b="
        + java.util.Arrays.toString(b)
        + ", bStart="
        + bStart
        + ", c="
        + java.util.Arrays.toString(c)
        + ", cStart="
        + cStart
        + ", n="
        + n
        + ", k="
        + k
        + ", m="
        + m
        + '}';
  }
}
