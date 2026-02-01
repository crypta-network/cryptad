package com.onionnetworks.fec;

import org.jetbrains.annotations.NotNull;

/** Parameter carrier for finite-field matrix multiplication slices. */
public final class MatrixMulParams {
  private final char[] a;
  private final int aStart;
  private final char[] b;
  private final int bStart;
  private final char[] c;
  private final int cStart;
  private final int n;
  private final int k;
  private final int m;

  /**
   * Creates a parameter bundle for matrix multiplication slices.
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
  public MatrixMulParams(
      char[] a, int aStart, char[] b, int bStart, char[] c, int cStart, int n, int k, int m) {
    this.a = a;
    this.aStart = aStart;
    this.b = b;
    this.bStart = bStart;
    this.c = c;
    this.cStart = cStart;
    this.n = n;
    this.k = k;
    this.m = m;
  }

  public char[] a() {
    return a;
  }

  public int aStart() {
    return aStart;
  }

  public char[] b() {
    return b;
  }

  public int bStart() {
    return bStart;
  }

  public char[] c() {
    return c;
  }

  public int cStart() {
    return cStart;
  }

  public int n() {
    return n;
  }

  public int k() {
    return k;
  }

  public int m() {
    return m;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof MatrixMulParams other)) {
      return false;
    }
    return java.util.Arrays.equals(a, other.a)
        && aStart == other.aStart
        && java.util.Arrays.equals(b, other.b)
        && bStart == other.bStart
        && java.util.Arrays.equals(c, other.c)
        && cStart == other.cStart
        && n == other.n
        && k == other.k
        && m == other.m;
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
