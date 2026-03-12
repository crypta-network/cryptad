package org.spaceroots.mantissa.geometry;

import java.util.Arrays;

/**
 * Immutable parameter object for linear combinations of vectors.
 *
 * <p>The combination stores parallel arrays of scale factors and vectors. Instances are immutable
 * and intended to reduce long parameter lists in vector constructors.
 */
public final class LinearCombination {

  private final double[] factors;
  private final Vector3D[] vectors;

  private LinearCombination(double[] factors, Vector3D[] vectors) {
    this.factors = factors;
    this.vectors = vectors;
  }

  public static LinearCombination of(Term... terms) {
    double[] factors = new double[terms.length];
    Vector3D[] vectors = new Vector3D[terms.length];
    for (int i = 0; i < terms.length; i++) {
      factors[i] = terms[i].factor;
      vectors[i] = terms[i].vector;
    }
    return new LinearCombination(factors, vectors);
  }

  public static Term term(double factor, Vector3D vector) {
    return new Term(factor, vector);
  }

  public int size() {
    return factors.length;
  }

  public double factorAt(int index) {
    return factors[index];
  }

  public Vector3D vectorAt(int index) {
    return vectors[index];
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof LinearCombination other)) {
      return false;
    }
    return Arrays.equals(factors, other.factors) && Arrays.equals(vectors, other.vectors);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(factors);
    result = 31 * result + Arrays.hashCode(vectors);
    return result;
  }

  public static final class Term {

    private final double factor;
    private final Vector3D vector;

    private Term(double factor, Vector3D vector) {
      this.factor = factor;
      this.vector = vector;
    }
  }
}
