package com.onionnetworks.fec;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class FECMathTest {

  private static char gfMul(FECMath math, char a, char b) {
    if (a == 0 || b == 0) {
      return 0;
    }
    int sum = math.getGfLog()[a] + math.getGfLog()[b];
    return math.getGfExp()[sum % math.getGfSize()];
  }

  private static char[] multiplyMatrices(FECMath math, char[] a, char[] b, int n, int k, int m) {
    char[] result = new char[n * m];
    for (int row = 0; row < n; row++) {
      for (int col = 0; col < m; col++) {
        char acc = 0;
        for (int i = 0; i < k; i++) {
          acc ^= gfMul(math, a[row * k + i], b[i * m + col]);
        }
        result[row * m + col] = acc;
      }
    }
    return result;
  }

  @Test
  void constructor_whenGfBitsOutOfRange_expectException() {
    assertThrows(IllegalArgumentException.class, () -> new FECMath(1));
    assertThrows(IllegalArgumentException.class, () -> new FECMath(17));
  }

  @Test
  void modnn_whenWithinRange_returnsSameValue() {
    FECMath math = new FECMath(8);
    char result = math.modnn(42);
    assertEquals(42, result);
  }

  @Test
  void modnn_whenMultipleOfFieldSize_returnsZero() {
    FECMath math = new FECMath(8);
    char result = math.modnn(math.getGfSize() * 2);
    assertEquals(0, result);
  }

  @Test
  void mul_whenEitherOperandZero_returnsZero() {
    FECMath math = new FECMath(8);
    assertEquals(0, math.mul((char) 5, (char) 0));
    assertEquals(0, math.mul((char) 0, (char) 7));
  }

  @Test
  void mul_whenUsingMulTable_matchesLogComputation() {
    FECMath math = new FECMath(8);
    char expected = gfMul(math, (char) 7, (char) 9);
    char actual = math.mul((char) 7, (char) 9);
    assertEquals(expected, actual);
  }

  @Test
  void mul_whenGfBitsGreaterThanEight_usesLogarithmBranch() {
    FECMath math = new FECMath(9);
    char expected = gfMul(math, (char) 5, (char) 7);
    char actual = math.mul((char) 5, (char) 7);
    assertEquals(expected, actual);
    assertEquals(0, math.mul((char) 0, (char) 7));
  }

  @Test
  void addMulChar_whenCoefficientZero_doesNotMutateDestination() {
    FECMath math = new FECMath(8);
    char[] dst = new char[] {1, 2, 3};
    char[] snapshot = dst.clone();
    char[] src = new char[] {4, 5, 6};

    math.addMul(dst, 0, src, 0, (char) 0, dst.length);

    assertArrayEquals(snapshot, dst);
  }

  @Test
  void addMulChar_whenGfBitsAtMostEight_appliesXorScaledSource() {
    FECMath math = new FECMath(8);
    char[] dst = new char[] {1, 2, 3, 4};
    char[] src = new char[] {5, 6, 7, 8};
    char coefficient = 9;

    math.addMul(dst, 0, src, 0, coefficient, dst.length);

    char[] expected = new char[dst.length];
    for (int i = 0; i < dst.length; i++) {
      expected[i] = (char) (new char[] {1, 2, 3, 4}[i] ^ gfMul(math, coefficient, src[i]));
    }

    assertArrayEquals(expected, dst);
  }

  @Test
  void addMulChar_whenGfBitsGreaterThanEight_usesLogarithmPath() {
    FECMath math = new FECMath(9);
    char[] dst = new char[] {10, 11, 12};
    char[] src = new char[] {1, 2, 3};
    char coefficient = 4;

    math.addMul(dst, 0, src, 0, coefficient, dst.length);

    char[] expected = new char[] {10, 11, 12};
    for (int i = 0; i < dst.length; i++) {
      char product = gfMul(math, coefficient, src[i]);
      expected[i] = (char) (expected[i] ^ product);
    }

    assertArrayEquals(expected, dst);
  }

  @Test
  void addMulByte_whenCoefficientNonZero_updatesDestination() {
    FECMath math = new FECMath(8);
    byte[] dst = new byte[] {1, 2, 3, 4};
    byte[] src = new byte[] {5, 6, 7, 8};
    byte coefficient = 9;

    math.addMul(dst, 0, src, 0, coefficient, dst.length);

    byte[] expected = new byte[dst.length];
    for (int i = 0; i < dst.length; i++) {
      int product = gfMul(math, (char) (coefficient & 0xff), (char) (src[i] & 0xff));
      int updated = Byte.toUnsignedInt(new byte[] {1, 2, 3, 4}[i]) ^ product;
      expected[i] = (byte) updated;
    }

    assertArrayEquals(expected, dst);
  }

  @Test
  void matMul_whenLeftIsIdentity_returnsRightMatrix() {
    FECMath math = new FECMath(8);
    char[] identity = new char[] {1, 0, 0, 1};
    char[] matrix = new char[] {5, 6, 7, 8};
    char[] result = new char[4];

    math.matMul(identity, matrix, result, 2, 2, 2);

    assertArrayEquals(matrix, result);
  }

  @Test
  void isIdentity_whenMatrixMatchesPattern_returnsTrue() {
    char[] matrix = new char[] {1, 0, 0, 1};
    assertTrue(FECMath.isIdentity(matrix, 2));
  }

  @Test
  void isIdentity_whenMatrixDiffers_returnsFalse() {
    char[] matrix = new char[] {1, 1, 0, 1};
    assertFalse(FECMath.isIdentity(matrix, 2));
  }

  @Test
  void invertMatrix_whenMatrixInvertible_returnsIdentityWhenMultiplied() {
    FECMath math = new FECMath(8);
    char[] matrix = new char[] {1, 1, 1, 2};
    char[] original = matrix.clone();

    math.invertMatrix(matrix, 2);

    char[] product = multiplyMatrices(math, original, matrix, 2, 2, 2);
    assertTrue(FECMath.isIdentity(product, 2));
  }

  @Test
  void invertMatrix_whenMatrixSingular_throwsIllegalArgumentException() {
    FECMath math = new FECMath(8);
    char[] singular = new char[] {1, 0, 2, 0};
    assertThrows(IllegalArgumentException.class, () -> math.invertMatrix(singular, 2));
  }

  @Test
  void invertVandermonde_whenSingleRow_leavesMatrixUntouched() {
    FECMath math = new FECMath(8);
    char[] matrix = new char[] {1};

    math.invertVandermonde(matrix, 1);

    assertArrayEquals(new char[] {1}, matrix);
  }

  @Test
  void createEncodeMatrix_whenValid_returnsSystematicMatrix() {
    FECMath math = new FECMath(8);
    int k = 3;
    int n = 5;

    char[] encodeMatrix = math.createEncodeMatrix(k, n);

    char[] top = new char[k * k];
    System.arraycopy(encodeMatrix, 0, top, 0, k * k);
    assertTrue(FECMath.isIdentity(top, k));

    for (int row = k; row < n; row++) {
      boolean allZero = true;
      for (int col = 0; col < k; col++) {
        if (encodeMatrix[row * k + col] != 0) {
          allZero = false;
          break;
        }
      }
      assertFalse(allZero, "Parity row must not be all zeros");
    }
  }

  @Test
  void createEncodeMatrix_whenParametersInvalid_throwsIllegalArgumentException() {
    FECMath math = new FECMath(8);
    assertThrows(IllegalArgumentException.class, () -> math.createEncodeMatrix(6, 5));
    int sizeBeyondField = math.getGfSize() + 2;
    assertThrows(
        IllegalArgumentException.class,
        () -> math.createEncodeMatrix(sizeBeyondField, sizeBeyondField));
  }

  @Test
  void createDecodeMatrix_whenUsingParityRows_returnsInverseSubmatrix() {
    FECMath math = new FECMath(8);
    int k = 3;
    int n = 5;

    char[] encMatrix = math.createEncodeMatrix(k, n);
    int[] index = new int[] {2, 3, 4};

    char[] decodeMatrix = math.createDecodeMatrix(encMatrix, index, k, n);

    char[] chosen = new char[k * k];
    for (int i = 0; i < k; i++) {
      System.arraycopy(encMatrix, index[i] * k, chosen, i * k, k);
    }

    char[] product = multiplyMatrices(math, chosen, decodeMatrix, k, k, k);
    assertTrue(FECMath.isIdentity(product, k));
  }

  @Test
  void createGFMatrix_whenCalled_returnsZeroInitializedArray() {
    char[] matrix = FECMath.createGFMatrix(2, 3);
    assertEquals(6, matrix.length);
    for (char value : matrix) {
      assertEquals(0, value);
    }
  }
}
