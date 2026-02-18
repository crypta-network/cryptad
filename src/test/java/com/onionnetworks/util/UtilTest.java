package com.onionnetworks.util;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class UtilTest {

  @BeforeEach
  void resetRandomSeed() throws Exception {
    java.security.SecureRandom secureRandom = java.security.SecureRandom.getInstance("SHA1PRNG");
    Util.setRandForTesting(secureRandom);
    Util.getRand().setSeed(0L);
    Util.getRand().setSeed(1234L);
  }

  @Test
  void getBytes_whenRoundTripInt_returnsOriginal() {
    int value = 0x12345678;

    byte[] bytes = Util.getBytes(value);
    int result = Util.getInt(bytes);

    assertEquals(value, result);
  }

  @Test
  void bzero_whenLengthBelowCache_zeroesRequestedRange() {
    byte[] data = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    Util.bzero(data, 2, 4);

    assertArrayEquals(new byte[] {1, 2, 0, 0, 0, 0, 7, 8, 9, 10}, data);
  }

  @Test
  void bzero_whenLargeLength_zeroesRequestedRange() {
    byte[] data = new byte[200];
    Arrays.fill(data, (byte) 1);

    Util.bzero(data, 5, 150);

    for (int i = 0; i < data.length; i++) {
      if (i < 5 || i >= 155) {
        assertEquals(1, data[i], "Unexpected zero outside target range at index " + i);
      } else {
        assertEquals(0, data[i], "Expected zero inside target range at index " + i);
      }
    }
  }

  @Test
  void bzeroChar_whenLargeLength_zeroesRequestedRange() {
    char[] data = new char[10];
    Arrays.fill(data, 'x');

    Util.bzero(data, 3, 4);

    assertArrayEquals(new char[] {'x', 'x', 'x', 0, 0, 0, 0, 'x', 'x', 'x'}, data);
  }

  @Test
  void getSpaces_whenAskedForThree_returnsThreeSpaces() {
    assertEquals("   ", Util.getSpaces(3));
  }

  @Test
  void arraysEqualInt_whenArraysMatch_returnsTrue() {
    int[] a = {0, 1, 2, 3, 4};
    int[] b = {9, 1, 2, 3, 8};

    assertTrue(Util.arraysEqual(a, 1, b, 1, 3));
  }

  @Test
  void arraysEqualInt_whenMismatch_returnsFalse() {
    int[] a = {0, 1, 99, 3};
    int[] b = {0, 1, 2, 3};

    assertFalse(Util.arraysEqual(a, 0, b, 0, 4));
  }

  @Test
  void arraysEqualByte_whenMismatch_returnsFalse() {
    byte[] a = {1, 2, 3};
    byte[] b = {1, 2, 4};

    assertFalse(Util.arraysEqual(a, 0, b, 0, 3));
  }

  @Test
  void arraysEqualChar_whenMatch_returnsTrue() {
    char[] a = {'a', 'b', 'c'};
    char[] b = {'x', 'b', 'c', 'd'};

    assertTrue(Util.arraysEqual(a, 1, b, 1, 2));
  }

  @Test
  void arraysEqualLong_whenMismatch_returnsFalse() {
    long[] a = {1L, 2L};
    long[] b = {1L, 3L};

    assertFalse(Util.arraysEqual(a, 0, b, 0, 2));
  }

  @Test
  void shuffleInt_whenSeeded_producesDeterministicOrder() {
    int[] values = {0, 1, 2, 3, 4};

    Util.shuffle(values);

    assertArrayEquals(new int[] {0, 3, 2, 4, 1}, values);
  }

  @Test
  void shuffleBoolean_whenSeeded_producesDeterministicOrder() {
    boolean[] values = {true, false, true, false};

    Util.shuffle(values);

    assertArrayEquals(new boolean[] {true, true, false, false}, values);
  }

  @Test
  void shuffleObject_whenSeeded_producesDeterministicOrder() {
    Object[] values = {"a", "b", "c"};

    Util.shuffle(values);

    assertArrayEquals(new Object[] {"b", "a", "c"}, values);
  }

  @Test
  void getBytesAndGetChars_whenRoundTrip_preservesContent() {
    char[] source = {(char) 0x1234, (char) 0xABCD};

    byte[] bytes = Util.getBytes(source);
    char[] result = Util.getChars(bytes);

    assertArrayEquals(source, result);
  }

  @Test
  void getChars_whenOddLength_throwsIllegalArgumentException() {
    byte[] bytes = {0x01, 0x02, 0x03};

    assertThrows(IllegalArgumentException.class, () -> Util.getChars(bytes));
  }

  @Test
  void arraycopyCharToByte_whenOddNumBytes_copiesStragglerHighByte() {
    char[] chars = {(char) 0x1122, (char) 0x3344};
    byte[] bytes = new byte[3];

    Util.arraycopy(chars, 0, bytes, 0, 3);

    assertArrayEquals(new byte[] {0x11, 0x22, 0x33}, bytes);
  }

  @Test
  void arraycopyByteToChar_whenOddNumBytes_setsTrailingHighByte() {
    byte[] bytes = new byte[] {0x11, 0x22, 0x33};
    char[] chars = new char[2];

    Util.arraycopy(bytes, 0, chars, 0, 3);

    assertEquals((char) 0x1122, chars[0]);
    assertEquals((char) 0x3300, chars[1]);
  }

  @Test
  void getHexDump_whenGivenSequentialBytes_formatsOctalIndexAndSpacing() {
    byte[] data = new byte[17];
    for (int i = 0; i < data.length; i++) {
      data[i] = (byte) i;
    }

    String dump = Util.getHexDump(data);

    assertEquals("0000000 00010203 04050607 08090a0b 0c0d0e0f\n0000020 10", dump);
  }

  @Test
  void divideCeilInt_whenNotDivisible_roundsUp() {
    assertEquals(3, Util.divideCeil(5, 2));
  }

  @Test
  void divideCeilLong_whenExactDivision_keepsQuotient() {
    assertEquals(4, Util.divideCeil(16L, 4L));
  }

  @Test
  void log2_whenPowerOfTwo_returnsExponent() {
    assertEquals(3.0, Util.log2(8.0), 0.0001);
  }

  @Test
  void bytesToHexAndHexToBytes_whenRoundTrip_preservesLowercase() {
    byte[] input = new byte[] {0x0F, 0x1A, (byte) 0xFF};

    String hex = Util.bytesToHex(input);
    byte[] result = Util.hexToBytes(hex);

    assertEquals("0f1aff", hex);
    assertArrayEquals(input, result);
  }

  @Test
  void hexToBytes_whenInvalidLength_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> Util.hexToBytes("abc"));
  }

  @Test
  void hexToBytes_whenInvalidDigits_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> Util.hexToBytes("0g"));
  }

  @Test
  void isProbablyNat_whenPrivateRanges_returnsTrue() {
    assertTrue(Util.isProbablyNat(new byte[] {10, 0, 0, 1}));
    assertTrue(Util.isProbablyNat(new byte[] {(byte) 192, (byte) 168, 1, 1}));
  }

  @Test
  void isProbablyNat_whenPublicRange_returnsFalse() {
    assertFalse(Util.isProbablyNat(new byte[] {8, 8, 8, 8}));
  }

  @Test
  void isProbablyNat_whenWrongLength_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> Util.isProbablyNat(new byte[] {1, 2, 3}));
  }

  @Test
  void getMethod_whenAssignableParameter_returnsPublicMethod() {
    Method method =
        Util.getMethod(AssignableMethods.class.getMethods(), "handle", new Class[] {Integer.class});

    assertNotNull(method);
    assertEquals("handle", method.getName());
    assertEquals(1, method.getParameterCount());
    assertEquals(Number.class, method.getParameterTypes()[0]);
  }

  @Test
  void getPublicMethod_whenImplementedOnInterface_findsInterfaceMethod() throws Exception {
    Method method =
        Util.getPublicMethod(NonPublicClass.class, "process", new Class[] {Number.class});

    assertNotNull(method);
    assertEquals("process", method.getName());
  }

  @Test
  void createIntIterator_whenIterating_consumesAllValues() {
    List<Integer> list = new ArrayList<>(List.of(1, 2, 3));
    Iterator<Integer> iterator = list.iterator();

    IntIterator intIterator = Util.createIntIterator(iterator);

    assertTrue(intIterator.hasNextInt());
    assertEquals(1, intIterator.nextInt());
    intIterator.removeInt();
    assertEquals(2, intIterator.nextInt());
    assertEquals(3, intIterator.nextInt());
    assertFalse(intIterator.hasNextInt());
    assertEquals(List.of(2, 3), list);
  }

  @SuppressWarnings("unused")
  public static class AssignableMethods {
    public void handle(Number number) {
      // No-op: method exists solely so reflection tests can verify assignable parameters.
    }
  }

  @SuppressWarnings("unused")
  public interface ProcessingInterface {
    void process(Number number);
  }

  static class NonPublicClass implements ProcessingInterface {
    @Override
    public void process(Number number) {
      // No-op: required to expose a public interface method on a non-public class for testing.
    }
  }
}
