package com.onionnetworks.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class BufferTest {

  @Test
  void constructor_withNegativeLength_throwsArrayIndexOutOfBoundsException() {
    byte[] data = new byte[2];

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> new Buffer(data, 0, -1));
  }

  @Test
  void constructor_withNegativeOffset_throwsArrayIndexOutOfBoundsException() {
    byte[] data = new byte[2];

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> new Buffer(data, -1, 1));
  }

  @Test
  void constructor_withLengthExceedingArray_throwsArrayIndexOutOfBoundsException() {
    byte[] data = new byte[3];

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> new Buffer(data, 2, 2));
  }

  @Test
  void getBytes_withOffsetAndLength_returnsCopyOfRange() {
    byte[] data = new byte[] {1, 2, 3, 4};
    Buffer buffer = new Buffer(data, 1, 2);

    byte[] copy = buffer.getBytes();

    assertArrayEquals(new byte[] {2, 3}, copy);
    assertNotSame(data, copy);
    copy[0] = 9;
    assertNotEquals(copy[0], data[1]);
  }

  @Test
  void equals_whenSameContentAndLength_returnsTrue() {
    Buffer left = new Buffer(new byte[] {5, 6, 7});
    Buffer right = new Buffer(new byte[] {5, 6, 7});

    assertEquals(left, right);
    assertEquals(right, left);
  }

  @Test
  void equals_withSubsectionBuffersAndOffsets_returnsTrue() {
    byte[] data = new byte[] {0, 1, 2, 3};
    Buffer left = new Buffer(data, 1, 2); // bytes 1,2
    Buffer right = new Buffer(new byte[] {1, 2});

    assertEquals(left, right);
  }

  @Test
  void equals_whenDifferentLength_returnsFalse() {
    Buffer left = new Buffer(new byte[] {1, 2, 3});
    Buffer right = new Buffer(new byte[] {1, 2});

    assertNotEquals(left, right);
  }

  @Test
  void equals_whenDifferentContent_returnsFalse() {
    Buffer left = new Buffer(new byte[] {1, 2, 3});
    Buffer right = new Buffer(new byte[] {1, 2, 4});

    assertNotEquals(left, right);
  }

  @Test
  void equals_whenComparedToNonBuffer_returnsFalse() {
    Buffer buffer = new Buffer(new byte[] {1});

    //noinspection AssertBetweenInconvertibleTypes
    assertNotEquals("not-a-buffer", buffer);
  }

  @Test
  void toString_whenOffsetZero_containsLengthOffsetAndValues() {
    Buffer buffer = new Buffer(new byte[] {9, 8});

    String description = buffer.toString();

    assertTrue(description.contains("length: 2"));
    assertTrue(description.contains("offset: 0"));
    assertTrue(description.contains("0: 9"));
    assertTrue(description.contains("1: 8"));
  }
}
