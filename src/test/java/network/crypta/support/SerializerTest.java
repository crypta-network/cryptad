package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100") // Allow method_whenCondition_expectOutcome naming in tests
class SerializerTest {

  // ---------- Helpers ----------

  private static byte[] writeWithSerializer(Object value) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    Serializer.writeToDataOutputStream(value, dos);
    dos.flush();
    return baos.toByteArray();
  }

  private static Object readWithSerializer(Class<?> type, byte[] bytes) throws IOException {
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      return Serializer.readFromDataInputStream(type, dis);
    }
  }

  // ---------- Boolean ----------

  @ParameterizedTest
  @CsvSource({"1,true", "0,false"})
  @DisplayName("readFromDataInputStream(Boolean) accepts only 0/1")
  void readFromDataInputStream_boolean_whenValidBytes_expectValue(int b, boolean expected)
      throws IOException {
    byte[] bytes = new byte[] {(byte) b};
    Object read = readWithSerializer(Boolean.class, bytes);
    assertEquals(expected, read);
  }

  @Test
  void readFromDataInputStream_boolean_whenInvalidByte_expectIOException() {
    byte[] bytes = new byte[] {(byte) 2};
    assertThrows(IOException.class, () -> readWithSerializer(Boolean.class, bytes));
  }

  // ---------- Primitives (numbers) ----------

  private static List<Arguments> integerNumbers() {
    return List.of(
        Arguments.of((byte) 9, Byte.class),
        Arguments.of((short) 0x7BEE, Short.class),
        Arguments.of(1_234_567, Integer.class),
        Arguments.of(123_456_789_012L, Long.class));
  }

  @ParameterizedTest
  @MethodSource("integerNumbers")
  void writeThenRead_integers_roundTrip(Object value, Class<?> type) throws IOException {
    byte[] bytes = writeWithSerializer(value);
    Object read = readWithSerializer(type, bytes);
    assertEquals(value, read);
  }

  private static List<Arguments> floatingNumbers() {
    return List.of(Arguments.of(Math.E, Double.class), Arguments.of(123.4567f, Float.class));
  }

  @ParameterizedTest
  @MethodSource("floatingNumbers")
  void writeThenRead_floatsAndDoubles_roundTrip(Number value, Class<?> type) throws IOException {
    byte[] bytes = writeWithSerializer(value);
    Object read = readWithSerializer(type, bytes);
    if (type == Double.class) {
      assertEquals(value.doubleValue(), (Double) read, 0.0);
    } else {
      assertEquals(value.floatValue(), (Float) read, 0.0f);
    }
  }

  // ---------- String ----------

  @Test
  void writeThenRead_string_withinMax_expectRoundTrip() throws IOException {
    String s = "hello π and ☕"; // BMP chars so writeChar/readChar are consistent
    byte[] bytes = writeWithSerializer(s);
    Object read = readWithSerializer(String.class, bytes);
    assertEquals(s, read);
  }

  @Test
  void readFromDataInputStream_string_whenNegativeLength_expectIOException() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(-1);
    }
    assertThrows(IOException.class, () -> readWithSerializer(String.class, baos.toByteArray()));
  }

  @Test
  void readFromDataInputStream_string_whenExceedsMax_expectIOException() throws IOException {
    int tooLarge = Serializer.MAX_ARRAY_LENGTH + 1;
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(tooLarge);
    }
    assertThrows(IOException.class, () -> readWithSerializer(String.class, baos.toByteArray()));
  }

  // ---------- double[] ----------

  @ParameterizedTest
  @CsvSource({"0", "255"})
  void writeThenRead_doubleArray_withBoundaryLengths_expectRoundTrip(int length)
      throws IOException {
    double[] arr = new double[length];
    for (int i = 0; i < arr.length; i++) arr[i] = i + Math.PI;
    byte[] bytes = writeWithSerializer(arr);
    Object read = readWithSerializer(double[].class, bytes);
    assertArrayEquals(arr, (double[]) read, 0.0);
  }

  @Test
  void writeToDataOutputStream_doubleArray_whenTooLong_expectIllegalArgumentException() {
    double[] arr = new double[256];
    assertThrows(IllegalArgumentException.class, () -> writeWithSerializer(arr));
  }

  // ---------- float[] ----------

  @ParameterizedTest
  @CsvSource({"0", "1023"})
  void writeThenRead_floatArray_withBoundaryLengths_expectRoundTrip(int length) throws IOException {
    float[] arr = new float[length];
    for (int i = 0; i < arr.length; i++) arr[i] = (float) (i + Math.E);
    byte[] bytes = writeWithSerializer(arr);
    Object read = readWithSerializer(float[].class, bytes);
    assertArrayEquals(arr, (float[]) read, 0.0f);
  }

  @Test
  void readFromDataInputStream_floatArray_whenNegativeLength_expectIOException()
      throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeShort(-1);
    }
    assertThrows(IOException.class, () -> readWithSerializer(float[].class, baos.toByteArray()));
  }

  @Test
  void readFromDataInputStream_floatArray_whenLengthTooLarge_expectIOException()
      throws IOException {
    // MAX_ARRAY_LENGTH / 4 = 1023; we write 1024 to trigger the guard.
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeShort(1024);
    }
    assertThrows(IOException.class, () -> readWithSerializer(float[].class, baos.toByteArray()));
  }

  // ---------- LinkedList / list ----------

  @Test
  void readListFromDataInputStream_whenLinkedListOfStrings_expectRoundTrip() throws IOException {
    LinkedList<String> list = new LinkedList<>();
    list.add("alpha");
    list.add("beta");
    list.add("gamma");

    // Serialize list using Serializer's LinkedList branch
    byte[] bytes = writeWithSerializer(list);

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      List<Object> read = Serializer.readListFromDataInputStream(String.class, dis);
      assertEquals(list, read);
    }
  }

  @Test
  void readListFromDataInputStream_whenEmpty_expectEmptyList() throws IOException {
    LinkedList<String> list = new LinkedList<>();
    byte[] bytes = writeWithSerializer(list);
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      List<Object> read = Serializer.readListFromDataInputStream(String.class, dis);
      assertEquals(0, read.size());
    }
  }

  // ---------- Unsupported types / errors ----------

  @Test
  void writeToDataOutputStream_whenUnsupportedType_expectIllegalArgumentException() {
    Object unsupported = new Object();
    assertThrows(IllegalArgumentException.class, () -> writeWithSerializer(unsupported));
  }

  @Test
  void readFromDataInputStream_whenUnsupportedType_expectIllegalArgumentException() {
    byte[] empty = new byte[0];
    assertThrows(IllegalArgumentException.class, () -> readWithSerializer(Object.class, empty));
  }

  // ---------- length(Class, maxStringLength) ----------

  @Test
  void length_whenKnownScalarTypes_expectExpectedSizes() {
    assertEquals(8, Serializer.length(Long.class, 0));
    assertEquals(1, Serializer.length(Boolean.class, 0));
    assertEquals(4, Serializer.length(Integer.class, 0));
    assertEquals(2, Serializer.length(Short.class, 0));
    assertEquals(8, Serializer.length(Double.class, 0));
    assertEquals(1, Serializer.length(Byte.class, 0));
    assertEquals(4 + 10 * 2, Serializer.length(String.class, 10));
  }

  // Dummy type to trigger WritableToDataOutputStream path in length()
  private static class DummyWritable implements network.crypta.io.WritableToDataOutputStream {
    @Override
    public void writeToDataOutputStream(DataOutputStream dos) throws IOException {
      dos.writeInt(42);
    }
  }

  @Test
  void length_whenWritableAssignable_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> Serializer.length(DummyWritable.class, 0));
  }

  @Test
  void length_whenLinkedList_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> Serializer.length(LinkedList.class, 0));
  }

  @Test
  void length_whenUnknownType_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> Serializer.length(double[].class, 0));
  }
}
