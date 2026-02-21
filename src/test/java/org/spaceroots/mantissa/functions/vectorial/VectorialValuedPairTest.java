package org.spaceroots.mantissa.functions.vectorial;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings({"java:S100", "java:S5778"})
class VectorialValuedPairTest {

  private static VectorialValuedPair constructPair(double x, double[] y) {
    return new VectorialValuedPair(x, y);
  }

  @Test
  void constructor_whenProvidedValues_copiesAbscissaAndOrdinate() {
    double[] input = {1.0, -2.5, 3.3};

    VectorialValuedPair pair = new VectorialValuedPair(4.2, input);

    assertEquals(4.2, pair.x);
    assertArrayEquals(input, pair.y);
    assertNotSame(input, pair.y, "y should be defensively copied");
  }

  @Test
  void constructor_whenInputArrayModified_doesNotAffectStored() {
    double[] input = {5.0, 6.0};

    VectorialValuedPair pair = new VectorialValuedPair(1.0, input);
    input[0] = -99.0;

    assertArrayEquals(new double[] {5.0, 6.0}, pair.y);
  }

  @Test
  void constructor_whenEmptyArray_allowsCreation() {
    double[] empty = {};

    VectorialValuedPair pair = new VectorialValuedPair(0.0, empty);

    assertEquals(0.0, pair.x);
    assertArrayEquals(empty, pair.y);
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void constructor_whenNullArray_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () -> {
          network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(constructPair(2.0, null));
        });
  }

  @Test
  void serialization_whenRoundTripped_preservesValuesAndIsolation()
      throws IOException, ClassNotFoundException {
    double[] input = {7.1, 8.2};
    VectorialValuedPair original = new VectorialValuedPair(9.3, input);

    byte[] serialized;
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos)) {
      oos.writeObject(original);
      serialized = baos.toByteArray();
    }

    VectorialValuedPair restored;
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serialized))) {
      restored = (VectorialValuedPair) ois.readObject();
    }

    assertEquals(original.x, restored.x);
    assertArrayEquals(original.y, restored.y);
    assertNotSame(
        original.y, restored.y, "Deserialization should create a separate array instance");
  }
}
