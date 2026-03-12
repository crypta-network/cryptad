package org.spaceroots.mantissa.functions.scalar;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ScalarValuedPairTest {

  private static final double EPS = 1.0e-12;

  @Test
  void constructor_whenGivenValues_storeValues() {
    ScalarValuedPair pair = new ScalarValuedPair(1.5, -2.0);

    assertEquals(1.5, pair.getX(), EPS);
    assertEquals(-2.0, pair.getY(), EPS);
  }

  @Test
  void copyConstructor_whenSourceProvided_createsIndependentCopy() {
    ScalarValuedPair original = new ScalarValuedPair(3.0, 4.0);

    ScalarValuedPair copy = new ScalarValuedPair(original);
    original.setX(5.0);
    original.setY(6.0);

    assertEquals(3.0, copy.getX(), EPS);
    assertEquals(4.0, copy.getY(), EPS);
    assertEquals(5.0, original.getX(), EPS);
    assertEquals(6.0, original.getY(), EPS);
  }

  @Test
  void setters_whenUpdated_overwriteValues() {
    ScalarValuedPair pair = new ScalarValuedPair(0.0, 0.0);

    pair.setX(-7.5);
    pair.setY(9.25);

    assertEquals(-7.5, pair.getX(), EPS);
    assertEquals(9.25, pair.getY(), EPS);
  }

  @Test
  void serialization_whenRoundTripped_preservesState() throws Exception {
    ScalarValuedPair pair = new ScalarValuedPair(123.456, -654.321);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(out)) {
      oos.writeObject(pair);
    }

    ScalarValuedPair deserialized;
    try (ObjectInputStream ois =
        new ObjectInputStream(new ByteArrayInputStream(out.toByteArray()))) {
      deserialized = (ScalarValuedPair) ois.readObject();
    }

    assertEquals(pair.getX(), deserialized.getX(), EPS);
    assertEquals(pair.getY(), deserialized.getY(), EPS);
  }

  @ParameterizedTest
  @MethodSource("specialValuesProvider")
  void constructor_whenSpecialDoubleValues_preservesValues(double x, double y) {
    ScalarValuedPair pair = new ScalarValuedPair(x, y);

    assertEquals(Double.doubleToLongBits(x), Double.doubleToLongBits(pair.getX()));
    assertEquals(Double.doubleToLongBits(y), Double.doubleToLongBits(pair.getY()));
  }

  private static Stream<Arguments> specialValuesProvider() {
    return Stream.of(
        Arguments.of(Double.NaN, 1.0),
        Arguments.of(Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY),
        Arguments.of(Double.MIN_VALUE, Double.MAX_VALUE));
  }
}
