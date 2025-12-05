package org.spaceroots.mantissa.fitting;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class PolynomialCoefficientTest {

  @Test
  void constructor_whenDegreeProvided_setsNameEstimateDegreeAndUnbound() {
    PolynomialCoefficient coefficient = new PolynomialCoefficient(3);

    assertEquals("a3", coefficient.getName());
    assertEquals(0.0, coefficient.getEstimate());
    assertEquals(3, coefficient.getDegree());
    assertFalse(coefficient.isBound());
  }

  @Test
  void setEstimate_whenUpdated_changesEstimateOnly() {
    PolynomialCoefficient coefficient = new PolynomialCoefficient(2);

    coefficient.setEstimate(4.5);

    assertEquals(4.5, coefficient.getEstimate());
    assertEquals(2, coefficient.getDegree());
    assertEquals("a2", coefficient.getName());
  }

  @Test
  void setBound_whenFlagToggled_updatesBoundStatus() {
    PolynomialCoefficient coefficient = new PolynomialCoefficient(1);

    coefficient.setBound(true);

    assertTrue(coefficient.isBound());
  }

  @Test
  void serialization_whenRoundTripped_preservesAllFields() throws Exception {
    PolynomialCoefficient original = new PolynomialCoefficient(7);
    original.setEstimate(1.25);
    original.setBound(true);

    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (ObjectOutputStream out = new ObjectOutputStream(buffer)) {
      out.writeObject(original);
    }

    PolynomialCoefficient restored;
    try (ObjectInputStream in =
        new ObjectInputStream(new ByteArrayInputStream(buffer.toByteArray()))) {
      restored = (PolynomialCoefficient) in.readObject();
    }

    assertEquals("a7", restored.getName());
    assertEquals(7, restored.getDegree());
    assertEquals(1.25, restored.getEstimate());
    assertTrue(restored.isBound());
  }
}
