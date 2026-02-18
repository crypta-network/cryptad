package org.spaceroots.mantissa.estimation;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class EstimatedParameterTest {

  @Test
  void constructor_whenBoundNotProvided_setsUnboundByDefault() {
    EstimatedParameter parameter = new EstimatedParameter("alpha", 1.5);

    assertEquals("alpha", parameter.getName());
    assertEquals(1.5, parameter.getEstimate());
    assertFalse(parameter.isBound());
  }

  @Test
  void constructor_whenBoundFlagProvided_setsFieldsAccordingly() {
    EstimatedParameter parameter = new EstimatedParameter("beta", -2.0, true);

    assertEquals("beta", parameter.getName());
    assertEquals(-2.0, parameter.getEstimate());
    assertTrue(parameter.isBound());
  }

  @Test
  void setEstimate_whenCalled_updatesValue() {
    EstimatedParameter parameter = new EstimatedParameter("gamma", 0.0);

    parameter.setEstimate(42.0);

    assertEquals(42.0, parameter.getEstimate());
  }

  @Test
  void setEstimate_whenUsingNaN_preservesValue() {
    EstimatedParameter parameter = new EstimatedParameter("delta", 5.0);

    parameter.setEstimate(Double.NaN);

    assertTrue(Double.isNaN(parameter.getEstimate()));
  }

  @Test
  void setBound_whenToggled_changesFlag() {
    EstimatedParameter parameter = new EstimatedParameter("epsilon", 3.0, false);

    parameter.setBound(true);
    assertTrue(parameter.isBound());

    parameter.setBound(false);
    assertFalse(parameter.isBound());
  }

  @Test
  void copyConstructor_whenModified_doesNotAffectOriginalInstance() {
    EstimatedParameter original = new EstimatedParameter("zeta", 7.0, true);
    EstimatedParameter copy = new EstimatedParameter(original);

    copy.setEstimate(8.0);
    copy.setBound(false);

    assertEquals("zeta", copy.getName());
    assertEquals("zeta", original.getName());
    assertEquals(7.0, original.getEstimate());
    assertTrue(original.isBound());
    assertEquals(8.0, copy.getEstimate());
    assertFalse(copy.isBound());
  }
}
