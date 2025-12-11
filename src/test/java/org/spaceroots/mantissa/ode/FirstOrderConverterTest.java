package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class FirstOrderConverterTest {

  @Mock private SecondOrderDifferentialEquations equations;

  @Test
  void getDimension_whenCalled_returnsDoubleOriginalDimension() {
    // Arrange
    when(equations.getDimension()).thenReturn(3);
    FirstOrderConverter converter = new FirstOrderConverter(equations);

    // Act
    int actual = converter.getDimension();

    // Assert
    assertEquals(6, actual);
    verify(equations).getDimension();
  }

  @Test
  void computeDerivatives_whenValidState_mapsToFirstOrderForm() throws DerivativeException {
    // Arrange
    when(equations.getDimension()).thenReturn(2);
    FirstOrderConverter converter = new FirstOrderConverter(equations);
    double[] state = new double[] {1.0, -2.0, 0.5, 4.0};
    double[] derivative = new double[4];
    double time = 1.5;

    org.mockito.Mockito.doAnswer(
            invocation -> {
              double[] z = invocation.getArgument(1);
              double[] zDot = invocation.getArgument(2);
              double[] zDDot = invocation.getArgument(3);
              assertArrayEquals(new double[] {1.0, -2.0}, z);
              assertArrayEquals(new double[] {0.5, 4.0}, zDot);
              zDDot[0] = z[0] + zDot[0];
              zDDot[1] = z[1] + zDot[1];
              return null;
            })
        .when(equations)
        .computeSecondDerivatives(
            eq(time), any(double[].class), any(double[].class), any(double[].class));

    // Act
    converter.computeDerivatives(time, state, derivative);

    // Assert
    assertArrayEquals(new double[] {0.5, 4.0, 1.5, 2.0}, derivative);
    verify(equations)
        .computeSecondDerivatives(
            eq(time), any(double[].class), any(double[].class), any(double[].class));
  }

  @Test
  void computeDerivatives_whenUnderlyingThrows_propagatesDerivativeException()
      throws DerivativeException {
    // Arrange
    when(equations.getDimension()).thenReturn(1);
    FirstOrderConverter converter = new FirstOrderConverter(equations);
    DerivativeException failure = new DerivativeException(new IllegalStateException("boom"));
    org.mockito.Mockito.doThrow(failure)
        .when(equations)
        .computeSecondDerivatives(
            anyDouble(), any(double[].class), any(double[].class), any(double[].class));
    double[] state = new double[] {1.0, 0.5};
    double[] derivative = new double[2];

    // Act + Assert
    DerivativeException thrown =
        assertThrows(
            DerivativeException.class, () -> converter.computeDerivatives(0.0, state, derivative));
    assertSame(failure, thrown);
  }
}
