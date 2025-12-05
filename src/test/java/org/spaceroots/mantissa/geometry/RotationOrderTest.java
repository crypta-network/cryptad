package org.spaceroots.mantissa.geometry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100")
@DisplayNameGeneration(ReplaceUnderscores.class)
class RotationOrderTest {

  @ParameterizedTest(name = "{0}")
  @MethodSource("rotationOrdersProvider")
  void getters_whenUsingPredefinedOrders_returnConfiguredAxes(
      String name,
      RotationOrder order,
      Vector3D expectedA1,
      Vector3D expectedA2,
      Vector3D expectedA3) {
    assertSame(expectedA1, order.getA1());
    assertSame(expectedA2, order.getA2());
    assertSame(expectedA3, order.getA3());
    assertEquals(name, order.toString());
  }

  @Test
  void toString_whenUsingDistinctOrders_returnsDistinctNames() {
    assertEquals("XYZ", RotationOrder.XYZ.toString());
    assertEquals("ZYZ", RotationOrder.ZYZ.toString());
  }

  private static Stream<Arguments> rotationOrdersProvider() {
    return Stream.of(
        Arguments.of("XYZ", RotationOrder.XYZ, Vector3D.plusI, Vector3D.plusJ, Vector3D.plusK),
        Arguments.of("XZY", RotationOrder.XZY, Vector3D.plusI, Vector3D.plusK, Vector3D.plusJ),
        Arguments.of("YXZ", RotationOrder.YXZ, Vector3D.plusJ, Vector3D.plusI, Vector3D.plusK),
        Arguments.of("YZX", RotationOrder.YZX, Vector3D.plusJ, Vector3D.plusK, Vector3D.plusI),
        Arguments.of("ZXY", RotationOrder.ZXY, Vector3D.plusK, Vector3D.plusI, Vector3D.plusJ),
        Arguments.of("ZYX", RotationOrder.ZYX, Vector3D.plusK, Vector3D.plusJ, Vector3D.plusI),
        Arguments.of("XYX", RotationOrder.XYX, Vector3D.plusI, Vector3D.plusJ, Vector3D.plusI),
        Arguments.of("XZX", RotationOrder.XZX, Vector3D.plusI, Vector3D.plusK, Vector3D.plusI),
        Arguments.of("YXY", RotationOrder.YXY, Vector3D.plusJ, Vector3D.plusI, Vector3D.plusJ),
        Arguments.of("YZY", RotationOrder.YZY, Vector3D.plusJ, Vector3D.plusK, Vector3D.plusJ),
        Arguments.of("ZXZ", RotationOrder.ZXZ, Vector3D.plusK, Vector3D.plusI, Vector3D.plusK),
        Arguments.of("ZYZ", RotationOrder.ZYZ, Vector3D.plusK, Vector3D.plusJ, Vector3D.plusK));
  }
}
