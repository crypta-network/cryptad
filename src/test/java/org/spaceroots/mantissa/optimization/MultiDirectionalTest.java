package org.spaceroots.mantissa.optimization;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class MultiDirectionalTest {

  private static final double EPS = 1e-12;

  @Test
  void minimizes_whenReflectionBeatsExpansion_keepsReflectedSimplex() throws Exception {
    MultiDirectional optimizer = new MultiDirectional();
    ConvergenceChecker checker = new StepCountChecker(1);

    PointCostPair result =
        optimizer.minimizes(x -> x[0] * x[0], 20, checker, new double[] {1.0}, new double[] {2.0});

    assertEquals(0.0, result.point[0], EPS);
    assertEquals(0.0, result.cost, EPS);
    assertArrayEquals(new double[] {0.0}, optimizer.simplex[0].point, EPS);
    assertArrayEquals(new double[] {1.0}, optimizer.simplex[1].point, EPS);
  }

  @Test
  void minimizes_whenExpansionBetterThanReflection_prefersExpandedSimplex() throws Exception {
    MultiDirectional optimizer = new MultiDirectional();
    ConvergenceChecker checker = new StepCountChecker(1);

    PointCostPair result =
        optimizer.minimizes(x -> x[0], 20, checker, new double[] {1.0}, new double[] {3.0});

    assertEquals(-3.0, result.point[0], EPS);
    assertEquals(-3.0, result.cost, EPS);
    assertArrayEquals(new double[] {-3.0}, optimizer.simplex[0].point, EPS);
    assertArrayEquals(new double[] {1.0}, optimizer.simplex[1].point, EPS);
  }

  @Test
  void minimizes_whenReflectionNotBetterButContractionIs_acceptsContractedSimplex()
      throws Exception {
    MultiDirectional optimizer = new MultiDirectional();
    ConvergenceChecker checker = new StepCountChecker(1);

    PointCostPair result =
        optimizer.minimizes(
            x -> Math.abs(x[0]), 20, checker, new double[] {1.0}, new double[] {3.0});

    assertEquals(0.0, result.point[0], EPS);
    assertEquals(0.0, result.cost, EPS);
    assertArrayEquals(new double[] {0.0}, optimizer.simplex[0].point, EPS);
    assertArrayEquals(new double[] {1.0}, optimizer.simplex[1].point, EPS);
  }

  /** Stops the optimization loop after a fixed number of convergence checks. */
  private static final class StepCountChecker implements ConvergenceChecker {
    private final int stopAfterCalls;
    private int calls;

    private StepCountChecker(int stopAfterCalls) {
      this.stopAfterCalls = stopAfterCalls;
    }

    @Override
    public boolean converged(PointCostPair[] simplex) {
      return calls++ >= stopAfterCalls;
    }
  }
}
