package org.spaceroots.mantissa.optimization;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class NelderMeadTest {

  @Test
  void iterateSimplex_whenReflectionBetterThanSecondWorst_replacesWorstWithReflection()
      throws Exception {
    // Arrange
    double[][] vertices = {
      new double[] {0.0, 0.0},
      new double[] {1.0, 0.0},
      new double[] {0.0, 2.0}
    };
    // cost sequence: v0, v1, v2, reflection
    ScriptedCostFunction costs = new ScriptedCostFunction(1.0, 2.0, 5.0, 1.5);
    NelderMead optimizer = new NelderMead();

    // Act
    optimizer.minimizes(costs, 10, new IterationChecker(0), vertices);

    // Assert
    assertEquals(1.0, optimizer.simplex[0].cost, 1e-12);
    assertEquals(1.5, optimizer.simplex[1].cost, 1e-12);
    assertEquals(2.0, optimizer.simplex[2].cost, 1e-12);
    assertArrayEquals(new double[] {1.0, -2.0}, optimizer.simplex[1].point, 1e-12);
  }

  @Test
  void iterateSimplex_whenExpansionBeatsReflection_acceptsExpansion() throws Exception {
    // Arrange
    double[][] vertices = {
      new double[] {0.0, 0.0},
      new double[] {1.0, 0.0},
      new double[] {0.0, 2.0}
    };
    // costs: v0, v1, v2, reflection (< smallest), expansion (< reflection)
    ScriptedCostFunction costs = new ScriptedCostFunction(5.0, 6.0, 7.0, 1.0, 0.5);
    NelderMead optimizer = new NelderMead();

    // Act
    optimizer.minimizes(costs, 10, new IterationChecker(0), vertices);

    // Assert
    assertEquals(0.5, optimizer.simplex[0].cost, 1e-12);
    assertArrayEquals(new double[] {1.5, -4.0}, optimizer.simplex[0].point, 1e-12);
  }

  @Test
  void iterateSimplex_whenOutsideContractionSucceeds_replacesWorstWithContraction()
      throws Exception {
    // Arrange
    double[][] vertices = {
      new double[] {0.0, 0.0},
      new double[] {1.0, 0.0},
      new double[] {3.0, 0.0}
    };
    // costs: v0, v1, v2, reflection (between 2nd and worst), contraction (<= reflection)
    ScriptedCostFunction costs = new ScriptedCostFunction(0.0, 1.0, 9.0, 4.0, 0.25);
    NelderMead optimizer = new NelderMead();

    // Act
    optimizer.minimizes(costs, 10, new IterationChecker(0), vertices);

    // Assert
    assertEquals(0.25, optimizer.simplex[1].cost, 1e-12);
    assertArrayEquals(new double[] {-0.75, 0.0}, optimizer.simplex[1].point, 1e-12);
  }

  @Test
  void iterateSimplex_whenContractionFails_triggersShrinkAndReevaluation() throws Exception {
    // Arrange
    double[][] vertices = {
      new double[] {0.0, 0.0},
      new double[] {1.0, 0.0},
      new double[] {0.0, 2.0}
    };
    // costs: v0, v1, v2, reflection (worse than worst), inside contraction (still worse),
    // shrink evaluations for the two updated vertices
    ScriptedCostFunction costs = new ScriptedCostFunction(0.0, 1.0, 5.0, 10.0, 8.0, 0.25, 1.0);
    NelderMead optimizer = new NelderMead();

    // Act
    optimizer.minimizes(costs, 15, new IterationChecker(0), vertices);

    // Assert
    assertEquals(0.0, optimizer.simplex[0].cost, 1e-12);
    assertEquals(0.25, optimizer.simplex[1].cost, 1e-12);
    assertEquals(1.0, optimizer.simplex[2].cost, 1e-12);
    assertArrayEquals(new double[] {0.5, 0.0}, optimizer.simplex[1].point, 1e-12);
    assertArrayEquals(new double[] {0.0, 1.0}, optimizer.simplex[2].point, 1e-12);
  }

  @Test
  void minimizes_whenCostSequenceExhausted_throwsCostException() {
    // Arrange
    double[][] vertices = {
      new double[] {0.0, 0.0},
      new double[] {1.0, 0.0},
      new double[] {0.0, 2.0}
    };
    // Only three costs provided, but simplex evaluation needs at least three plus one for iteration
    ScriptedCostFunction costs = new ScriptedCostFunction(1.0, 2.0, 3.0);
    NelderMead optimizer = new NelderMead();

    // Act + Assert
    assertThrows(
        CostException.class,
        () -> optimizer.minimizes(costs, 5, new IterationChecker(0), vertices));
  }

  private static final class IterationChecker implements ConvergenceChecker {

    private final int iterationsBeforeConverged;
    private int calls;

    IterationChecker(int iterationsBeforeConverged) {
      this.iterationsBeforeConverged = iterationsBeforeConverged;
    }

    @Override
    public boolean converged(PointCostPair[] simplex) {
      return calls++ > iterationsBeforeConverged;
    }
  }

  private static final class ScriptedCostFunction implements CostFunction {

    private final double[] scripted;
    private int index;

    ScriptedCostFunction(double... scripted) {
      this.scripted = scripted;
    }

    @Override
    public double cost(double[] x) throws CostException {
      if (index >= scripted.length) {
        throw new CostException("No scripted cost available for evaluation " + index);
      }
      return scripted[index++];
    }
  }
}
