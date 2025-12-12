package org.spaceroots.mantissa.roots;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.ComputableFunction;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class BrentSolverTest {

  @Test
  void getRoot_afterConstruction_returnsNaN() {
    BrentSolver solver = new BrentSolver();

    assertTrue(Double.isNaN(solver.getRoot()));
  }

  @Test
  void findRoot_whenCheckerReturnsLowOnFirstIteration_setsLowerEndpointAsRoot() throws Exception {
    // Arrange
    BrentSolver solver = new BrentSolver();
    ComputableFunction function = x -> x * x - 2.0;
    ConvergenceChecker checker = Mockito.mock(ConvergenceChecker.class);
    Mockito.when(
            checker.converged(
                Mockito.anyDouble(), Mockito.anyDouble(), Mockito.anyDouble(), Mockito.anyDouble()))
        .thenReturn(ConvergenceChecker.LOW);

    double x0 = 0.0;
    double x1 = 2.0;
    double f0 = function.valueAt(x0);
    double f1 = function.valueAt(x1);

    // Act
    boolean found = solver.findRoot(function, checker, 10, x0, f0, x1, f1);

    // Assert
    assertTrue(found);
    assertEquals(x0, solver.getRoot(), 0.0);
  }

  @Test
  void findRoot_whenCheckerReturnsHighOnFirstIteration_setsUpperEndpointAsRoot() throws Exception {
    // Arrange
    BrentSolver solver = new BrentSolver();
    ComputableFunction function = x -> x * x - 2.0;
    ConvergenceChecker checker = Mockito.mock(ConvergenceChecker.class);
    Mockito.when(
            checker.converged(
                Mockito.anyDouble(), Mockito.anyDouble(), Mockito.anyDouble(), Mockito.anyDouble()))
        .thenReturn(ConvergenceChecker.HIGH);

    double x0 = 0.0;
    double x1 = 2.0;
    double f0 = function.valueAt(x0);
    double f1 = function.valueAt(x1);

    // Act
    boolean found = solver.findRoot(function, checker, 10, x0, f0, x1, f1);

    // Assert
    assertTrue(found);
    assertEquals(x1, solver.getRoot(), 0.0);
  }

  @Test
  void findRoot_whenUpperEndpointIsExactRoot_convergesWithoutEvaluatingFunction() throws Exception {
    // Arrange
    BrentSolver solver = new BrentSolver();
    ComputableFunction function = Mockito.mock(ComputableFunction.class);
    ConvergenceChecker checker = (xLow, fLow, xHigh, fHigh) -> ConvergenceChecker.NONE;

    double x0 = 0.0;
    double x1 = 1.0;
    double f0 = -1.0;
    double f1 = 0.0;

    // Act
    boolean found = solver.findRoot(function, checker, 10, x0, f0, x1, f1);

    // Assert
    assertTrue(found);
    assertEquals(x1, solver.getRoot(), 0.0);
    Mockito.verifyNoInteractions(function);
  }

  @Test
  void findRoot_whenMaxIterIsZero_returnsFalseAndLeavesRootUnchanged() throws Exception {
    // Arrange
    BrentSolver solver = new BrentSolver();
    ComputableFunction function = Mockito.mock(ComputableFunction.class);
    ConvergenceChecker checker = (xLow, fLow, xHigh, fHigh) -> ConvergenceChecker.NONE;

    double x0 = 0.0;
    double x1 = 1.0;

    // Act
    boolean found = solver.findRoot(function, checker, 0, x0, -1.0, x1, 1.0);

    // Assert
    assertFalse(found);
    assertTrue(Double.isNaN(solver.getRoot()));
    Mockito.verifyNoInteractions(function);
  }

  @Test
  void findRoot_whenFunctionThrowsDuringIteration_propagatesFunctionException() throws Exception {
    // Arrange
    BrentSolver solver = new BrentSolver();
    ComputableFunction function = Mockito.mock(ComputableFunction.class);
    ConvergenceChecker checker = Mockito.mock(ConvergenceChecker.class);
    Mockito.when(
            checker.converged(
                Mockito.anyDouble(), Mockito.anyDouble(), Mockito.anyDouble(), Mockito.anyDouble()))
        .thenReturn(ConvergenceChecker.NONE);

    double x0 = 0.0;
    double x1 = 2.0;
    double f0 = -1.0;
    double f1 = 1.0;

    Mockito.when(function.valueAt(Mockito.anyDouble())).thenThrow(new FunctionException("boom"));

    // Act + Assert
    assertThrows(
        FunctionException.class, () -> solver.findRoot(function, checker, 5, x0, f0, x1, f1));

    Mockito.verify(checker, Mockito.atLeastOnce())
        .converged(
            Mockito.anyDouble(), Mockito.anyDouble(), Mockito.anyDouble(), Mockito.anyDouble());
  }

  @Test
  void findRoot_whenBracketContainsRoot_convergesToExpectedValue() throws Exception {
    // Arrange
    BrentSolver solver = new BrentSolver();
    ComputableFunction function = x -> x * x - 2.0;
    ConvergenceChecker checker = (xLow, fLow, xHigh, fHigh) -> ConvergenceChecker.NONE;

    double x0 = 0.0;
    double x1 = 2.0;
    double f0 = function.valueAt(x0);
    double f1 = function.valueAt(x1);

    // Act
    boolean found = solver.findRoot(function, checker, 100, x0, f0, x1, f1);

    // Assert
    assertTrue(found);
    double root = solver.getRoot();
    assertTrue(root >= x0 && root <= x1);
    assertEquals(0.0, function.valueAt(root), 1.0e-12);
    assertEquals(Math.sqrt(2.0), root, 1.0e-10);
  }

  @Test
  void findRoot_whenNonlinearFunction_convergesToFixedPointRoot() throws Exception {
    // Arrange
    BrentSolver solver = new BrentSolver();
    ComputableFunction function = x -> Math.cos(x) - x;
    ConvergenceChecker checker = (xLow, fLow, xHigh, fHigh) -> ConvergenceChecker.NONE;

    double x0 = 0.0;
    double x1 = 1.0;
    double f0 = function.valueAt(x0);
    double f1 = function.valueAt(x1);

    // Act
    boolean found = solver.findRoot(function, checker, 200, x0, f0, x1, f1);

    // Assert
    assertTrue(found);
    double root = solver.getRoot();
    assertEquals(0.0, function.valueAt(root), 1.0e-12);
    assertEquals(0.7390851332, root, 1.0e-9);
  }
}
