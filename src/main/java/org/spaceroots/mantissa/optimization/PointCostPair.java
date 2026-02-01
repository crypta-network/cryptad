package org.spaceroots.mantissa.optimization;

import java.util.Arrays;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Immutable pair that groups a point in the optimization search space with the cost value computed
 * at that point.
 *
 * <p>The value object is used throughout direct-search optimizers to shuttle candidate vertices
 * between the cost function, convergence checker, and simplex maintenance code. Instances are
 * created as soon as a coordinate array is available, and the cost field may be pre-populated or
 * filled in later by the optimizer. The contained point array is defensively copied on
 * construction, keeping subsequent optimizer steps insulated from caller mutations and preserving
 * deterministic behavior. Values are intended to be read frequently and never mutated, so sharing
 * references to instances is safe as long as the object itself is not replaced. The type is
 * thread-safe for read-only sharing because it exposes no setters and its state does not change
 * after creation.
 *
 * <ul>
 *   <li>Holds the {@code point} coordinates and the scalar {@code cost} for that location.
 *   <li>Supports value-style equality that compares array contents rather than references.
 *   <li>Provides a concise {@link #toString()} for diagnostics and logging of optimizer steps.
 * </ul>
 *
 * @author Luc Maisonobe
 * @version $Id: PointCostPair.java 1709 2006-12-03 21:16:50Z luc $
 * @see CostFunction
 */
public final class PointCostPair {
  private final double[] point;
  private final double cost;

  /**
   * Build a point/cost pair by defensively copying the supplied coordinates and associating them
   * with a scalar cost.
   *
   * <p>This constructor accepts a point array that defines the location in the objective function
   * domain and the cost value currently known for that location. The array is cloned so that later
   * mutations performed by callers cannot leak into optimizer state. Callers may pass {@link
   * Double#NaN} as the cost when the value is not yet available; optimizers typically evaluate and
   * replace that placeholder during simplex processing. A {@code null} point is not permitted and
   * results in a {@link NullPointerException}.
   *
   * @param point point coordinates expressed as finite doubles; must be non-{@code null} and is
   *     defensively copied to protect internal immutability
   * @param cost cost associated with the point, or {@code Double.NaN} when not yet evaluated;
   *     callers retain responsibility for ensuring numeric validity
   * @throws NullPointerException if {@code point} is {@code null} or contains elements that cannot
   *     be accessed during cloning
   */
  public PointCostPair(double[] point, double cost) {
    this.point = point.clone();
    this.cost = cost;
  }

  public double[] point() {
    return point;
  }

  public double cost() {
    return cost;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof PointCostPair pair)) {
      return false;
    }
    return Double.compare(cost, pair.cost) == 0 && Arrays.equals(point, pair.point);
  }

  @Override
  public int hashCode() {
    return Objects.hash(Arrays.hashCode(point), Double.doubleToLongBits(cost));
  }

  @Override
  public @NotNull String toString() {
    return "PointCostPair[point=" + Arrays.toString(point) + ", cost=" + cost + ']';
  }
}
