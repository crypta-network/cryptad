package org.spaceroots.mantissa.quadrature.vectorial;

import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.ComputableFunction;

/**
 * Integrates vector-valued functions over a finite interval using an implementation-specific
 * quadrature scheme.
 *
 * <p>This interface defines the contract implemented by numerical integrators that evaluate a
 * {@link ComputableFunction} between two real bounds and return the accumulated area for every
 * component. Typical usage creates an integrator tuned for accuracy or performance, then invokes
 * {@link #integrate(ComputableFunction, double, double)} with a function that reports its own
 * dimensionality and provides component values on demand. Implementations may adapt step sizes,
 * reuse scratch buffers, or allocate per call, but they all guarantee that the returned vector
 * corresponds to the definite integral from {@code a} to {@code b}, preserving sign when the bounds
 * are reversed. Unless stated otherwise by a concrete class, instances are not guaranteed to be
 * thread-safe; prefer one integrator per concurrent integration task to avoid a shared mutable
 * state. Callers remain responsible for ensuring that the supplied function is side-effect free or
 * otherwise safe to sample repeatedly.
 *
 * <ul>
 *   <li>Delegates evaluation to the provided {@link ComputableFunction} without altering its state.
 *   <li>Supports integration in either direction; negative orientation yields negated results.
 *   <li>Returns a fresh array holding one accumulated value per function component.
 * </ul>
 *
 * @see ComputableFunction
 * @version $Id: ComputableFunctionIntegrator.java 1231 2002-03-12 20:07:04Z luc $
 * @author L. Maisonobe
 */
public interface ComputableFunctionIntegrator {
  /**
   * Compute the definite integral of a vector function between two real bounds.
   *
   * <p>The integrator samples the supplied {@link ComputableFunction} as needed, accumulating one
   * scalar integral per component and returning all results in a new array. The orientation of the
   * integral follows standard calculus rules: if {@code a > b} the outcome is the negated integral
   * of {@code [b, a]}. Implementations may choose adaptive or fixed-step strategies and may invoke
   * the function many times; callers should ensure that repeated evaluations are inexpensive and
   * free from side effects that would distort numerical accuracy.
   *
   * <pre>{@code
   * ComputableFunction f = ...;
   * double[] area = integrator.integrate(f, 0.0, 1.0);
   * }</pre>
   *
   * @param f function to integrate; must expose dimension and support repeated evaluations without
   *     mutation-sensitive side effects
   * @param a initial abscissa of the integration interval; may exceed {@code b} to request reversed
   *     orientation
   * @param b terminal abscissa of the integration interval; may be lower than {@code a} for
   *     negative orientation
   * @return array containing one integrated value per component; length matches {@code f}
   *     dimensionality and ownership is transferred to the caller
   * @throws FunctionException if evaluating the supplied function fails or signals an unrecoverable
   *     condition during integration
   */
  double[] integrate(ComputableFunction f, double a, double b) throws FunctionException;
}
