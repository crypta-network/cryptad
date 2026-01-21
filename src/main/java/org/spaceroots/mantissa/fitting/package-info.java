/**
 * This package provides classes to perform curve fitting.
 *
 * <p>Curve fitting is a special case of an {@link
 * org.spaceroots.mantissa.estimation.EstimationProblem estimation problem} were the parameters are
 * the coefficients of a function <code>f</code> whose graph <code>y=f(x)</code> should pass through
 * sample points, and were the measurements are the ordinates of the curve <code>yi=f(xi)</code>.
 *
 * <p>The organization of this package is explained in the class diagram below. The {@link
 * org.spaceroots.mantissa.fitting.AbstractCurveFitter AbstractCurveFitter} class is the base class
 * for all curve fitting classes, it handles all common features like sample points handling. Each
 * curve fitting class should subclass this abstract class and implement the {@link
 * org.spaceroots.mantissa.fitting.AbstractCurveFitter#valueAt valueAt} and {@link
 * org.spaceroots.mantissa.fitting.AbstractCurveFitter#partial partial} methods. <img
 * src="doc-files/org_spaceroots_mantissa_fitting_classes.png" />
 *
 * @author L. Maisonobe
 */
package org.spaceroots.mantissa.fitting;
