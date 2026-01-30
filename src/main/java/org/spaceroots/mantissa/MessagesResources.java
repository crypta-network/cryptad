package org.spaceroots.mantissa;

import java.util.ListResourceBundle;

/**
 * Resource bundle that provides localized message strings for the Mantissa library.
 *
 * <p>This class is the default {@link java.util.ResourceBundle} for Mantissa. It supplies a fixed
 * mapping from message keys to human‑readable text used across the library for exceptions and
 * user‑facing diagnostics. Mantissa loads the bundle through the standard {@code
 * ResourceBundle.getBundle(...)} mechanism, and because this implementation extends {@link
 * java.util.ListResourceBundle} the data is expressed as a two‑dimensional {@code Object[][]} of
 * key/value pairs.
 *
 * <p>The bundle is effectively stateless: all entries are stored in the static {@link #contents}
 * array. Instances are safe to share between threads for read‑only use. Callers should treat the
 * returned contents as immutable; while {@link #getContents()} returns a clone of the outer array,
 * the clone is shallow and does not protect the inner key/value rows from mutation.
 *
 * <ul>
 *   <li>Defines the canonical set of message keys for Mantissa.
 *   <li>Provides default (English) text for each key.
 *   <li>Acts as the fallback bundle when no locale‑specific bundle is present.
 * </ul>
 *
 * @version $Id: MessagesResources.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see java.util.ResourceBundle
 * @see java.util.ListResourceBundle
 */
@SuppressWarnings("unused")
public class MessagesResources extends ListResourceBundle {

  /**
   * Creates a new resource bundle instance.
   *
   * <p>This constructor performs no initialization beyond what the superclass requires. It exists
   * solely to satisfy the {@link java.util.ResourceBundle} contract, which mandates a public
   * no‑argument constructor so bundles can be instantiated reflectively by the runtime. All message
   * data is defined in the static {@link #contents} array, so constructing instances is cheap and
   * side‑effect free.
   */
  public MessagesResources() {
    // Intentionally empty: ListResourceBundle requires a public no-arg constructor,
    // and this bundle is fully defined by the static {@code contents} array.
  }

  /**
   * Returns the key/value pairs that make up this bundle.
   *
   * <p>The returned array follows the {@link java.util.ListResourceBundle} convention where each
   * row is a two‑element array containing a {@link String} key and its corresponding message text.
   * This method clones the outer {@code Object[][]} to prevent callers from replacing the bundle’s
   * top‑level table, but it does not deep‑copy the inner rows. As a result, callers must not mutate
   * the elements of the returned structure.
   *
   * @return a shallow clone of the bundle’s contents table, intended for read‑only iteration.
   */
  @Override
  public Object[][] getContents() {
    return contents.clone();
  }

  /**
   * Static table of message key/value pairs for the default locale.
   *
   * <p>Each entry is a two‑element array of {@code String} key and {@code String} message. The
   * second element currently mirrors the key for all entries, representing the default English text
   * used when no translation is available.
   */
  static final Object[][] contents = {

    // org.spaceroots.mantissa.estimation.GaussNewtonEstimator
    {"unable to converge in {0} iterations", "unable to converge in {0} iterations"},

    // org.spaceroots.mantissa.estimation.LevenbergMarquardtEstimator
    {
      "cost relative tolerance is too small ({0}), no further reduction in the sum of squares is"
          + " possible",
      "cost relative tolerance is too small ({0}), no further reduction in the sum of squares is"
          + " possible"
    },
    {
      "parameters relative tolerance is too small ({0}), no further improvement in the approximate"
          + " solution is possible",
      "parameters relative tolerance is too small ({0}), no further improvement in the approximate"
          + " solution is possible"
    },
    {
      "orthogonality tolerance is too small ({0}), solution is orthogonal to the jacobian",
      "orthogonality tolerance is too small ({0}), solution is orthogonal to the jacobian"
    },
    {
      "maximal number of evaluations exceeded ({0})", "maximal number of evaluations exceeded ({0})"
    },

    // org.spaceroots.mantissa.fitting.HarmonicCoefficientsGuesser
    {"unable to guess a first estimate", "unable to guess a first estimate"},

    // org.spaceroots.mantissa.fitting.HarmonicFitter
    {"sample must contain at least {0} points", "sample must contain at least {0} points"},

    // org.spaceroots.mantissa.functions.ExhaustedSampleException
    {"sample contains only {0} elements", "sample contains only {0} elements"},

    // org.spaceroots.mantissa.geometry.CardanEulerSingularityException
    {"Cardan angles singularity", "Cardan angles singularity"},
    {"Euler angles singularity", "Euler angles singularity"},

    // org.spaceroots.mantissa.geometry.Rotation
    {
      "a {0}x{1} matrix cannot be a rotation matrix", "a {0}x{1} matrix cannot be a rotation matrix"
    },
    {
      "the closest orthogonal matrix has a negative determinant {0}",
      "the closest orthogonal matrix has a negative determinant {0}"
    },
    {
      "unable to orthogonalize matrix in {0} iterations",
      "unable to orthogonalize matrix in {0} iterations"
    },

    // org.spaceroots.mantissa.linalg;.SingularMatrixException
    {"singular matrix", "singular matrix"},

    // org.spaceroots.mantissa.ode.AdaptiveStepsizeIntegrator
    {
      "minimal step size ({0}) reached, integration needs {1}",
      "minimal step size ({0}) reached, integration needs {1}"
    },

    // org.spaceroots.mantissa.ode.GraggBulirschStoerIntegrator,
    // org.spaceroots.mantissa.ode.RungeKuttaFehlbergIntegrator,
    // org.spaceroots.mantissa.ode.RungeKuttaIntegrator
    {
      "dimensions mismatch: ODE problem has dimension {0}," + " state vector has dimension {1}",
      "dimensions mismatch: ODE problem has dimension {0}," + " state vector has dimension {1}"
    },
    {
      "too small integration interval: length = {0}", "too small integration interval: length = {0}"
    },

    // org.spaceroots.mantissa.optimization.DirectSearchOptimizer
    {
      "none of the {0} start points lead to convergence",
      "none of the {0} start points lead to convergence"
    },

    // org.spaceroots.mantissa.random.CorrelatedRandomVectorGenerator
    {"dimension mismatch {0} != {1}", "dimension mismatch {0} != {1}"},

    // org.spaceroots.mantissa.random.NotPositiveDefiniteMatrixException
    {"not positive definite matrix", "not positive definite matrix"}
  };
}
