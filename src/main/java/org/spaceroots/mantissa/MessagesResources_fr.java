package org.spaceroots.mantissa;

import java.util.ListResourceBundle;

/**
 * Resource bundle that provides localized French message strings for the Mantissa library.
 *
 * <p>This class is the French {@link java.util.ResourceBundle} for Mantissa. It supplies a fixed
 * mapping from message keys to human‑readable text used across the library for exceptions and
 * user‑facing diagnostics. Mantissa loads the bundle through the standard {@code
 * ResourceBundle.getBundle(...)} mechanism; because this implementation extends {@link
 * java.util.ListResourceBundle}, the data is expressed as a two‑dimensional {@code Object[][]} of
 * key/value pairs.
 *
 * <p>The bundle is effectively stateless: all entries are stored in the static {@link #contents}
 * array. Instances are safe to share between threads for read‑only use. Callers should treat the
 * returned contents as immutable; while {@link #getContents()} returns a clone of the outer array,
 * the clone is shallow and does not protect the inner key/value rows from mutation.
 *
 * <ul>
 *   <li>Defines the French translation for Mantissa’s canonical message keys.
 *   <li>Uses the same keys as the default bundle, so formatting stays consistent.
 *   <li>Serves as the locale‑specific bundle selected when {@code Locale.FRENCH} is active.
 * </ul>
 *
 * @version $Id: MessagesResources_fr.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see java.util.ResourceBundle
 * @see java.util.ListResourceBundle
 */
@SuppressWarnings("unused")
public class MessagesResources_fr extends ListResourceBundle {

  /**
   * Creates a new French resource bundle instance.
   *
   * <p>This constructor performs no initialization beyond what the superclass requires. It exists
   * solely to satisfy the {@link java.util.ResourceBundle} contract, which mandates a public
   * no‑argument constructor so bundles can be instantiated reflectively by the runtime. All message
   * data is defined in the static {@link #contents} array, so constructing instances is cheap and
   * side‑effect free.
   */
  public MessagesResources_fr() {
    // Intentionally empty: ListResourceBundle instances are created reflectively by the
    // ResourceBundle machinery and require a public no-arg constructor, but all actual
    // data lives in the static `contents` array.
  }

  /**
   * Returns the key/value pairs that make up this bundle.
   *
   * <p>The returned array follows the {@link java.util.ListResourceBundle} convention where each
   * row is a two‑element array containing a {@link String} key and its corresponding French message
   * text. This method clones the outer {@code Object[][]} to prevent callers from replacing the
   * bundle’s top‑level table, but it does not deep‑copy the inner rows. As a result, callers must
   * not mutate the elements of the returned structure.
   *
   * @return a shallow clone of the bundle’s contents table, intended for read‑only iteration.
   */
  public Object[][] getContents() {
    return contents.clone();
  }

  /**
   * Static table of message key/value pairs for the French locale.
   *
   * <p>Each entry is a two‑element array of {@code String} key and {@code String} French
   * translation. The set of keys matches the default bundle exactly to ensure that formatting
   * parameters and lookup behavior remain compatible across locales.
   */
  static final Object[][] contents = {

    // org.spaceroots.mantissa.estimation.GaussNewtonEstimator
    {"unable to converge in {0} iterations", "pas de convergence après {0} itérations"},

    // org.spaceroots.mantissa.estimation.LevenbergMarquardtEstimator
    {
      "cost relative tolerance is too small ({0}), no further reduction in the sum of squares is"
          + " possible",
      "trop petite tolérance relative sur le coût ({0}), aucune réduction de la"
          + " somme des carrés n''est possible"
    },
    {
      "parameters relative tolerance is too small ({0}), no further improvement in the approximate"
          + " solution is possible",
      "trop petite tolérance relative sur les paramètres ({0}), aucune amélioration"
          + " de la solution approximative n''est possible"
    },
    {
      "orthogonality tolerance is too small ({0}), solution is orthogonal to the jacobian",
      "trop petite tolérance sur l''orthogonalité ({0}), la solution est orthogonale"
          + " à la jacobienne"
    },
    {"maximal number of evaluations exceeded ({0})", "nombre maximal d''évaluations dépassé ({0})"},

    // org.spaceroots.mantissa.fitting.HarmonicCoefficientsGuesser
    {"unable to guess a first estimate", "impossible de trouver une première estimée"},

    // org.spaceroots.mantissa.fitting.HarmonicFitter
    {"sample must contain at least {0} points", "l''échantillon doit contenir au moins {0} points"},

    // org.spaceroots.mantissa.functions.ExhaustedSampleException
    {"sample contains only {0} elements", "l''échantillon ne contient que {0} points"},

    // org.spaceroots.mantissa.geometry.CardanEulerSingularityException
    {"Cardan angles singularity", "singularité d''angles de Cardan"},
    {"Euler angles singularity", "singularité d''angles d''Euler"},

    // org.spaceroots.mantissa.geometry.Rotation
    {
      "a {0}x{1} matrix cannot be a rotation matrix",
      "une matrice {0}x{1} ne peut pas étre une matrice de rotation"
    },
    {
      "the closest orthogonal matrix has a negative determinant {0}",
      "la matrice orthogonale la plus proche a un déterminant négatif {0}"
    },
    {
      "unable to orthogonalize matrix in {0} iterations",
      "impossible de rendre la matrice orthogonale en {0} itérations"
    },

    // org.spaceroots.mantissa.linalg;.SingularMatrixException
    {"singular matrix", "matrice singulière"},

    // org.spaceroots.mantissa.ode.AdaptiveStepsizeIntegrator
    {
      "minimal step size ({0}) reached, integration needs {1}",
      "pas minimal ({0}) atteint, l''intégration nécessite {1}"
    },

    // org.spaceroots.mantissa.ode.GraggBulirschStoerIntegrator,
    // org.spaceroots.mantissa.ode.RungeKuttaFehlbergIntegrator,
    // org.spaceroots.mantissa.ode.RungeKuttaIntegrator
    {
      "dimensions mismatch: ODE problem has dimension {0}," + " state vector has dimension {1}",
      "incompatibilité de dimensions entre le problème ODE ({0})," + " et le vecteur d''état ({1})"
    },
    {"too small integration interval: length = {0}", "intervalle d''intégration trop petit : {0}"},

    // org.spaceroots.mantissa.optimization.DirectSearchOptimizer
    {
      "none of the {0} start points lead to convergence",
      "aucun des {0} points de départ n''aboutit à une convergence"
    },

    // org.spaceroots.mantissa.random.CorrelatedRandomVectorGenerator
    {"dimension mismatch {0} != {1}", "dimensions incompatibles {0} != {1}"},

    // org.spaceroots.mantissa.random.NotPositiveDefiniteMatrixException
    {"not positive definite matrix", "matrice non définie positive"}
  };
}
