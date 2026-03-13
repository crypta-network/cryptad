package org.spaceroots.mantissa.ode;

import java.io.Serial;
import org.spaceroots.mantissa.MantissaException;

/**
 * Signals problems detected while performing numerical ordinary differential equation integration.
 *
 * <p>Instances of this exception are created by integrator implementations when a configuration or
 * runtime issue prevents forward progress, such as inconsistent step configuration, user callbacks
 * that refuse a step, or an internal computation failure reported by lower-level components. The
 * exception preserves the original, localized message specifier and inserts, allowing callers to
 * present meaningful diagnostics to end users or logs without losing structured context.
 *
 * <p>Typical usage occurs in client code that executes an {@code Integrator} and wraps the call in
 * a try/catch block to surface the failure reason and decide whether to retry with adjusted
 * tolerances, reduce step sizes, or abort the overall computation. The class itself is immutable
 * and thread-safe to share across threads when propagating errors through asynchronous task
 * pipelines.
 *
 * <ul>
 *   <li>Responsibilities: carry translated integration error messages up the call chain.
 *   <li>Notable behavior: retains format specifier and raw parts for deferred localization.
 *   <li>Concurrency: safe for concurrent reads; instances are never modified after creation.
 * </ul>
 *
 * @author Luc Maisonobe
 * @version $Id: IntegratorException.java 1686 2005-12-16 12:59:51Z luc $
 * @see MantissaException
 */
public class IntegratorException extends MantissaException {

  /**
   * Builds an integration exception using a translatable message template and raw arguments.
   *
   * <p>The constructor stores both the specifier and its unlocalized parts so that higher layers
   * can format the final message lazily using the caller's locale or log formatting rules. Callers
   * typically pass a message key defined by the integration module along with any contextual values
   * (step size, current time, state vector dimension, and so on) that will be merged into the
   * template. The resulting instance is immutable and can be safely re-thrown across threads when
   * executing integration tasks in parallel pools.
   *
   * @param specifier translation key describing the integration failure message template.
   * @param parts unlocalized insertion values aligned with the specifier placeholders.
   */
  public IntegratorException(String specifier, String[] parts) {
    super(specifier, parts);
  }

  @Serial private static final long serialVersionUID = -1390328069787882608L;
}
