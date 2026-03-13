package org.spaceroots.mantissa.ode;

import java.io.Serial;
import org.spaceroots.mantissa.MantissaException;

/**
 * Reports failures that occur while evaluating user-provided differential equations during an
 * integration step.
 *
 * <p>This exception is thrown when a user callback that provides first-order derivatives fails in a
 * way that prevents the integrator from continuing. Typical triggers include arithmetic errors,
 * domain violations in the underlying model, or detected inconsistencies in the state supplied to
 * the derivative function. Library callers generally rethrow the original cause to preserve stack
 * traces while converting it into this type so the ODE framework can surface a predictable failure
 * contract. Instances are lightweight, immutable, and safe to share between threads when the
 * underlying cause is also thread-safe to inspect.
 *
 * <p>Use this class when you need to interrupt an integration run from within a derivative
 * computation and want the caller to receive a domain-specific exception rather than a generic
 * runtime failure. Integrators typically catch it, log or propagate it, and abort further steps to
 * avoid returning partial or invalid results.
 *
 * <ul>
 *   <li>Provides a formatted, localized message through {@link MantissaException} support.
 *   <li>Accepts an underlying cause to retain low-level diagnostics.
 *   <li>Designed for deterministic, repeatable error handling inside ODE solvers.
 * </ul>
 *
 * @author Luc Maisonobe
 * @version $Id: DerivativeException.java 1695 2006-09-03 19:59:05Z luc $
 */
public class DerivativeException extends MantissaException {

  /**
   * Creates an exception with a localized, formatted message describing the derivative failure.
   *
   * <p>This constructor is intended for situations where the caller wants to control the
   * human-readable message shown to higher layers. The {@code specifier} is looked up in the
   * resource bundle managed by {@link MantissaException}, and the provided {@code parts} are
   * interpolated into the translated pattern. The resulting message is immutable and safe to read
   * from any thread. Use this form when you have structured context values and do not need to
   * capture a throwable cause.
   *
   * <pre>{@code
   * // Example: surface a units-related validation error
   * throw new DerivativeException("integration.error.units", new String[] {unitName});
   * }</pre>
   *
   * @param specifier message key resolved through internationalization resources; must not be
   *     {@code null} and should identify a concrete error template
   * @param parts untranslatable context values inserted into the formatted message; the array may
   *     be empty but should not contain {@code null} elements
   */
  public DerivativeException(String specifier, String[] parts) {
    super(specifier, parts);
  }

  /**
   * Builds an exception that wraps an underlying cause raised during derivative evaluation.
   *
   * <p>This variant preserves the triggering throwable so downstream handlers can inspect the
   * original stack trace and type while still receiving a domain-specific wrapper understood by the
   * ODE integrators. The message is automatically derived from the cause unless additional
   * formatting is added later by callers. The resulting instance is immutable and can be reused or
   * rethrown across thread boundaries when the wrapped cause allows concurrent inspection.
   *
   * @param cause originating problem encountered while computing the derivative; may be any checked
   *     or unchecked exception and is stored as-is for diagnostic purposes
   */
  public DerivativeException(Throwable cause) {
    super(cause);
  }

  @Serial private static final long serialVersionUID = -4100440615830558122L;
}
