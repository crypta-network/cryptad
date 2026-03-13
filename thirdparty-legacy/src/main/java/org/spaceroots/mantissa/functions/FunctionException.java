package org.spaceroots.mantissa.functions;

import java.io.Serial;
import org.spaceroots.mantissa.MantissaException;

/**
 * Signals failures that occur while evaluating or preparing scalar or vector functions.
 *
 * <p>The exception acts as the common transport for user-visible errors in the functions package.
 * Callers typically throw it when an argument violates a domain constraint, when evaluation cannot
 * converge, or when a lower-level numerical routine reports an unrecoverable problem. The class
 * extends {@link MantissaException} so messages can be localized and parameterized without forcing
 * callers to build formatted strings eagerly. Instances are immutable and therefore safe to share
 * across threads once created.
 *
 * <p>Typical usage is to raise the exception close to the detection site, optionally supplying a
 * cause so that diagnostic chains remain intact. Consumers can inspect the message parts inherited
 * from {@code MantissaException} to build structured error reports without re-formatting raw text.
 * Example:
 *
 * <pre>{@code
 * // Example: wrap a numerical failure with a localized message key
 * throw new FunctionException("function.non.convergent", new String[] {functionName});
 * }</pre>
 *
 * <ul>
 *   <li>Captures translated message specifiers and dynamic parts for deferred formatting.
 *   <li>Provides constructors for raw messages or chained exceptions.
 *   <li>Does not alter control flow semantics; it only enriches error reporting.
 * </ul>
 *
 * @version $Id: FunctionException.java 1686 2005-12-16 12:59:51Z luc $
 * @author L. Maisonobe
 */
public class FunctionException extends MantissaException {

  /**
   * Builds an exception whose message is produced from a translated format string.
   *
   * <p>Use this constructor when the message should be localized and composed lazily. The {@code
   * specifier} is resolved by {@link MantissaException} against the configured translation
   * resources, and {@code parts} are inserted verbatim into the resulting format. Neither argument
   * is modified, and the resulting exception remains immutable after construction.
   *
   * @param specifier translation key or format specifier describing the error condition; must not
   *     be {@code null} and should match a resource bundle entry.
   * @param parts ordered substitution values inserted into the translated format; may be empty but
   *     must not be {@code null} when formatting expects arguments.
   */
  public FunctionException(String specifier, String[] parts) {
    super(specifier, parts);
  }

  /**
   * Builds an exception from a single message that will be translated if possible.
   *
   * <p>This variant is convenient when the error text is already complete or when no dynamic parts
   * are needed. The message is passed to {@link MantissaException}, which will attempt localization
   * according to the project-wide resource configuration. The instance is immutable and thread-safe
   * after construction.
   *
   * @param message human-readable error description or translation key; should be non-empty and
   *     meaningful to the caller or user interface.
   */
  public FunctionException(String message) {
    super(message);
  }

  /**
   * Builds an exception that wraps an underlying cause while preserving its stack trace.
   *
   * <p>Select this constructor when an upstream component throws an exception that should propagate
   * as a function-level failure. The cause is recorded for later inspection through standard
   * exception chaining APIs, allowing diagnostics to retain full context. No message translation is
   * performed unless the cause supplies one.
   *
   * @param cause originating throwable that triggered the failure; may be {@code null} when the
   *     caller prefers to defer message creation to higher layers.
   */
  public FunctionException(Throwable cause) {
    super(cause);
  }

  @Serial private static final long serialVersionUID = 1455885104381976115L;
}
