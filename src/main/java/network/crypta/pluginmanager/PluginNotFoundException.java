package network.crypta.pluginmanager;

import java.io.Serial;

/**
 * Signals that a requested plugin could not be found during plugin management operations.
 *
 * <p>This exception is thrown when the plugin manager is asked to resolve, load, or otherwise
 * operate on a plugin identifier that does not map to a known plugin. It represents an absence of a
 * plugin rather than a failure while executing a plugin action; callers should treat it as a
 * negative lookup result and decide whether to report the missing plugin, fall back to a default,
 * or abort the requested operation.
 *
 * <p>The exception is immutable after construction and carries only the standard {@link Exception}
 * state (message and optional cause). It does not capture a structured plugin key; if additional
 * context is needed, supply a descriptive message when constructing the exception.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Represents a missing plugin at lookup time, not an invalid plugin lifecycle state.
 *   <li>Does not imply retry will succeed unless the plugin registry changes.
 *   <li>May wrap a lower-level cause when the lookup process itself fails.
 * </ul>
 */
public class PluginNotFoundException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception indicating that a plugin could not be found.
   *
   * <p>This constructor produces an instance without a detail message or explicit cause. It is
   * suitable when the missing-plugin condition is handled internally and the caller does not need
   * to surface a user-facing explanation. When higher-level reporting is desired, prefer a
   * constructor that accepts a message so the missing plugin identifier can be included.
   */
  public PluginNotFoundException() {
    super();
  }

  /**
   * Creates an exception indicating that a plugin could not be found, with a detail message.
   *
   * <p>The provided message should describe what was being looked up (for example, a plugin name,
   * class name, or other identifier) and, when helpful, the context of the lookup. The message is
   * forwarded to the superclass and is intended for logs or user-visible diagnostics; it does not
   * affect control flow beyond identifying the failure mode.
   *
   * @param arg0 the detail message describing the missing plugin; may be {@code null} if unknown
   */
  public PluginNotFoundException(String arg0) {
    super(arg0);
  }

  /**
   * Creates an exception indicating that a plugin could not be found, with a message and cause.
   *
   * <p>Use this constructor when the missing-plugin condition is discovered while handling another
   * failure that should be preserved for debugging, such as an I/O error while reading plugin
   * metadata. The supplied message typically names the plugin being searched for, while the cause
   * captures the underlying exception that prevented a successful lookup.
   *
   * @param arg0 the detail message describing the missing plugin and lookup context; may be {@code
   *     null} if no additional description is available
   * @param arg1 the underlying cause to retain for diagnostics; may be {@code null} when none
   *     exists
   */
  public PluginNotFoundException(String arg0, Throwable arg1) {
    super(arg0, arg1);
  }

  /**
   * Creates an exception indicating that a plugin could not be found, wrapping an underlying cause.
   *
   * <p>This constructor is appropriate when the primary information is the originating failure, and
   * a separate human-readable message is not necessary or is already included by the cause. The
   * supplied throwable is forwarded to the superclass; callers may still add additional context by
   * using the message-and-cause constructor instead.
   *
   * @param arg0 the underlying cause of the lookup failure; may be {@code null} if unknown
   */
  public PluginNotFoundException(Throwable arg0) {
    super(arg0);
  }
}
