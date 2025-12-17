package network.crypta.pluginmanager;

import java.io.Serial;

/**
 * Signals that a requested plugin is known but cannot be used because it is too old for the current
 * node or required plugin API level.
 *
 * <p>This exception is a specialization of {@link PluginNotFoundException} used to communicate a
 * specific kind of negative lookup result: the plugin is effectively "not found" for the purposes
 * of the requested operation because it does not meet minimum compatibility requirements. It is
 * typically thrown during plugin resolution or load paths that first locate plugin metadata and
 * then enforce version or build constraints before proceeding.
 *
 * <p>The instance carries only a detail message (and optionally a cause via the superclass APIs).
 * Callers should include enough context in the message to support diagnostics, such as which plugin
 * was requested and which constraint was violated, without assuming a particular formatting or UI.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Distinguishes "present but incompatible" from "unknown plugin" for callers that care.
 *   <li>Does not prescribe remediation; the caller decides whether to update, disable, or ignore.
 *   <li>Retrying is not expected to succeed unless plugin versions or constraints change.
 * </ul>
 */
public class PluginTooOldException extends PluginNotFoundException {

  @Serial private static final long serialVersionUID = -3104024342634046289L;

  /**
   * Creates an exception indicating that the located plugin is too old for the requested operation.
   *
   * <p>The provided message should describe the incompatibility in terms meaningful to operators or
   * logs. When possible, include the plugin identifier and the relevant constraint (for example, a
   * minimum required version/build) as plain text. The message is passed to the superclass and does
   * not influence control flow beyond classifying the failure mode.
   *
   * @param string the detail message describing the incompatibility; may be {@code null} if unknown
   */
  public PluginTooOldException(String string) {
    super(string);
  }
}
