package network.crypta.node;

/**
 * Console bridge used by the Text Mode Client Interface.
 *
 * <p>This package-private utility centralizes all interactions with the JVM's standard input and
 * output streams for the Text Mode Client Interface (TMCI). By funnelling reads and writes through
 * a single indirection, adjacent classes can keep their logging concerns separate from console
 * emission while still reusing the process console when appropriate. This class does not perform
 * buffering, framing, or transformation; it simply exposes the underlying {@link System} streams in
 * a minimal, dependency-free manner. The design intentionally avoids adding higher-level semantics
 * so that higher layers (such as {@code TextModeClientInterfaceServer}) retain full control over
 * protocol formatting, lifecycles, and threading.
 *
 * <p>Thread-safety: the returned streams are the JVM's globally shared standard streams. Their
 * effective thread-safety and lifetime are governed by the JVM and any caller coordination. This
 * class itself holds no mutable state and is therefore thread-safe. Mutability: callers obtain live
 * references to {@code System.in} and {@code System.out}; if those are reassigned elsewhere in the
 * process, subsequent calls will reflect the new targets.
 */
@SuppressWarnings("java:S106")
class TextModeClientInterfaceConsole {
  /** Prevents instantiation. */
  private TextModeClientInterfaceConsole() {}

  /**
   * Prints a single line to the process' standard output.
   *
   * <p>This helper writes the given message followed by the platform line separator using {@link
   * System#out}. It performs no formatting or escaping, and it does not synchronize beyond what
   * {@code PrintStream} already provides. Callers should avoid printing sensitive information and
   * should consider structured logging for diagnostic output.
   *
   * @param message the text to emit to standard output; {@code null} is printed as the literal
   *     string {@code "null"} per {@link java.io.PrintStream#println(String)} semantics
   */
  static void print(String message) {
    System.out.println(message);
  }

  /**
   * Returns the current process standard input stream.
   *
   * <p>The returned reference is the live value of {@link System#in} at call time. It may change if
   * the process reassigns {@code System.in} later. The stream is not wrapped, and ownership remains
   * with the JVM; callers must not close it unless they explicitly manage the entire process I/O
   * lifecycle.
   *
   * @return a live reference to {@link System#in}; do not close, buffer, or block indefinitely
   *     without considering process-wide impact
   */
  static java.io.InputStream in() {
    return System.in;
  }

  /**
   * Returns the current process standard output stream.
   *
   * <p>The returned reference is the live value of {@link System#out} at call time. It may change
   * if the process reassigns {@code System.out} later. The stream is not wrapped, and ownership
   * remains with the JVM; callers should not close it. Prefer higher-level logging for diagnostic
   * events.
   *
   * @return a live reference to {@link System#out}; do not close and avoid mixing with structured
   *     logs unless intentional
   */
  static java.io.PrintStream out() {
    return System.out;
  }
}
