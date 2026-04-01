package network.crypta.node;

import java.io.Serial;
import network.crypta.config.ConfigExitCodes;

/**
 * Reports an early node startup failure with an associated process exit code.
 *
 * <p>Throw this exception when initialization cannot proceed, and the launcher or wrapper should
 * terminate the JVM with a deterministic exit status. Use one of the {@code EXIT_*} constants to
 * classify the failure. The chosen code is also exposed via {@link #exitCode} for programmatic
 * handling. Instances are immutable and thread-safe.
 */
public class NodeInitException extends Exception {
  public final int exitCode;

  /** Misconfigured bandwidth limits detected during startup. */
  public static final int EXIT_BAD_BWLIMIT = 26;

  /** Unit/integration test signaled a fatal error while running under test mode. */
  public static final int EXIT_TEST_ERROR = 25;

  /** Throttle file (rate control state) is missing, unreadable, or corrupt. */
  public static final int EXIT_THROTTLE_FILE_ERROR = 23;

  /** Updater subsystem fails to start. */
  public static final int EXIT_COULD_NOT_START_UPDATER = 21;

  /** TMCI (text-mode control interface) fails to start. */
  @SuppressWarnings("unused")
  public static final int EXIT_COULD_NOT_START_TMCI = 19;

  /** FProxy HTTP service fails to start. */
  public static final int EXIT_COULD_NOT_START_FPROXY = 18;

  /** FCP (client protocol) service fails to start. */
  @SuppressWarnings("unused")
  public static final int EXIT_COULD_NOT_START_FCP = 17;

  /** Node directory is invalid, inaccessible, or not writable. */
  public static final int EXIT_BAD_DIR = 15;

  /** Configured store size violates limits or heuristics. */
  public static final int EXIT_INVALID_STORE_SIZE = 13;

  /** No UDP ports are available for networking. */
  public static final int EXIT_NO_AVAILABLE_UDP_PORTS = 11;

  /** USM port value is impossible on this platform or configuration. */
  public static final int EXIT_IMPOSSIBLE_USM_PORT = 10;

  /** Binding the USM port fails (already in use or permissions). */
  public static final int EXIT_COULD_NOT_BIND_USM = 9;

  /** Other store-related initialization error which is not covered by specific codes. */
  public static final int EXIT_STORE_OTHER = 3;

  /** Upper bound for node-specific exit codes (not itself an exit value). */
  public static final int EXIT_NODE_UPPER_LIMIT = 1024;

  /** Generated or edited {@code wrapper.conf} is invalid. */
  public static final int EXIT_BROKE_WRAPPER_CONF = ConfigExitCodes.BROKE_WRAPPER_CONF;

  /** Creation or update of {@code master.keys} fails (e.g., I/O error). */
  public static final int EXIT_CANT_WRITE_MASTER_KEYS = 30;

  /** Generic configuration error; shares the exit code with master keys write failures. */
  public static final int EXIT_BAD_CONFIG = 30;

  /** Sentinel for debugging: surface the exception without mapping to a specific code. */
  public static final int EXIT_EXCEPTION_TO_DEBUG = 1023;

  /** Serialization identifier for binary compatibility. */
  @Serial private static final long serialVersionUID = -1;

  /**
   * Constructs a {@code NodeInitException} with a human-readable message and exit code.
   *
   * <p>The message is augmented with the numeric code in parentheses for convenience. Do not
   * include secrets or credentials in {@code msg} as it may be logged.
   *
   * @param exitCode one of the {@code EXIT_*} constants declared in this class
   * @param msg short description of the initialization failure; must not contain sensitive data
   */
  public NodeInitException(int exitCode, String msg) {
    super(msg + " (" + exitCode + ')');
    this.exitCode = exitCode;
  }
}
