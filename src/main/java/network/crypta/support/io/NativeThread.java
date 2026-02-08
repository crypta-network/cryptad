package network.crypta.support.io;

import com.sun.jna.Native;
import com.sun.jna.Platform;
import network.crypta.fs.AppEnv;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link Thread} that can adjust its native scheduling priority on Linux.
 *
 * <p>The class maps Java thread priorities to the operating system's {@code nice} levels using JNA
 * bindings to {@code getpriority(2)} and {@code setpriority(2)}. On non-Linux platforms, or when
 * the process runs inside a sandboxed/containerized environment where decreasing priority is
 * disallowed, it falls back to regular JVM priorities without attempting native calls.
 *
 * <p>Extenders may override {@link #realRun()} to add post-run behavior, but must still call {@link
 * Thread#run()} by either not overriding {@link #run()} or by calling {@code super.run()}
 * explicitly if they do override it.
 *
 * <p>Operational notes:
 *
 * <ul>
 *   <li>Linux only: native priority adjustments require enough privileges to decrease the {@code
 *       nice} value. Without privileges, calls fail and the class records a disabled state.
 *   <li>Sandbox detection: Snap, Flatpak, and Docker are detected via {@code AppEnv}; native
 *       renicing is skipped to avoid noisy failures.
 *   <li>Threading: this class extends {@link Thread} and is therefore not thread-safe beyond the
 *       guarantees provided by {@link Thread}.
 * </ul>
 *
 * @see <a href="https://emu.freenetproject.org/pipermail/devl/2008-February/028357.html">Devl
 *     Mailing List</a>
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class NativeThread extends Thread {
  private static final Logger LOG = LoggerFactory.getLogger(NativeThread.class);

  /**
   * True when native functions are available and initialization succeeded on this runtime. On
   * Linux, this implies that the C library has been registered via JNA.
   */
  public static final boolean LOAD_NATIVE;

  /**
   * True when native renicing has been permanently disabled for this process because an unexpected
   * external renice was detected. When set, {@link #usingNativeCode()} returns false and further
   * native adjustments are skipped.
   */
  private static volatile boolean disabled;

  /** Range of Java priorities ({@code MAX_PRIORITY - MIN_PRIORITY}). */
  public static final int JAVA_PRIORITY_RANGE = Thread.MAX_PRIORITY - Thread.MIN_PRIORITY;

  /** Native baseline nice value measured at startup (Linux only). */
  private static final int NATIVE_PRIORITY_BASE;

  /** Number of usable native priority steps starting from {@link #NATIVE_PRIORITY_BASE}. */
  public static final int NATIVE_PRIORITY_RANGE;

  /** Current Java-level priority requested for this thread. */
  private final int currentPriority;

  /**
   * If true, skip the consistency check that detects external renice. Use this when the creator
   * runs at {@link #NATIVE_PRIORITY_BASE} and intentionally manages priorities externally.
   */
  private final boolean dontCheckRenice;

  /**
   * True in known Linux sandboxes (Snap/Flatpak/Docker) where decreasing {@code nice} is blocked
   * without elevated capabilities. In that case, {@code setpriority(2)} is not invoked and the JVM
   * priority is used exclusively to avoid noisy failures.
   */
  private static final boolean SANDBOX_DISABLE_RENICE;

  private static volatile boolean sandboxLogOnce = false;

  /** True when at least three native priority bands are available. */
  public static final boolean HAS_THREE_NICE_LEVELS;

  /** True when the native range can represent {@link PriorityLevel} values. */
  public static final boolean HAS_ENOUGH_NICE_LEVELS;

  /** True when the native range can represent all Java priority steps. */
  public static final boolean HAS_PLENTY_NICE_LEVELS;

  /**
   * Coarse-grained priority bands used by the runtime. The values map to Java priority constants
   * and are converted to native {@code nice} levels on Linux.
   */
  public enum PriorityLevel {
    /** Lowest priority. */
    MIN_PRIORITY(1),
    /** Below-normal priority. */
    LOW_PRIORITY(3),
    /** Normal priority. */
    NORM_PRIORITY(5),
    /** Above-normal priority. */
    HIGH_PRIORITY(7),
    /** Highest priority. */
    MAX_PRIORITY(10);

    public final int value;

    PriorityLevel(int myValue) {
      value = myValue;
    }

    /**
     * Resolve a {@code PriorityLevel} from its integer value.
     *
     * @param value mapped integer value
     * @return the matching level
     * @throws IllegalArgumentException if {@code value} does not match a level
     */
    @SuppressWarnings("unused")
    public static PriorityLevel fromValue(int value) {
      for (PriorityLevel level : PriorityLevel.values()) {
        if (level.value == value) return level;
      }

      throw new IllegalArgumentException();
    }
  }

  /** Number of coarse-grained levels expected for {@link #HAS_ENOUGH_NICE_LEVELS}. */
  public static final int ENOUGH_NICE_LEVELS = PriorityLevel.values().length;

  static {
    LOG.debug("Running init()");
    // Loading the NativeThread library isn't useful on macOS
    boolean maybeLoadNative = Platform.isLinux();
    LOG.trace("Run init(): should loadNative={}", maybeLoadNative);
    // Detect sandboxed/containerized environments where decreasing nice is blocked.
    AppEnv envDet = new AppEnv();
    boolean inSnap = envDet.isSnap();
    boolean inFlatpak = envDet.isFlatpak();
    boolean inDocker = envDet.isDocker();
    SANDBOX_DISABLE_RENICE = maybeLoadNative && (inSnap || inFlatpak || inDocker);
    if (maybeLoadNative) {
      NATIVE_PRIORITY_BASE = LinuxNativeThread.getpriority(0, 0);
      NATIVE_PRIORITY_RANGE = 20 - NATIVE_PRIORITY_BASE;
      LOG.info(
          "Using the NativeThread implementation (base nice level is {}), native range {}",
          NATIVE_PRIORITY_BASE,
          NATIVE_PRIORITY_RANGE);
      // they are 3 main prio levels
      HAS_THREE_NICE_LEVELS = NATIVE_PRIORITY_RANGE >= 3;
      HAS_ENOUGH_NICE_LEVELS = NATIVE_PRIORITY_RANGE >= ENOUGH_NICE_LEVELS;
      HAS_PLENTY_NICE_LEVELS = NATIVE_PRIORITY_RANGE >= JAVA_PRIORITY_RANGE;
      if (!(HAS_ENOUGH_NICE_LEVELS && HAS_THREE_NICE_LEVELS))
        LOG.warn(
            "The JVM has been niced down to a level which won't allow it to schedule threads"
                + " properly. LOWER THE NICE LEVEL!");
      LOAD_NATIVE = true;
    } else {
      // unused anyway
      NATIVE_PRIORITY_BASE = 0;
      NATIVE_PRIORITY_RANGE = 19;
      HAS_THREE_NICE_LEVELS = true;
      HAS_ENOUGH_NICE_LEVELS = true;
      HAS_PLENTY_NICE_LEVELS = true;
      LOAD_NATIVE = false;
    }
    LOG.debug("Run init(): LOAD_NATIVE = {}", LOAD_NATIVE);
    if (SANDBOX_DISABLE_RENICE) {
      StringBuilder sb = new StringBuilder("Sandbox detected: disabling native thread renice (");
      boolean first = true;
      if (inSnap) {
        sb.append("Snap");
        first = false;
      }
      if (inFlatpak) {
        if (!first) sb.append('/');
        sb.append("Flatpak");
        first = false;
      }
      if (inDocker) {
        if (!first) sb.append('/');
        sb.append("Docker");
      }
      sb.append(") due to sandbox constraints.");
      LOG.info("{}", sb);
    }
  }

  private static class LinuxNativeThread {
    static {
      Native.register(Platform.C_LIBRARY_NAME);
    }

    private static native int getpriority(int which, int who);

    private static native int setpriority(int which, int who, int prio);
  }

  /**
   * Construct a thread with the given name and initial priority.
   *
   * <p>On Linux, the constructor does not immediately renice; the adjustment occurs when the thread
   * starts via {@link #run()}.
   *
   * @param name thread name
   * @param priority initial Java priority to apply
   * @param dontCheckRenice set to {@code true} to skip external-renice detection; use only when the
   *     creator intentionally manages native priorities
   */
  public NativeThread(String name, int priority, boolean dontCheckRenice) {
    super(name);
    this.currentPriority = priority;
    this.dontCheckRenice = dontCheckRenice;
  }

  /**
   * Construct a thread with a target {@link Runnable}, name, and initial priority.
   *
   * <p>On Linux, the native priority is applied when the thread starts.
   *
   * @param r task to execute
   * @param name thread name
   * @param priority initial Java priority to apply
   * @param dontCheckRenice set to {@code true} to skip external-renice detection; use only when the
   *     creator intentionally manages native priorities
   */
  public NativeThread(Runnable r, String name, int priority, boolean dontCheckRenice) {
    super(r, name);
    this.currentPriority = priority;
    this.dontCheckRenice = dontCheckRenice;
  }

  // Intentionally no constructor overload with ThreadGroup to avoid the legacy API.

  @Override
  public final void run() {
    if (!setNativePriority(currentPriority))
      LOG.info("setNativePriority({}) has failed!", currentPriority);
    super.run();
    realRun();
  }

  /**
   * Optional hook invoked after {@link Thread#run()} returns.
   *
   * <p>Subclasses may override this method to perform cleanup or additional work at the end of the
   * thread's execution. The default implementation does nothing.
   */
  public void realRun() {
    // No-op by default; subclasses may override.
  }

  // Map Java priority to native nice and apply it when allowed.
  private boolean setNativePriority(int prio) {
    LOG.debug("setNativePriority({})", prio);
    if (prio < Thread.MIN_PRIORITY || prio > Thread.MAX_PRIORITY) {
      throw new IllegalArgumentException("Thread priority out of range: " + prio);
    }
    applyJvmPriority(prio);
    if (SANDBOX_DISABLE_RENICE) {
      if (!sandboxLogOnce) {
        markSandboxLogged();
        LOG.info(
            "Skipping native setpriority in sandbox (Snap/Flatpak/Docker); using JVM priority"
                + " only.");
      }
      return true; // treat as success to avoid noisy warnings
    }
    if (!LOAD_NATIVE) {
      LOG.debug("LOAD_NATIVE is false; using JVM priority only");
      return true;
    }
    int realPrio = LinuxNativeThread.getpriority(0, 0);
    if (disabled) {
      LOG.info("Not setting native priority as disabled due to renicing");
      return false;
    }
    if (NATIVE_PRIORITY_BASE != realPrio && !dontCheckRenice) {
      /*
       * Detected external renice or unexpected creation path. Disable further native renicing
       * because we can no longer assume a stable baseline for conversions.
       */
      markDisabled();
      LOG.error(
          "Detected external renice; disabling native priority adjustment. Base nice={}, actual={},"
              + " thread={}",
          NATIVE_PRIORITY_BASE,
          realPrio,
          this);
      LOG.error(
          "External renice detected; native renice remains disabled. Base nice={}, actual={},"
              + " thread={}",
          NATIVE_PRIORITY_BASE,
          realPrio,
          this);
      return false;
    }
    final int linuxPriority =
        NATIVE_PRIORITY_BASE
            + NATIVE_PRIORITY_RANGE
            - (NATIVE_PRIORITY_RANGE * (prio - PriorityLevel.MIN_PRIORITY.value))
                / JAVA_PRIORITY_RANGE;
    if (linuxPriority == realPrio) return true; // Already at requested native priority.
    // Guard: increasing priority without privileges should never be requested here.
    if (prio < currentPriority)
      throw new IllegalStateException(
          "You're trying to set a thread priority"
              + " above the current value!! It's not possible if you aren't root"
              + " and shouldn't ever occur in our code. (asked="
              + prio
              + ':'
              + linuxPriority
              + " currentMax="
              + currentPriority
              + ':'
              + NATIVE_PRIORITY_BASE
              + ") SHOULD NOT HAPPEN, please report!");
    LOG.debug(
        "Setting native priority to {} (base={}) for {}",
        linuxPriority,
        NATIVE_PRIORITY_BASE,
        this);
    return (LinuxNativeThread.setpriority(0, 0, linuxPriority) > -1);
  }

  @SuppressWarnings("ThreadPriorityCheck")
  private void applyJvmPriority(int prio) {
    setPriority(prio);
  }

  /**
   * Current Java-level priority for this thread.
   *
   * @return the priority passed at construction time
   */
  public int getNativePriority() {
    return currentPriority;
  }

  /**
   * Determine whether native renicing is active for this process.
   *
   * @return {@code true} if native functions are loaded and not disabled due to external renicing;
   *     {@code false} otherwise
   */
  public static boolean usingNativeCode() {
    return LOAD_NATIVE && !disabled;
  }

  /**
   * Normalize a thread name by removing volatile suffixes.
   *
   * <p>Heuristics strip text following {@code " for "}, {@code '@'}, and {@code '('}. Use this to
   * group related thread names for logging or metrics.
   *
   * @param name input name
   * @return normalized name without variable suffixes
   */
  public static String normalizeName(String name) {
    if (name.contains(" for ")) name = name.substring(0, name.indexOf(" for "));
    if (name.indexOf('@') != -1) name = name.substring(0, name.indexOf('@'));
    if (name.indexOf('(') != -1) name = name.substring(0, name.indexOf('('));

    return name.trim();
  }

  /**
   * Convenience accessor that normalizes {@link #getName()}.
   *
   * @return normalized thread name
   */
  public String getNormalizedName() {
    return normalizeName(getName());
  }

  private static void markDisabled() {
    disabled = true;
  }

  private static void markSandboxLogged() {
    sandboxLogOnce = true;
  }
}
