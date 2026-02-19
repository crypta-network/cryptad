package network.crypta.support;

import com.sun.jna.win32.*;

import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import network.crypta.fs.AppEnv;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Controls the operating system scheduling priority of the current process.
 *
 * <p>This utility moves the Crypta reference daemon into a background scheduling class so it does
 * not compete with interactive tasks. It uses JNA to call native facilities directly and keeps
 * behavior intentionally conservative: if an operation is not supported or not permitted, it fails
 * softly and leaves the process priority unchanged.
 *
 * <p>Platform behavior:
 *
 * <ul>
 *   <li><b>Windows</b>: calls {@code SetPriorityClass(BELOW_NORMAL_PRIORITY_CLASS)} on the current
 *       process via {@code kernel32}.
 *   <li><b>Linux</b>: calls {@code setpriority(PRIO_PROCESS, 0, 10)} (increasing niceness) when the
 *       environment is not sandboxed. In Snap/Flatpak/Docker containers, lowering priority is
 *       typically blocked for unprivileged users; in such cases the call is skipped and a warning
 *       is logged.
 *   <li><b>macOS</b>: calls {@code setpriority(PRIO_DARWIN_THREAD, 0, PRIO_DARWIN_BG)} to request a
 *       background thread priority.
 * </ul>
 *
 * <p>Thread-safety and idempotency:
 *
 * <ul>
 *   <li>The operation is idempotent. Subsequent calls are no-ops once background mode is entered.
 *   <li>The internal state flag is {@code volatile}; concurrent callers may race on the first call,
 *       but the effect is the same and later calls observe the final state.
 * </ul>
 *
 * <p>Logging and errors:
 *
 * <ul>
 *   <li>Messages are emitted through SLF4J. Successful transitions and sandbox skips are logged at
 *       {@code WARN} to remain visible in minimal test/console configurations.
 *   <li>No exceptions are thrown; native failures cause the method to return {@code false} and log
 *       a warning, leaving the process priority unchanged.
 * </ul>
 */
public class ProcessPriority {
  private static final Logger LOG = LoggerFactory.getLogger(ProcessPriority.class);
  private static volatile boolean background = false;

  // Minimal kernel32 mapping used to adjust process priority on Windows.
  @SuppressWarnings("java:S100")
  public interface WindowsHolder extends StdCallLibrary {
    WindowsHolder INSTANCE = Native.load("kernel32", WindowsHolder.class);

    boolean SetPriorityClass(HANDLE hProcess, DWORD dwPriorityClass);

    HANDLE GetCurrentProcess();

    DWORD GetLastError();

    DWORD BELOW_NORMAL_PRIORITY_CLASS = new DWORD(0x00004000);
  }

  // JNA mapping for libc setpriority(2) on Linux; not part of the public API.
  private static class LinuxHolder {
    static {
      Native.register(Platform.C_LIBRARY_NAME);
    }

    private static native int setpriority(int which, int who, int prio);

    static final int PRIO_PROCESS = 0;
    static final int MYSELF = 0;
    static final int LOWER_PRIORITY = 10;
  }

  // Darwin/macOS setpriority(2) mapping and constants; internal-use only.
  private static class OSXHolder {
    static {
      Native.register(Platform.C_LIBRARY_NAME);
    }

    private static native int setpriority(int which, int who, int prio);

    static final int PRIO_DARWIN_THREAD = 3;
    static final int MYSELF = 0;
    static final int PRIO_DARWIN_BG = 0x1000;
  }

  /**
   * Enters background scheduling mode for the current process, when permitted by the host OS.
   *
   * <p>On Windows, sets the priority class to {@code BELOW_NORMAL_PRIORITY_CLASS}. On Linux, raises
   * the niceness value by 10 using {@code setpriority} (unless running in a sandboxed environment
   * such as Snap/Flatpak/Docker, where the call is skipped). On macOS, applies the Darwin
   * background thread priority.
   *
   * <p>This method is idempotent; when background mode is already enabled, it returns the cached
   * state without performing native calls.
   *
   * @return {@code true} if background mode is in effect after the call (either due to a successful
   *     native operation, a sandboxed skip that leaves defaults in place, or because it was already
   *     enabled); {@code false} if a native call was attempted and failed.
   */
  public static boolean enterBackgroundMode() {
    if (!background) {
      // On sandboxed Linux (Snap/Flatpak/Docker), renicing is typically blocked without
      // capabilities. Skip the native call and rely on the JVM/OS defaults.
      AppEnv env = new AppEnv();
      if (env.isLinux() && (env.isSnap() || env.isFlatpak() || env.isDocker())) {
        LOG.warn(
            "Skipping process setpriority due to sandbox constraints (Snap/Flatpak/Docker). Using"
                + " JVM default priority.");
        background = true; // treat as engaged to avoid further attempts/noise
        return true;
      }
      // Dispatch to the platform-specific implementation.
      if (Platform.isWindows()) {
        WindowsHolder lib = WindowsHolder.INSTANCE;

        if (lib.SetPriorityClass(
            lib.GetCurrentProcess(), WindowsHolder.BELOW_NORMAL_PRIORITY_CLASS)) {
          LOG.warn("SetPriorityClass() succeeded!");
          background = true;
          return true;
        } else {
          LOG.warn("SetPriorityClass() failed: {}", lib.GetLastError());
          return false;
        }
      } else if (Platform.isLinux()) {
        return handleReturn(
            LinuxHolder.setpriority(
                LinuxHolder.PRIO_PROCESS, LinuxHolder.MYSELF, LinuxHolder.LOWER_PRIORITY));

      } else if (Platform.isMac()) {
        return handleReturn(
            OSXHolder.setpriority(
                OSXHolder.PRIO_DARWIN_THREAD, OSXHolder.MYSELF, OSXHolder.PRIO_DARWIN_BG));
      }
    }
    return background;
  }

  // Helper to normalize the return value and logging for Unix-like setpriority results.
  private static boolean handleReturn(int ret) {
    if (ret == 0) {
      LOG.warn("setpriority() succeeded!");
      background = true;
      return true;
    } else {
      LOG.warn("setpriority() failed: {}", ret);
      return false;
    }
  }
}
